import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:otp_crypto/pfs/crypto/signature.dart';
import 'package:otp_crypto/pfs/handshake/client_hello.dart';
import 'package:otp_crypto/pfs/handshake/handshake_client.dart';
import 'package:otp_crypto/pfs/handshake/key_schedule.dart';
import 'package:otp_crypto/pfs/handshake/server_hello.dart';
import 'package:otp_crypto/pfs/handshake/transcript.dart';
import 'package:otp_crypto/pfs/pfs_config.dart';
import 'package:otp_crypto/pfs/server_identity.dart';
import 'package:test/test.dart';

void main() {
  group('PFS v2 handshake', () {
    test('Transcript hash matches known vector (canonical bytes)', () async {
      // This test locks down deterministic canonicalization.
      final suite = 'X25519-HKDF-SHA256-CHACHA20POLY1305';

      final ch = ClientHello(
        suite: suite,
        clientEphemeralPublicKey: SimplePublicKey(
          Uint8List.fromList(List<int>.generate(32, (i) => i)),
          type: KeyPairType.x25519,
        ),
        clientRandom: Uint8List.fromList(List<int>.generate(32, (i) => 100 + i)),
        timestampMs: 1700000000000,
        expectedServerIdentity: const ServerIdentityRef(
          kid: 'pfs-server-id',
          keyVersion: 3,
          alg: ServerSigAlg.ed25519,
        ),
      );

      final sh = ServerHello(
        suite: suite,
        serverEphemeralPublicKey: SimplePublicKey(
          Uint8List.fromList(List<int>.generate(32, (i) => 32 + i)),
          type: KeyPairType.x25519,
        ),
        serverRandom: Uint8List.fromList(List<int>.generate(32, (i) => 200 + i)),
        timestampMs: 1700000000100,
        identity: const ServerIdentityRef(
          kid: 'pfs-server-id',
          keyVersion: 3,
          alg: ServerSigAlg.ed25519,
        ),
        signature: Uint8List(64), // excluded from transcript hash
      );

      final t = HandshakeTranscript(clientHello: ch, serverHello: sh);
      final h = await t.hashSha256();

      // IMPORTANT:
      // This expected value MUST be updated only if transcript rules change.
      // It reflects canonical JSON (sorted keys) for both hellos.
      const expectedHex = 'e5328677cbee949fc3b4d76f61f4561e51b5b3754645f2257fc39aceab19d862';
      expect(_hex(h), expectedHex);

      final sid16 = await t.sid16();
      expect(_hex(sid16), expectedHex.substring(0, 32));
    });

    test('Handshake signature verify + key derivation agrees with KeySchedule', () async {
      final suite = 'X25519-HKDF-SHA256-CHACHA20POLY1305';
      final nowMs = 1700000000000;

      // Deterministic ephemeral keys
      final clientSeed = Uint8List.fromList(List<int>.generate(32, (i) => 1 + i));
      final serverSeed = Uint8List.fromList(List<int>.generate(32, (i) => 101 + i));

      final x25519 = X25519();
      final clientEph = await x25519.newKeyPairFromSeed(clientSeed);
      final serverEph = await x25519.newKeyPairFromSeed(serverSeed);

      final clientPub = await clientEph.extractPublicKey();
      final serverPub = await serverEph.extractPublicKey();

      // Deterministic server identity key (Vault would hold the private part).
      final idSeed = Uint8List.fromList(List<int>.generate(32, (i) => 201 + i));
      final ed = Ed25519();
      final idKeyPair = await ed.newKeyPairFromSeed(idSeed);
      final idPub = await idKeyPair.extractPublicKey();

      const identityRef = ServerIdentityRef(
        kid: 'pfs-server-id',
        keyVersion: 1,
        alg: ServerSigAlg.ed25519,
      );

      final config = PfsConfig(
        aead: PfsAead.chacha20Poly1305,
        resolveServerPublicKey: (kid, {int? keyVersion}) async {
          if (kid == identityRef.kid && (keyVersion == null || keyVersion == identityRef.keyVersion)) {
            return idPub as SimplePublicKey;
          }
          return null;
        },
        pinnedServerKeys: {
          identityRef.kid: idPub as SimplePublicKey,
        },
      );

      final ch = ClientHello(
        suite: suite,
        clientEphemeralPublicKey: clientPub as SimplePublicKey,
        clientRandom: Uint8List.fromList(List<int>.generate(32, (i) => 9)),
        timestampMs: nowMs,
        expectedServerIdentity: identityRef,
      );

      // Provisional ServerHello (sig bytes excluded from transcript hash anyway).
      final shProvisional = ServerHello(
        suite: suite,
        serverEphemeralPublicKey: serverPub as SimplePublicKey,
        serverRandom: Uint8List.fromList(List<int>.generate(32, (i) => 7)),
        timestampMs: nowMs,
        identity: identityRef,
        signature: Uint8List(64),
      );

      final transcriptForSig = HandshakeTranscript(clientHello: ch, serverHello: shProvisional);
      final transcriptHash = await transcriptForSig.hashSha256();

      final sig = await ed.sign(transcriptHash, keyPair: idKeyPair);

      final sh = ServerHello(
        suite: suite,
        serverEphemeralPublicKey: serverPub as SimplePublicKey,
        serverRandom: shProvisional.serverRandom,
        timestampMs: nowMs,
        identity: identityRef,
        signature: Uint8List.fromList(sig.bytes),
      );

      // Verify signature helper accepts raw bytes and "vault:v1:<b64>" style.
      final sigB64 = base64Encode(sig.bytes);
      final vaultStyle = 'vault:v1:$sigB64';
      final parsed = PfsSignature.parseVaultSignature(vaultStyle);
      expect(parsed, Uint8List.fromList(sig.bytes));

      final ok = await PfsSignature.verifyEd25519(
        message: transcriptHash,
        signatureBytes: parsed,
        publicKey: idPub as SimplePublicKey,
      );
      expect(ok, isTrue);

      // Now run the actual handshake client processing.
      final hc = HandshakeClient(config);
      final state = ClientHelloState(hello: ch, clientEphemeralKeyPair: clientEph);
      final result = await hc.processServerHello(
        state: state,
        serverHello: sh,
        nowMs: nowMs,
      );

      // KeySchedule should match HandshakeClient derivation.
      final clientData = await clientEph.extract();
      if (clientData is! SimpleKeyPairData) {
        throw StateError('expected SimpleKeyPairData for clientEph');
      }
      final clientPriv = SecretKey(Uint8List.fromList(clientData.bytes));

      final ks = KeySchedule(config);
      final expected = await ks.derive(
        clientEphemeralPrivateKey: clientPriv,
        serverEphemeralPublicKey: serverPub as SimplePublicKey,
        transcript: HandshakeTranscript(clientHello: ch, serverHello: sh),
      );

      final gotKey = await result.aeadKey.extractBytes();
      final expKey = await expected.aeadKey.extractBytes();

      expect(gotKey, expKey);
      expect(result.nonceBase12, expected.nonceBase12);
      expect(result.sid16, expected.sid16);
    });
  });
}

String _hex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
