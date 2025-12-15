import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/signature.dart';
import '../errors.dart';
import '../pfs_config.dart';
import '../server_identity.dart';
import 'client_hello.dart';
import 'key_schedule.dart';
import 'server_hello.dart';
import 'transcript.dart';

/// Holds the client-side ephemeral state produced when creating a ClientHello.
/// You must keep this until you receive and verify the ServerHello.
final class ClientHelloState {
  final ClientHello hello;
  final KeyPair clientEphemeralKeyPair;

  const ClientHelloState({
    required this.hello,
    required this.clientEphemeralKeyPair,
  });

  Uint8List encodeHello() => hello.encode();
}

/// Resulting session materials after a successful v2 handshake.
final class HandshakeResult {
  /// Session identifier: first 16 bytes of SHA-256(transcript).
  final Uint8List sid16;

  /// AEAD key (32 bytes).
  final SecretKey aeadKey;

  /// 12-byte nonce base. Per-message nonce will be derived from this + seq.
  final Uint8List nonceBase12;

  /// The server identity key reference that authenticated this handshake.
  final ServerIdentityRef serverIdentity;

  /// Negotiated suite string (must match both hellos).
  final String suite;

  /// Transcript (useful for debugging / interop testing).
  final HandshakeTranscript transcript;

  const HandshakeResult({
    required this.sid16,
    required this.aeadKey,
    required this.nonceBase12,
    required this.serverIdentity,
    required this.suite,
    required this.transcript,
  });
}

/// Client-side v2 handshake:
/// - Generates ephemeral X25519 keypair
/// - Builds ClientHello
/// - Verifies ServerHello signature (Ed25519) over transcript hash
/// - Derives session keys via KeySchedule (HKDF(sharedSecret, salt=SHA256(transcript)))
final class HandshakeClient {
  final PfsConfig config;

  const HandshakeClient(this.config);
  Uint8List secureRandomBytes(int randomLenBytes) {
    if (randomLenBytes < 0) {
      throw ArgumentError.value(randomLenBytes, 'randomLenBytes', '>= 0 olmalı');
    }

    final out = Uint8List(randomLenBytes);
    final rnd = Random.secure();

    // Random.nextInt(256) ile her byte’ı doldur.
    for (var i = 0; i < out.length; i++) {
      out[i] = rnd.nextInt(256);
    }
    return out;
  }
  /// Builds a ClientHello + returns the ephemeral keypair state to keep.
  Future<ClientHelloState> createClientHello({
    ServerIdentityRef? expectServerIdentity,
    int randomLenBytes = 32,
    int? timestampMs,
  }) async {
    if (randomLenBytes <= 0) {
      throw PfsErrors.invalidInput('randomLenBytes must be > 0');
    }

    final suite = _suiteId(config);

    final keyPair = await config.keyExchangeAlgorithm.newKeyPair();
    final pub = await keyPair.extractPublicKey();

    final crand = Uint8List.fromList(
      secureRandomBytes(randomLenBytes),
    );
    final ts = timestampMs ?? DateTime.now().millisecondsSinceEpoch;

    final hello = ClientHello(
      suite: suite,
      clientEphemeralPublicKey: pub,
      clientRandom: crand,
      timestampMs: ts,
      expectedServerIdentity: expectServerIdentity,
    );

    return ClientHelloState(
      hello: hello,
      clientEphemeralKeyPair: keyPair,
    );
  }

  /// Processes ServerHello, verifies signature, and derives session keys.
  Future<HandshakeResult> processServerHello({
    required ClientHelloState state,
    required ServerHello serverHello,
    int? nowMs,
  }) async {
    try {
      _validateHelloPair(state.hello, serverHello);

      final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
      _validateHandshakeTimestamps(state.hello, serverHello, now);

      // Transcript hash (used for signature verification and HKDF salt).
      final transcript = HandshakeTranscript(
        clientHello: state.hello,
        serverHello: serverHello,
      );
      final transcriptHash = await transcript.hashSha256();

      // Resolve server identity public key (pinned or resolver).
      final serverPub = await config.resolveKey(
        serverHello.identity.kid,
        keyVersion: serverHello.identity.keyVersion,
      );
      if (serverPub == null) {
        throw PfsErrors.keyNotFound(
          'kid=${serverHello.identity.toWireKid()}',
        );
      }

      // Verify server signature over transcript hash.
      final ok = await PfsSignature.verifyEd25519(
        message: transcriptHash,
        signatureBytes: serverHello.signature,
        publicKey: serverPub,
      );
      if (!ok) {
        throw PfsErrors.signatureInvalid();
      }

      // Derive session keys via KeySchedule (single source of truth).
      final clientPriv = await _extractX25519PrivateAsSecret(
        state.clientEphemeralKeyPair,
      );

      final ks = KeySchedule(config);
      final keys = await ks.derive(
        clientEphemeralPrivateKey: clientPriv,
        serverEphemeralPublicKey: serverHello.serverEphemeralPublicKey,
        transcript: transcript,
      );

      return HandshakeResult(
        sid16: Uint8List.fromList(keys.sid16),
        aeadKey: keys.aeadKey,
        nonceBase12: Uint8List.fromList(keys.nonceBase12),
        serverIdentity: serverHello.identity,
        suite: serverHello.suite,
        transcript: transcript,
      );
    } on PfsException {
      rethrow;
    } on FormatException catch (e) {
      throw PfsErrors.handshakeFailed(e.message);
    } on StateError catch (e) {
      throw PfsErrors.handshakeFailed(e.message);
    } catch (e) {
      throw PfsErrors.handshakeFailed(e);
    }
  }

  static String _suiteId(PfsConfig config) {
    switch (config.aead) {
      case PfsAead.chacha20Poly1305:
        return 'X25519-HKDF-SHA256-CHACHA20POLY1305';
      case PfsAead.aesGcm:
        return 'X25519-HKDF-SHA256-AES256GCM';
    }
  }

  static void _validateHelloPair(ClientHello ch, ServerHello sh) {
    if (ch.v != 2 || sh.v != 2) {
      throw PfsErrors.unsupportedVersion('expected v=2');
    }
    if (ch.suite != sh.suite) {
      throw PfsErrors.handshakeFailed(
        'suite mismatch: client="${ch.suite}" server="${sh.suite}"',
      );
    }

    // If client pinned/expected a specific server identity, enforce it.
    final expected = ch.expectedServerIdentity;
    if (expected != null) {
      if (expected.kid != sh.identity.kid) {
        throw PfsErrors.handshakeFailed(
          'server kid mismatch: expected="${expected.kid}" got="${sh.identity.kid}"',
        );
      }
      if (expected.keyVersion != null && expected.keyVersion != sh.identity.keyVersion) {
        throw PfsErrors.handshakeFailed(
          'server keyVersion mismatch: expected="${expected.keyVersion}" got="${sh.identity.keyVersion}"',
        );
      }
      if (expected.alg != sh.identity.alg) {
        throw PfsErrors.handshakeFailed(
          'server alg mismatch: expected="${expected.alg.id}" got="${sh.identity.alg.id}"',
        );
      }
    }

    if (sh.identity.alg != ServerSigAlg.ed25519) {
      throw PfsErrors.handshakeFailed(
        'unsupported server signature alg: ${sh.identity.alg.id}',
      );
    }
  }

  void _validateHandshakeTimestamps(ClientHello ch, ServerHello sh, int nowMs) {
    final maxSkew = config.handshakeMaxClockSkew.inMilliseconds;

    final dtClient = (nowMs - ch.timestampMs).abs();
    if (dtClient > maxSkew) {
      throw PfsErrors.timestampSkew('client skew ${dtClient}ms');
    }

    final dtServer = (nowMs - sh.timestampMs).abs();
    if (dtServer > maxSkew) {
      throw PfsErrors.timestampSkew('server skew ${dtServer}ms');
    }

    final delta = sh.timestampMs - ch.timestampMs;
    if (delta.abs() > (maxSkew * 2)) {
      throw PfsErrors.timestampSkew('delta ${delta}ms');
    }
  }

static Future<SecretKey> _extractX25519PrivateAsSecret(KeyPair kp) async {
    final data = await kp.extract();

    if (data.type != KeyPairType.x25519) {
      throw PfsErrors.handshakeFailed('expected X25519 keypair');
    }

    if (data is! SimpleKeyPairData) {
      throw PfsErrors.handshakeFailed('expected SimpleKeyPairData for X25519');
    }

    final priv = Uint8List.fromList(data.bytes);
    if (priv.length != 32) {
      throw PfsErrors.handshakeFailed('X25519 private key must be 32 bytes');
    }

    return SecretKey(priv);
  }

}
