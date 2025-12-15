import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:otp_crypto/pfs/handshake/client_hello.dart';
import 'package:otp_crypto/pfs/handshake/handshake_client.dart';
import 'package:otp_crypto/pfs/handshake/server_hello.dart';
import 'package:otp_crypto/pfs/handshake/transcript.dart';
import 'package:otp_crypto/pfs/message/aad.dart';
import 'package:otp_crypto/pfs/pfs_config.dart';
import 'package:otp_crypto/pfs/server_identity.dart';
import 'package:otp_crypto/pfs/session/pfs_session.dart';
import 'package:test/test.dart';

void main() {
  group('PFS v2 message protect/unprotect', () {
    test('protect() increments seq and unprotect() returns plaintext', () async {
      final nowMs = 1700000000000;

      final config = PfsConfig(
        // Resolver not used by session operations.
        resolveServerPublicKey: (_, {int? keyVersion}) async => null,
        replayWindowSize: 0, // strict monotonic for this test
        maxClockSkew: const Duration(seconds: 60),
      );

      final session = PfsSession.fromHandshake(
        config: config,
        result: _makeHandshakeResult(
          config: config,
          nowMs: nowMs,
        ),
      );

      final http = const HttpContext(
        method: 'POST',
        path: '/api/v1/devices',
        query: {'a': '1'},
      );

      final pt = Uint8List.fromList(utf8.encode('hello pfs'));
      final r1 = await session.protect(plaintext: pt, http: http, nowMs: nowMs);

      expect(r1.header.v, 2);
      expect(r1.header.seq, 1);
      expect(r1.header.timestampMs, nowMs);
      expect(r1.envelope.ct, isNotEmpty);
      expect(r1.envelope.tag, isNotEmpty);
      expect(r1.envelope.nonce, isNull);

      final out1 = await session.unprotect(
        header: r1.header,
        envelope: r1.envelope,
        http: http,
        nowMs: nowMs,
      );
      expect(utf8.decode(out1), 'hello pfs');

      // Second message increments seq.
      final r2 = await session.protect(plaintext: pt, http: http, nowMs: nowMs);
      expect(r2.header.seq, 2);
    });

    test('AAD endpoint binding: different method/path must fail authentication', () async {
      final nowMs = 1700000000000;

      final config = PfsConfig(
        resolveServerPublicKey: (_, {int? keyVersion}) async => null,
        replayWindowSize: 0,
        maxClockSkew: const Duration(seconds: 60),
      );

      final session = PfsSession.fromHandshake(
        config: config,
        result: _makeHandshakeResult(
          config: config,
          nowMs: nowMs,
        ),
      );

      final httpOk = const HttpContext(method: 'GET', path: '/a');
      final httpBad1 = const HttpContext(method: 'POST', path: '/a');
      final httpBad2 = const HttpContext(method: 'GET', path: '/b');

      final pt = Uint8List.fromList(utf8.encode('bound'));
      final r = await session.protect(plaintext: pt, http: httpOk, nowMs: nowMs);

      // Wrong method
      expect(
        () => session.unprotect(
          header: r.header,
          envelope: r.envelope,
          http: httpBad1,
          nowMs: nowMs,
        ),
        throwsA(isA<FormatException>()),
      );

      // Wrong path
      expect(
        () => session.unprotect(
          header: r.header,
          envelope: r.envelope,
          http: httpBad2,
          nowMs: nowMs,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('Replay protection: same seq twice is rejected (strict mode)', () async {
      final nowMs = 1700000000000;

      final config = PfsConfig(
        resolveServerPublicKey: (_, {int? keyVersion}) async => null,
        replayWindowSize: 0, // strict
        maxClockSkew: const Duration(seconds: 60),
      );

      final session = PfsSession.fromHandshake(
        config: config,
        result: _makeHandshakeResult(
          config: config,
          nowMs: nowMs,
        ),
      );

      final http = const HttpContext(method: 'GET', path: '/r');
      final pt = Uint8List.fromList(utf8.encode('replay'));
      final r = await session.protect(plaintext: pt, http: http, nowMs: nowMs);

      final out = await session.unprotect(
        header: r.header,
        envelope: r.envelope,
        http: http,
        nowMs: nowMs,
      );
      expect(utf8.decode(out), 'replay');

      // Second time with same header/envelope should be rejected as replay.
      expect(
        () => session.unprotect(
          header: r.header,
          envelope: r.envelope,
          http: http,
          nowMs: nowMs,
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });
}

HandshakeResult _makeHandshakeResult({
  required PfsConfig config,
  required int nowMs,
}) {
  // We don't need a *real* Vault signature here; PfsSession only uses:
  // - sid16
  // - aeadKey
  // - nonceBase12
  // - serverIdentity/kid for header metadata
  // But we include a real transcript to keep structure consistent.

  const identityRef = ServerIdentityRef(
    kid: 'pfs-server-id',
    keyVersion: 1,
    alg: ServerSigAlg.ed25519,
  );

  final suite = (config.aead == PfsAead.chacha20Poly1305) ? 'X25519-HKDF-SHA256-CHACHA20POLY1305' : 'X25519-HKDF-SHA256-AES256GCM';

  final ch = ClientHello(
    suite: suite,
    clientEphemeralPublicKey: SimplePublicKey(
      Uint8List.fromList(List<int>.generate(32, (i) => i)),
      type: KeyPairType.x25519,
    ),
    clientRandom: Uint8List.fromList(List<int>.filled(32, 1)),
    timestampMs: nowMs,
    expectedServerIdentity: identityRef,
  );

  final sh = ServerHello(
    suite: suite,
    serverEphemeralPublicKey: SimplePublicKey(
      Uint8List.fromList(List<int>.generate(32, (i) => 32 + i)),
      type: KeyPairType.x25519,
    ),
    serverRandom: Uint8List.fromList(List<int>.filled(32, 2)),
    timestampMs: nowMs,
    identity: identityRef,
    signature: Uint8List(64),
  );

  final transcript = HandshakeTranscript(clientHello: ch, serverHello: sh);

  // Fixed session key material for test determinism.
  final aeadKeyBytes = Uint8List.fromList(List<int>.generate(32, (i) => 0xA0 + i));
  final nonceBase12 = Uint8List.fromList(List<int>.generate(12, (i) => 0xB0 + i));

  // sid16 from transcript hash first 16 bytes.
  // We compute synchronously by blocking via a small helper.
  // (Tests are async elsewhere; here we keep it simple by using a known deterministic sid.)
  //
  // To avoid making this function async, we hardcode a stable sid for message tests.
  final sid16 = Uint8List.fromList(List<int>.generate(16, (i) => 0x10 + i));

  return HandshakeResult(
    sid16: sid16,
    aeadKey: SecretKey(aeadKeyBytes),
    nonceBase12: nonceBase12,
    serverIdentity: identityRef,
    suite: suite,
    transcript: transcript,
  );
}
