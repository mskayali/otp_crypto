import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../codec/canonical_json.dart';
import '../server_identity.dart';

/// v2 ClientHello message (minimal, canonicalizable).
///
/// Byte fields are base64 (standard).
///
/// Canonical encoding MUST be stable across Dart <-> PHP:
/// - We build a JSON map
/// - We encode it using canonicalJsonUtf8() (sorted keys, no whitespace)
final class ClientHello {
  final int v;
  final String suite;

  /// Client ephemeral X25519 public key.
  final PublicKey clientEphemeralPublicKey;

  /// Client random bytes (recommended 32 bytes).
  final Uint8List clientRandom;

  /// Unix time in milliseconds (client-side).
  final int timestampMs;

  /// Optional: which server identity key the client expects (pinning/selection).
  final ServerIdentityRef? expectedServerIdentity;

  const ClientHello({
    this.v = 2,
    required this.suite,
    required this.clientEphemeralPublicKey,
    required this.clientRandom,
    required this.timestampMs,
    this.expectedServerIdentity,
  });

  /// Canonical JSON map (keys stable).
  Map<String, dynamic> toCanonicalJson() {
    if (v != 2) {
      throw StateError('ClientHello.v must be 2 for PFS v2');
    }
    if (clientEphemeralPublicKey.type != KeyPairType.x25519) {
      throw StateError('clientEphemeralPublicKey must be X25519');
    }

    final m = <String, dynamic>{
      'v': 2,
      'suite': suite,
      'cpub': clientEphemeralPublicKey.toString(),
      'crand': base64Encode(clientRandom),
      'ts': timestampMs,
    };

    final id = expectedServerIdentity;
    if (id != null) {
      // Compact selection/pinning metadata.
      m['kid'] = id.toWireKid();
      m['alg'] = id.alg.id;
    }

    return m;
  }

  /// Canonical JSON bytes (UTF-8). This is what MUST be used in transcripts.
  Uint8List encode() => canonicalJsonUtf8(toCanonicalJson());

  static ClientHello decode(Uint8List bytes) {
    final obj = jsonDecode(utf8.decode(bytes));
    if (obj is! Map<String, dynamic>) {
      throw const FormatException('ClientHello must be a JSON object');
    }
    return fromJson(obj);
  }

  static ClientHello fromJson(Map<String, dynamic> json) {
    final v = json['v'];
    final suite = json['suite'];
    final cpub = json['cpub'];
    final crand = json['crand'];
    final ts = json['ts'];

    if (v is! int || v != 2) {
      throw const FormatException('ClientHello.v must be 2');
    }
    if (suite is! String || suite.trim().isEmpty) {
      throw const FormatException('ClientHello.suite is required');
    }
    if (cpub is! String || cpub.isEmpty) {
      throw const FormatException('ClientHello.cpub is required');
    }
    if (crand is! String || crand.isEmpty) {
      throw const FormatException('ClientHello.crand is required');
    }
    if (ts is! int || ts <= 0) {
      throw const FormatException('ClientHello.ts is required');
    }

    final clientPubBytes = base64Decode(cpub);
    if (clientPubBytes.length != 32) {
      throw const FormatException('ClientHello.cpub must be 32 bytes (X25519)');
    }

    final clientRandom = base64Decode(crand);
    if (clientRandom.isEmpty) {
      throw const FormatException('ClientHello.crand must not be empty');
    }

    ServerIdentityRef? expected;
    final kid = json['kid'];
    final alg = json['alg'];
    if (kid is String && kid.trim().isNotEmpty) {
      expected = ServerIdentityRef.fromWire(
        kid: kid,
        alg: alg is String ? alg : null,
      );
    }

    return ClientHello(
      v: 2,
      suite: suite,
      clientEphemeralPublicKey: SimplePublicKey(clientPubBytes, type: KeyPairType.x25519),
      clientRandom: Uint8List.fromList(clientRandom),
      timestampMs: ts,
      expectedServerIdentity: expected,
    );
  }
}
