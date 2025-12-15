import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/signature.dart';
import '../server_identity.dart';

/// v2 ServerHello message.
///
/// Fields:
/// - v: protocol version (int) -> 2
/// - suite: crypto suite identifier (string) MUST match ClientHello.suite
/// - spub: server ephemeral X25519 public key (base64)
/// - srand: server random (base64, 32 bytes recommended)
/// - ts: server timestamp (unix ms)
/// - kid: server identity key ref "<kid>[:<ver>]"
/// - alg: server signature algorithm (currently "ed25519")
/// - sig: signature over transcript hash (string)
///
/// Signature formats accepted in [fromJson]:
/// - base64 raw signature
/// - Vault Transit style "vault:v1:<base64>" (or any "vault:...:<base64>")
/// - List<int> (raw signature bytes) for non-JSON transports
///
/// Notes:
/// - Signature is produced by the server identity private key (ideally in Vault).
/// - Client verifies sig using a resolved/pinned public key for (kid, version).
final class ServerHello {
  final int v;
  final String suite;

  /// Server ephemeral X25519 public key.
  final SimplePublicKey serverEphemeralPublicKey;

  /// Server random bytes (recommended 32 bytes).
  final Uint8List serverRandom;

  /// Unix time in milliseconds (server-side).
  final int timestampMs;

  /// Which server identity key was used to sign.
  final ServerIdentityRef identity;

  /// Signature bytes (Ed25519) over transcript hash.
  final Uint8List signature;

  const ServerHello({
    this.v = 2,
    required this.suite,
    required this.serverEphemeralPublicKey,
    required this.serverRandom,
    required this.timestampMs,
    required this.identity,
    required this.signature,
  });

  /// Returns canonical JSON map for transcript hashing/verification.
  ///
  /// IMPORTANT:
  /// - The transcript hash uses:
  ///   - ClientHello canonical JSON bytes
  ///   - ServerHello canonical JSON bytes *without* 'sig'
  /// - So this function has a [includeSignature] toggle.
  Map<String, dynamic> toCanonicalJson({required bool includeSignature}) {
    if (v != 2) {
      throw StateError('ServerHello.v must be 2 for PFS v2');
    }
    if (serverEphemeralPublicKey.type != KeyPairType.x25519) {
      throw StateError('serverEphemeralPublicKey must be X25519');
    }

    final m = <String, dynamic>{
      'v': 2,
      'suite': suite,
      'spub': base64Encode(serverEphemeralPublicKey.bytes),
      'srand': base64Encode(serverRandom),
      'ts': timestampMs,
      'kid': identity.toWireKid(),
      'alg': identity.alg.id,
    };

    if (includeSignature) {
      // When encoding we always emit plain base64 (no "vault:" prefix).
      m['sig'] = base64Encode(signature);
    }

    return m;
  }

  /// Encodes canonical JSON bytes (UTF-8).
  Uint8List encode() {
    final jsonStr = jsonEncode(toCanonicalJson(includeSignature: true));
    return Uint8List.fromList(utf8.encode(jsonStr));
  }

  static ServerHello decode(Uint8List bytes) {
    final obj = jsonDecode(utf8.decode(bytes));
    if (obj is! Map<String, dynamic>) {
      throw const FormatException('ServerHello must be a JSON object');
    }
    return fromJson(obj);
  }

  static ServerHello fromJson(Map<String, dynamic> json) {
    final v = json['v'];
    final suite = json['suite'];
    final spub = json['spub'];
    final srand = json['srand'];
    final ts = json['ts'];
    final kid = json['kid'];
    final alg = json['alg'];
    final sig = json['sig'];

    if (v is! int || v != 2) {
      throw const FormatException('ServerHello.v must be 2');
    }
    if (suite is! String || suite.trim().isEmpty) {
      throw const FormatException('ServerHello.suite is required');
    }
    if (spub is! String || spub.isEmpty) {
      throw const FormatException('ServerHello.spub is required');
    }
    if (srand is! String || srand.isEmpty) {
      throw const FormatException('ServerHello.srand is required');
    }
    if (ts is! int || ts <= 0) {
      throw const FormatException('ServerHello.ts is required');
    }
    if (kid is! String || kid.trim().isEmpty) {
      throw const FormatException('ServerHello.kid is required');
    }
    if (alg is! String || alg.trim().isEmpty) {
      throw const FormatException('ServerHello.alg is required');
    }
    if (sig == null) {
      throw const FormatException('ServerHello.sig is required');
    }

    final serverPubBytes = base64Decode(spub);
    if (serverPubBytes.length != 32) {
      throw const FormatException('ServerHello.spub must be 32 bytes (X25519)');
    }

    final serverRandom = base64Decode(srand);
    if (serverRandom.isEmpty) {
      throw const FormatException('ServerHello.srand must not be empty');
    }

    final identity = ServerIdentityRef.fromWire(kid: kid, alg: alg);

    final sigBytes = _parseSignatureField(sig);
    if (sigBytes.isEmpty) {
      throw const FormatException('ServerHello.sig must not be empty');
    }

    return ServerHello(
      v: 2,
      suite: suite,
      serverEphemeralPublicKey: SimplePublicKey(serverPubBytes, type: KeyPairType.x25519),
      serverRandom: Uint8List.fromList(serverRandom),
      timestampMs: ts,
      identity: identity,
      signature: Uint8List.fromList(sigBytes),
    );
  }

  static Uint8List _parseSignatureField(Object sig) {
    if (sig is String) {
      // Accept plain base64 or Vault Transit "vault:v1:<b64>" style.
      return PfsSignature.parseVaultSignature(sig);
    }
    if (sig is List) {
      // Accept raw bytes in non-JSON usage.
      final bytes = sig.cast<int>();
      return Uint8List.fromList(bytes);
    }
    throw const FormatException('ServerHello.sig must be a string or byte list');
  }
}
