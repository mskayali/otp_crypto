import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:otp_crypto/pfs/errors.dart';

/// Server identity signature algorithm.
///
/// For Vault Transit integration, Ed25519 is a solid default (fast, modern).
enum ServerSigAlg {
  ed25519;

  String get id {
    switch (this) {
      case ServerSigAlg.ed25519:
        return 'ed25519';
    }
  }

  static ServerSigAlg parse(String value) {
    final v = value.trim().toLowerCase();
    switch (v) {
      case 'ed25519':
        return ServerSigAlg.ed25519;
      default:
        throw PfsErrors.invalidInput('Unsupported server signature algorithm: $value');
    }
  }
}

/// Reference to the server identity key used to authenticate the handshake.
///
/// In Vault Transit terms:
/// - [kid] typically maps to a Transit key name (e.g. "pfs-server-id").
/// - [keyVersion] maps to a specific key version (rotation support).
final class ServerIdentityRef {
  final String kid;
  final int? keyVersion;
  final ServerSigAlg alg;

  const ServerIdentityRef({
    required this.kid,
    this.keyVersion,
    this.alg = ServerSigAlg.ed25519,
  });

  /// Compact wire form: "<kid>[:<ver>]"
  ///
  /// Examples:
  /// - "pfs-server-id"
  /// - "pfs-server-id:3"
  String toWireKid() => keyVersion == null ? kid : '$kid:${keyVersion!.toString()}';

  static ServerIdentityRef fromWire({
    required String kid,
    String? alg,
  }) {
    final trimmed = kid.trim();
    if (trimmed.isEmpty) {
      throw PfsErrors.handshakeFailed('kid cannot be empty');
    }

    final parts = trimmed.split(':');
    final name = parts.first;
    int? ver;

    if (parts.length > 2) {
      throw PfsErrors.handshakeFailed('Invalid kid format: $kid');
    }
    if (parts.length == 2) {
      ver = int.tryParse(parts[1]);
      if (ver == null || ver <= 0) {
        throw PfsErrors.handshakeFailed('Invalid key version in kid: $kid');
      }
    }

    return ServerIdentityRef(
      kid: name,
      keyVersion: ver,
      alg: alg == null ? ServerSigAlg.ed25519 : ServerSigAlg.parse(alg),
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'kid': kid,
        if (keyVersion != null) 'keyVersion': keyVersion,
        'alg': alg.id,
      };

  static ServerIdentityRef fromJson(Map<String, dynamic> json) {
    final kid = json['kid'];
    if (kid is! String || kid.trim().isEmpty) {
      throw PfsErrors.handshakeFailed('Invalid kid in ServerIdentityRef JSON');
    }
    final keyVersion = json['keyVersion'];
    final alg = json['alg'];

    return ServerIdentityRef(
      kid: kid,
      keyVersion: keyVersion is int ? keyVersion : null,
      alg: alg is String ? ServerSigAlg.parse(alg) : ServerSigAlg.ed25519,
    );
  }
}

/// A resolved server identity key (public) for verifying handshake signatures.
final class ServerIdentityKey {
  final ServerIdentityRef ref;
  final SimplePublicKey publicKey;

  const ServerIdentityKey({
    required this.ref,
    required this.publicKey,
  });

  /// Convenience factory for Ed25519 public keys.
  factory ServerIdentityKey.ed25519({
    required ServerIdentityRef ref,
    required Uint8List publicKeyBytes,
  }) {
    return ServerIdentityKey(
      ref: ref,
      publicKey: SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519),
    );
  }

  /// Base64 (standard) encoding of the public key bytes.
  String publicKeyB64() => base64Encode(publicKey.bytes);

  /// Create from base64-encoded public key bytes.
  static ServerIdentityKey fromB64({
    required ServerIdentityRef ref,
    required String publicKeyB64,
  }) {
    final bytes = base64Decode(publicKeyB64);
    switch (ref.alg) {
      case ServerSigAlg.ed25519:
        return ServerIdentityKey.ed25519(ref: ref, publicKeyBytes: bytes);
    }
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'ref': ref.toJson(),
        'publicKeyB64': publicKeyB64(),
      };

  static ServerIdentityKey fromJson(Map<String, dynamic> json) {
    final refJson = json['ref'];
    final pkB64 = json['publicKeyB64'];
    if (refJson is! Map<String, dynamic> || pkB64 is! String) {
      throw PfsErrors.handshakeFailed('Invalid ServerIdentityKey JSON');
    }
    final ref = ServerIdentityRef.fromJson(refJson);
    return ServerIdentityKey.fromB64(ref: ref, publicKeyB64: pkB64);
  }
}
