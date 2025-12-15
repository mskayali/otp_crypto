import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Supported AEAD (authenticated encryption with associated data) algorithms.
enum PfsAead {
  /// ChaCha20-Poly1305 (recommended for broad platform consistency).
  chacha20Poly1305,

  /// AES-GCM (good when hardware acceleration is reliably available).
  aesGcm,
}

/// Resolves the server's signing public key used to authenticate the handshake.
///
/// In Vault Transit terms, [kid] typically maps to a Transit key name and
/// [keyVersion] to a specific key version.
typedef ServerPublicKeyResolver = Future<SimplePublicKey?> Function(
  String kid, {
  int? keyVersion,
});

/// Configuration for the v2 PFS protocol layer.
///
/// Notes:
/// - PFS comes from ephemeral X25519 in the handshake (not from Vault).
/// - Vault is used to *sign* the handshake transcript using a long-term server
///   identity key whose private part never leaves Vault.
/// - This config is intentionally transport-agnostic; HTTP/WebSocket callers
///   feed method/path to the AAD layer.
final class PfsConfig {
  /// Protocol identifier used as HKDF "info" context and transcript domain.
  final String protocolId;

  /// AEAD algorithm for data messages.
  final PfsAead aead;

  /// Maximum allowed clock skew for message timestamps.
  final Duration maxClockSkew;

  /// Maximum allowed clock skew for the handshake (often tighter).
  final Duration handshakeMaxClockSkew;

  /// How many past sequence numbers to accept in a sliding replay window.
  ///
  /// Set to 0 to require strictly monotonic increasing sequence numbers.
  final int replayWindowSize;

  /// Resolves server identity public keys for handshake signature verification.
  final ServerPublicKeyResolver resolveServerPublicKey;

  /// Optional pinned keys to avoid network lookup in environments where the
  /// server key is provisioned out-of-band (pinning).
  final Map<String, SimplePublicKey> pinnedServerKeys;

  const PfsConfig({
    this.protocolId = 'otp-pfs-v2',
    this.aead = PfsAead.chacha20Poly1305,
    this.maxClockSkew = const Duration(seconds: 60),
    this.handshakeMaxClockSkew = const Duration(seconds: 30),
    this.replayWindowSize = 0,
    required this.resolveServerPublicKey,
    this.pinnedServerKeys = const {},
  }) : assert(replayWindowSize >= 0);

  /// Returns the cryptography implementation for the configured AEAD.
  Cipher get cipher {
    switch (aead) {
      case PfsAead.chacha20Poly1305:
        return Chacha20.poly1305Aead();
      case PfsAead.aesGcm:
        return AesGcm.with256bits();
    }
  }

  /// Handshake signature algorithm (server identity).
  SignatureAlgorithm get signatureAlgorithm => Ed25519();

  /// Key agreement algorithm (ephemeral ECDH for PFS).
  KeyExchangeAlgorithm get keyExchangeAlgorithm => X25519();

  /// Resolve a server identity key, preferring pinned keys when present.
  Future<SimplePublicKey?> resolveKey(String kid, {int? keyVersion}) async {
    final pinned = pinnedServerKeys[kid];
    if (pinned != null) return pinned;
    return resolveServerPublicKey(kid, keyVersion: keyVersion);
  }

  /// Convenience helper for pinning a raw Ed25519 public key.
  static SimplePublicKey ed25519PublicKey(Uint8List bytes) => SimplePublicKey(bytes, type: KeyPairType.ed25519);
}
