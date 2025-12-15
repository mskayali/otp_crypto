import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../pfs_config.dart';
import 'transcript.dart';

/// Output of the v2 key schedule.
final class PfsSessionKeys {
  /// AEAD encryption key.
  final SecretKey aeadKey;

  /// Base material for per-message nonces.
  ///
  /// We derive a 12-byte base and then XOR-in the message sequence number
  /// (u64be) into the last 8 bytes to get a unique 96-bit nonce per message.
  final Uint8List nonceBase12;

  /// Session identifier (first 16 bytes of transcript hash).
  final Uint8List sid16;

  const PfsSessionKeys({
    required this.aeadKey,
    required this.nonceBase12,
    required this.sid16,
  });
}

/// Key schedule for v2:
///
/// shared = X25519(client_eph_priv, server_eph_pub)
/// salt   = SHA256(transcript_bytes)
/// PRK    = HKDF-Extract(salt, shared)
/// OKM    = HKDF-Expand(PRK, info = protocolId + "/keys", len = keyLen + 12)
///
/// Output:
/// - aeadKey (32 bytes) for ChaCha20-Poly1305 / AES-256-GCM
/// - nonceBase12 (12 bytes)
final class KeySchedule {
  final PfsConfig config;

  const KeySchedule(this.config);

  Future<PfsSessionKeys> derive({
    required SecretKey clientEphemeralPrivateKey,
    required SimplePublicKey serverEphemeralPublicKey,
    required HandshakeTranscript transcript,
  }) async {
    // 1) Shared secret (PFS)
    final shared = await config.keyExchangeAlgorithm.sharedSecretKey(
      keyPair: _StaticKeyPair(clientEphemeralPrivateKey),
      remotePublicKey: serverEphemeralPublicKey,
    );

    // 2) salt = SHA256(transcript)
    final salt = await transcript.hashSha256();

    // 3) HKDF: expand to (32 + 12) bytes
    final hkdf = Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32 + 12,
    );

    final info = utf8.encode('${config.protocolId}/keys');
    final okmKey = await hkdf.deriveKey(
      secretKey: shared,
      nonce: salt, // Using transcript hash as HKDF salt/nonce.
      info: info,
    );

    final okmBytes = await okmKey.extractBytes();
    if (okmBytes.length != 44) {
      throw StateError('HKDF output length mismatch: ${okmBytes.length}');
    }

    // Optimization: copy once, then slice views from the same buffer.
    final okmBuf = Uint8List.fromList(okmBytes);
    final keyBytes = Uint8List.sublistView(okmBuf, 0, 32);
    final nonceBase = Uint8List.sublistView(okmBuf, 32, 44);

    final sid16 = await transcript.sid16();

    return PfsSessionKeys(
      aeadKey: SecretKey(Uint8List.fromList(keyBytes)),
      nonceBase12: Uint8List.fromList(nonceBase),
      sid16: Uint8List.fromList(sid16),
    );
  }
}

/// cryptography.dart's KeyExchangeAlgorithm.sharedSecretKey requires a KeyPair.
/// We only have the private key bytes from an ephemeral X25519 key generated
/// elsewhere, so we wrap it in a KeyPair implementation.
///
/// This is internal and keeps private key material in a SecretKey.
final class _StaticKeyPair implements KeyPair {
  final SecretKey _privateKey;

  bool _destroyed = false;

  // Cache to avoid repeated extraction/derivation work.
  Uint8List? _cachedPrivateBytes;
  SimplePublicKey? _cachedPublicKey;

  _StaticKeyPair(this._privateKey);

  @override
  bool get hasBeenDestroyed => _destroyed;

  @override
  void destroy() {
    if (_destroyed) return;
    _destroyed = true;

    // Best-effort: wipe any cached private bytes we pulled into memory.
    final priv = _cachedPrivateBytes;
    if (priv != null) {
      for (var i = 0; i < priv.length; i++) {
        priv[i] = 0;
      }
    }

    _cachedPrivateBytes = null;
    _cachedPublicKey = null;

    // Best-effort: if underlying SecretKey supports destroy (SecretKeyData does),
    // call it. If it doesn't, ignore.
    try {
      (_privateKey as dynamic).destroy();
    } catch (_) {
      // ignore
    }
  }

  @override
  Future<KeyPairData> extract() async {
    if (_destroyed) {
      throw StateError('KeyPair has been destroyed');
    }

    _cachedPrivateBytes ??= Uint8List.fromList(await _privateKey.extractBytes());

    final privBytes = _cachedPrivateBytes!;
    if (privBytes.length != 32) {
      throw StateError(
        'X25519 private key must be 32 bytes, got ${privBytes.length}',
      );
    }

    _cachedPublicKey ??= await (await X25519().newKeyPairFromSeed(privBytes)).extractPublicKey();

    return SimpleKeyPairData(
      List<int>.from(privBytes),
      publicKey: _cachedPublicKey!,
      type: KeyPairType.x25519,
    );
  }

  @override
  Future<PublicKey> extractPublicKey() async {
    if (_destroyed) {
      throw StateError('KeyPair has been destroyed');
    }
    if (_cachedPublicKey != null) return _cachedPublicKey!;
    final data = await extract();
    return data.publicKey;
  }

  // Optional internal helper (not part of KeyPair API in cryptography):
  Future<SecretKey> extractPrivateKey() async {
    if (_destroyed) {
      throw StateError('KeyPair has been destroyed');
    }
    return _privateKey;
  }
}
