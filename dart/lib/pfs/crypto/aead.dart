import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:otp_crypto/pfs/errors.dart';

import '../pfs_config.dart';

/// AEAD helper for v2.
///
/// Design:
/// - Uses cryptography.dart ciphers (ChaCha20-Poly1305 / AES-GCM)
/// - Nonce derivation: 12-byte base XOR u64be(seq) into last 8 bytes
/// - Provides encrypt/decrypt wrappers returning/accepting (ct, tag)
///
/// Notes:
/// - We intentionally keep nonce deterministic from (base, seq) to avoid
///   sending it on the wire.
/// - This file is "crypto plumbing" only; session/replay logic lives elsewhere.
final class PfsAeadHelper {
  final PfsConfig config;

  const PfsAeadHelper(this.config);

  Cipher get _cipher => config.cipher;

  /// Derive nonce for given sequence number.
  ///
  /// nonce = nonceBase12 XOR (0x00000000 || u64be(seq)) at bytes[4..11]
  static Uint8List nonceForSeq({
    required Uint8List nonceBase12,
    required int seq,
  }) {
    if (nonceBase12.length != 12) {
      throw PfsErrors.invalidInput('nonceBase must be 12 bytes');
    }
    if (seq <= 0 || seq > 0xFFFFFFFFFFFFFFFF) {
      throw PfsErrors.invalidInput('seq out of range');
    }
    final nonce = Uint8List.fromList(nonceBase12);
    final s = _u64be(seq);
    for (var i = 0; i < 8; i++) {
      nonce[4 + i] ^= s[i];
    }
    return nonce;
  }

  /// Encrypt and return ciphertext + tag (MAC).
  Future<({Uint8List ct, Uint8List tag})> encrypt({
    required SecretKey key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) async {
    final box = await _cipher.encrypt(
      plaintext,
      secretKey: key,
      nonce: nonce,
      aad: aad,
    );

    return (
      ct: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    );
  }

  /// Decrypt ciphertext + tag.
  ///
  /// Throws [SecretBoxAuthenticationError] on authentication failure.
  Future<Uint8List> decrypt({
    required SecretKey key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
    required Uint8List aad,
  }) async {
    final box = SecretBox(
      ciphertext,
      nonce: nonce,
      mac: Mac(tag),
    );

    final pt = await _cipher.decrypt(
      box,
      secretKey: key,
      aad: aad,
    );

    return Uint8List.fromList(pt);
  }

  static Uint8List _u64be(int n) {
    final out = Uint8List(8);
    out[0] = (n >>> 56) & 0xFF;
    out[1] = (n >>> 48) & 0xFF;
    out[2] = (n >>> 40) & 0xFF;
    out[3] = (n >>> 32) & 0xFF;
    out[4] = (n >>> 24) & 0xFF;
    out[5] = (n >>> 16) & 0xFF;
    out[6] = (n >>> 8) & 0xFF;
    out[7] = n & 0xFF;
    return out;
  }
}
