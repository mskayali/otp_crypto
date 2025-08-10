/// OTP Crypto – HMAC-SHA256 (pure Dart impl using SHA-256 from `crypto`)
/// ---------------------------------------------------------------------
/// Implements HMAC(SHA-256) per RFC 2104 / FIPS 198-1 with a 64-byte block size.
/// We only depend on the SHA-256 digest from `package:crypto`, while the HMAC
/// construction (ipad/opad, key normalization, concatenation) is written here.
///
/// SECURITY NOTES:
/// - Keys longer than the block size (64) are first hashed with SHA-256,
///   then zero-padded up to 64 bytes (K0).
/// - HMAC output length is 32 bytes for SHA-256.
/// - Prefer `Bytes.constantTimeEquals` when comparing tags.
///
/// HINTS:
/// - Use `compute(key, [...])` to MAC multiple parts without extra copies.
/// - Avoid converting to strings; operate on bytes (`Uint8List`) end-to-end.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'utils.dart';

class HmacSha256 {
  HmacSha256._(); // static-only

  static const int _blockSize = 64; // block size for SHA-256

  /// Computes HMAC-SHA256(key, data) and returns a 32-byte tag.
  ///
  /// [key]: secret key bytes (any length; will be normalized).
  /// [data]: input bytes; recommend passing `Uint8List` to avoid extra copies.
  ///
  /// HINT: For single-part input; see `computeParts` for multi-part.
  static Uint8List compute(Uint8List key, Uint8List data) {
    return computeParts(key, [data]);
  }

  /// Computes HMAC-SHA256 over multiple parts without concatenating externally.
  ///
  /// Example:
  /// ```dart
  /// final tag = HmacSha256.computeParts(key, [part1, part2, part3]);
  /// ```
  ///
  /// HINT: Prefer this to reduce temporary allocations for large payloads.
  static Uint8List computeParts(Uint8List key, List<Uint8List> parts) {
    // 1) Normalize key to K0 (block-size bytes)
    final k0 = _normalizeKey(key);

    // 2) Prepare ipad/opad = K0 ⊕ ipad/opad
    final ipad = Uint8List(_blockSize);
    final opad = Uint8List(_blockSize);
    for (var i = 0; i < _blockSize; i++) {
      final b = k0[i];
      ipad[i] = b ^ 0x36;
      opad[i] = b ^ 0x5c;
    }

    // 3) inner = SHA256(ipad || data...)
    final innerConcat = <Uint8List>[ipad, ...parts];
    final inner = _sha256(Bytes.concat(innerConcat));

    // 4) tag = SHA256(opad || inner)
    final tag = _sha256(Bytes.concat([opad, inner]));

    // Zeroize temporary pads as a best-effort hygiene.
    Bytes.secureZero(ipad);
    Bytes.secureZero(opad);
    Bytes.secureZero(k0);

    return tag;
  }

  /// Normalizes the key for HMAC:
  /// - If key length > block size: key = SHA256(key)
  /// - If key length < block size: right-pad with zeros to block size
  /// - If key length == block size: use as-is (after copying)
  ///
  /// Returns a fresh, mutable Uint8List of length `_blockSize`.
  static Uint8List _normalizeKey(Uint8List key) {
    Uint8List k;
    if (key.length > _blockSize) {
      k = _sha256(key);
    } else {
      k = Bytes.copy(key);
    }
    if (k.length == _blockSize) {
      return k; // already block-sized
    }
    final k0 = Uint8List(_blockSize);
    k0.setAll(0, k);
    return k0;
  }

  /// Computes SHA-256 digest of [data] and returns a 32-byte array.
  ///
  /// HINT: Isolated to allow future replacement (e.g., HW-backed digest).
  static Uint8List _sha256(Uint8List data) {
    final digest = crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }
}
