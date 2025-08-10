/// OTP Crypto – HKDF-SHA256 (extract + expand)
/// -------------------------------------------
/// Implements HKDF (RFC 5869) over SHA-256 in pure Dart using our HMAC
/// construction (`HmacSha256`). Used to derive two 32-byte keys:
///   - enc_key (AES-256 key)
///   - mac_key (HMAC-SHA256 key)
///
/// SCHEME:
/// - PRK = HMAC(salt, IKM)                    // extract
/// - OKM = T(1) || T(2) || … up to L bytes    // expand
///   where T(i) = HMAC(PRK, T(i-1) || info || i)
///
/// NOTES:
/// - HashLen = 32 (SHA-256)
/// - Max output length L ≤ 255 * HashLen (per RFC 5869).
/// - If `salt` is null/empty, RFC recommends a zero-array of HashLen.
/// - We derive 64 bytes once and split: enc_key = first 32, mac_key = next 32.
///
/// HINTS:
/// - Use `deriveKeys(...)` for the common enc/mac pair derivation.
/// - Keep inputs as bytes; avoid string conversions for secrets.

import 'dart:typed_data';

import 'sha256_hmac.dart';
import 'utils.dart';

/// Pair of derived keys (32 bytes each): encryption and MAC.
class DerivedKeys {
  /// 32-byte AES-256 key.
  final Uint8List encKey;

  /// 32-byte HMAC-SHA256 key.
  final Uint8List macKey;

  const DerivedKeys(this.encKey, this.macKey);
}

class HkdfSha256 {
  HkdfSha256._(); // static-only

  /// SHA-256 digest length in bytes.
  static const int hashLen = 32;

  /// Computes the Extract step: PRK = HMAC(salt, ikm).
  ///
  /// [ikm] Input keying material (secret), any length.
  /// [salt] Optional salt; if null or empty, uses a zero array of length `hashLen`.
  ///
  /// RETURNS: 32-byte PRK.
  ///
  /// SECURITY:
  /// - Provide a non-empty random salt where feasible (protocol-level constant).
  static Uint8List extract({
    required Uint8List ikm,
    Uint8List? salt,
  }) {
    final Uint8List usedSalt = (salt == null || salt.isEmpty)
        ? Uint8List(hashLen) // RFC: zeros if salt is not provided
        : salt;
    final prk = HmacSha256.compute(usedSalt, ikm);
    return prk; // 32 bytes
  }

  /// Computes the Expand step to produce [length] bytes from a given [prk].
  ///
  /// [prk] Pseudorandom key from `extract` (must be `hashLen` bytes).
  /// [info] Optional context/application-specific information (can be empty).
  /// [length] Desired output keying material length (0 < length ≤ 255*hashLen).
  ///
  /// RETURNS: OKM (length bytes).
  ///
  /// HINT:
  /// - For two 32B keys, call with length=64 and then split.
  static Uint8List expand({
    required Uint8List prk,
    Uint8List? info,
    required int length,
  }) {
    if (prk.length != hashLen) {
      throw ArgumentError.value(prk.length, 'prk.length', 'PRK must be $hashLen bytes.');
    }
    if (length <= 0 || length > 255 * hashLen) {
      throw ArgumentError.value(length, 'length', 'Must be in range 1..${255 * hashLen}.');
    }

    final Uint8List infoBytes = (info == null) ? Uint8List(0) : info;
    final int nBlocks = (length + hashLen - 1) ~/ hashLen; // ceil
    final out = Uint8List(length);

    // Iterative T(i) generation
    Uint8List previousT = Uint8List(0);
    var offset = 0;
    for (int i = 1; i <= nBlocks; i++) {
      // T(i) = HMAC(PRK, T(i-1) || info || counterByte)
      final counter = Uint8List.fromList([i & 0xff]);
      final t = HmacSha256.computeParts(
        prk,
        [previousT, infoBytes, counter],
      );

      final copyLen = (offset + hashLen <= length) ? hashLen : (length - offset);
      out.setRange(offset, offset + copyLen, t);
      offset += copyLen;

      // Zeroize previousT and replace with new t for next round.
      Bytes.secureZero(previousT);
      previousT = t;
    }

    // Best effort: wipe the last T(i)
    Bytes.secureZero(previousT);

    return out;
  }

  /// One-shot HKDF: derive `encKey` and `macKey` (32B each) from a master key.
  ///
  /// [masterKey] IKM; MUST be at least 32 bytes (enforced by higher-level config).
  /// [salt] Optional salt (recommended random, protocol-wide constant).
  /// [info] Optional info/context (binds keys to protocol).
  ///
  /// RETURNS: { encKey: 32B, macKey: 32B }
  ///
  /// HINT:
  /// - Keep `salt` and `info` consistent across Dart/PHP for interoperability.
  static DerivedKeys deriveKeys({
    required Uint8List masterKey,
    Uint8List? salt,
    Uint8List? info,
  }) {
    final prk = extract(ikm: masterKey, salt: salt);
    final okm = expand(prk: prk, info: info, length: 64);

    // Split into two 32B keys: first for AES, second for HMAC.
    final encKey = Uint8List.sublistView(okm, 0, 32);
    final macKey = Uint8List.sublistView(okm, 32, 64);

    // Defensive copies (sublistView is backed by `okm`).
    final encKeyCopy = Uint8List.fromList(encKey);
    final macKeyCopy = Uint8List.fromList(macKey);

    // Best-effort scrubbing of intermediates.
    Bytes.secureZero(prk);
    Bytes.secureZero(okm);

    return DerivedKeys(encKeyCopy, macKeyCopy);
  }
}
