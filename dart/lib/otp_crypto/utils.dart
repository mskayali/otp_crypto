/// OTP Crypto – Low-level utilities
/// --------------------------------
/// Collection of byte helpers used across the crypto stack:
/// - Base64 (standard) encode/decode with padding normalization
/// - u64 big-endian encoding (for window field)
/// - Constant-time byte equality
/// - Byte concatenation / zeroization
///
/// SECURITY NOTES:
/// - `constantTimeEquals` prevents timing leaks when comparing MACs.
/// - Use `secureZero` on temporary sensitive buffers you control.
/// - `fromBase64Strict` rejects invalid Base64 (after trimming whitespace).

import 'dart:convert' show base64, utf8;
import 'dart:typed_data';

/// Misc byte helpers.
class Bytes {
  Bytes._(); // static-only

  /// ASCII label "iv" as bytes (used in IV derivation).
  ///
  /// HINT: Reuse this to avoid re-encoding the label string.
  static final Uint8List ivLabel = Uint8List.fromList(utf8.encode('iv'));

  /// ASCII label "tag" as bytes (used in MAC derivation).
  ///
  /// HINT: Reuse this to avoid re-encoding the label string.
  static final Uint8List tagLabel = Uint8List.fromList(utf8.encode('tag'));

  /// Returns a defensive copy of [src].
  ///
  /// HINT: Use when storing user-supplied buffers.
  static Uint8List copy(Uint8List src) => Uint8List.fromList(src);

  /// Concatenates multiple byte arrays into a single Uint8List.
  ///
  /// HINT: Preserve order: concat([a, b, c]) -> a||b||c
  static Uint8List concat(List<Uint8List> parts) {
    final total = parts.fold<int>(0, (n, p) => n + p.length);
    final out = Uint8List(total);
    var offset = 0;
    for (final p in parts) {
      out.setAll(offset, p);
      offset += p.length;
    }
    return out;
  }

  /// Encodes [data] as **standard** Base64 (with padding).
  ///
  /// HINT: Use for wire fields `n`, `c`, and body tag.
  static String toBase64(Uint8List data) => base64.encode(data);

  /// Decodes a **standard** Base64 string to bytes.
  /// - Trims ASCII whitespace.
  /// - Auto-fixes missing padding if input length % 4 != 0.
  /// - Throws [FormatException] if still invalid after normalization.
  ///
  /// HINT: Use this for wire inputs; it is strict after normalization.
  static Uint8List fromBase64Strict(String b64) {
    // Remove whitespace often added by intermediaries.
    final normalized = _normalizeB64(b64);
    return Uint8List.fromList(base64.decode(normalized));
  }

  /// Constant-time comparison of two byte arrays.
  /// - Runs in time proportional to the longest input.
  /// - Does not early-return on first difference.
  ///
  /// HINT: Use to compare HMAC tags and other secret values.
  static bool constantTimeEquals(Uint8List a, Uint8List b) {
    var diff = a.length ^ b.length; // include length diff
    final maxLen = a.length > b.length ? a.length : b.length;
    for (var i = 0; i < maxLen; i++) {
      final ai = i < a.length ? a[i] : 0;
      final bi = i < b.length ? b[i] : 0;
      diff |= (ai ^ bi);
    }
    return diff == 0;
  }

  /// Overwrites the contents of [buf] with zeros.
  ///
  /// HINT: Call on temporary secrets you control once they are no longer needed.
  static void secureZero(Uint8List buf) {
    for (var i = 0; i < buf.length; i++) {
      buf[i] = 0;
    }
  }

  /// Encodes an unsigned 64-bit integer as **big-endian** 8 bytes.
  ///
  /// HINT: Use for the `window` field in derivations.
  static Uint8List u64beInt(int value) {
    if (value < 0) {
      throw ArgumentError.value(value, 'value', 'Must be non-negative.');
    }
    // Dart ints are arbitrary precision; constrain to 0..2^64-1 logically.
    final big = BigInt.from(value);
    return u64be(big);
  }

  /// Encodes an unsigned 64-bit BigInt as **big-endian** 8 bytes.
  ///
  /// HINT: Use when working with BigInt window values directly.
  static Uint8List u64be(BigInt value) {
    if (value.isNegative) {
      throw ArgumentError.value(value, 'value', 'Must be non-negative.');
    }
    // Mask to 64 bits (logical constraint).
    final mask64 = (BigInt.one << 64) - BigInt.one;
    final v = value & mask64;

    final out = Uint8List(8);
    var tmp = v;
    for (var i = 7; i >= 0; i--) {
      out[i] = (tmp & BigInt.from(0xff)).toInt();
      tmp = tmp >> 8;
    }
    return out;
  }

  /// Decodes 8 bytes **big-endian** into a non-negative BigInt.
  ///
  /// HINT: Provided for completeness; rarely needed by this protocol.
  static BigInt u64beToBigInt(Uint8List bytes, [int offset = 0]) {
    if (offset < 0 || offset + 8 > bytes.length) {
      throw RangeError.range(offset, 0, bytes.length - 8, 'offset', 'Need 8 bytes starting at offset.');
    }
    BigInt v = BigInt.zero;
    for (var i = 0; i < 8; i++) {
      v = (v << 8) | BigInt.from(bytes[offset + i]);
    }
    return v;
  }

  /// UTF-8 encode helper (labels, non-secrets).
  ///
  /// HINT: Prefer using [ivLabel] and [tagLabel] for those constants.
  static Uint8List utf8Encode(String s) => Uint8List.fromList(utf8.encode(s));

  /// UTF-8 decode helper.
  ///
  /// HINT: Use only for non-secret, small metadata; avoid for large payloads.
  static String utf8Decode(Uint8List b) => utf8.decode(b, allowMalformed: false);

  // -- Internal ----

  /// Normalizes a Base64 string:
  /// - Strips ASCII whitespace
  /// - Adds missing '=' padding up to length % 4 == 0
  static String _normalizeB64(String s) {
    // Remove common whitespace (\r, \n, space, \t).
    final trimmed = s.replaceAll(RegExp(r'\s+'), '');
    final mod = trimmed.length % 4;
    if (mod == 0) return trimmed;
    // Add '=' padding to next multiple of 4.
    final pad = 4 - mod;
    return trimmed + ('=' * pad);
  }
}
