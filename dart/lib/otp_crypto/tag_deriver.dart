/// OTP Crypto – Authentication tag derivation (Encrypt-then-MAC)
/// -------------------------------------------------------------
/// Computes the MAC tag over the ciphertext using:
///   tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)
///
/// INPUTS:
/// - `macKey`    : 32-byte HMAC-SHA256 key derived via HKDF
/// - `window`    : floor(epochSeconds / windowSeconds)
/// - `nonce`     : exactly 8 random bytes (wire header `n`)
/// - `ciphertext`: AES-256-CBC output bytes (header `c`, Base64 before/after)
///
/// SECURITY NOTES:
/// - This is **Encrypt-then-MAC**: always verify the tag before decryption.
/// - Use constant-time comparison for tag verification (see `Bytes.constantTimeEquals`).
/// - Do not include plaintext in the MAC; only the ciphertext and associated data.
///
/// HINTS:
/// - Reuse `Bytes.tagLabel` and `Bytes.u64beInt(window)` to build the input.
/// - `nonce` length is enforced to be 8 bytes.

import 'dart:typed_data';

import 'rand_nonce.dart';
import 'sha256_hmac.dart';
import 'utils.dart';

class TagDeriver {
  TagDeriver._(); // static-only

  /// Computes:
  ///   tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)
  ///
  /// RETURNS: 32-byte HMAC-SHA256 tag.
  ///
  /// Throws [ArgumentError] if inputs are malformed.
  static Uint8List derive({
    required Uint8List macKey,
    required int window,
    required Uint8List nonce,
    required Uint8List ciphertext,
  }) {
    if (macKey.isEmpty) {
      throw ArgumentError('macKey must not be empty.');
    }
    NonceGenerator.validate(nonce);

    // Prepare input = "tag" || u64be(window) || nonce || ciphertext
    final wBytes = Bytes.u64beInt(window);
    final parts = <Uint8List>[
      Bytes.tagLabel,
      wBytes,
      nonce,
      ciphertext,
    ];

    // Compute HMAC over the concatenated parts.
    return HmacSha256.computeParts(macKey, parts);
  }
}
