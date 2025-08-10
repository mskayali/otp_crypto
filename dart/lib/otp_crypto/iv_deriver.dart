/// OTP Crypto – IV derivation (time-windowed, OTP-like)
/// ----------------------------------------------------
/// Derives a 16-byte AES-CBC IV that is **not transmitted** over the wire.
/// Both sides compute the same IV deterministically from:
///   iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]
///
/// INPUTS:
/// - `macKey` : 32-byte HMAC-SHA256 key derived via HKDF
/// - `window` : floor(epochSeconds / windowSeconds)
/// - `nonce`  : exactly 8 random bytes (wire header `n`)
///
/// SECURITY NOTES:
/// - Do **not** reuse the same (window, nonce) pair within the acceptance
///   window, otherwise IVs repeat. Use a fresh nonce per message.
/// - The IV depends on `macKey`; protect that key rigorously.
/// - IV is deterministic per (window, nonce, macKey); **never send it**.
///
/// HINTS:
/// - Use `NonceGenerator.defaultGenerator()` to obtain nonces.
/// - Reuse `Bytes.ivLabel` and `Bytes.u64beInt` to avoid extra allocations.

import 'dart:typed_data';

import 'rand_nonce.dart';
import 'sha256_hmac.dart';
import 'utils.dart';

class IvDeriver {
  IvDeriver._(); // static-only

  /// Derives a 16-byte IV using:
  ///   HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]
  ///
  /// [macKey] 32-byte key used for HMAC.
  /// [window] integer time window.
  /// [nonce]  8-byte random nonce (validated).
  ///
  /// RETURNS: 16-byte IV for AES-256-CBC.
  ///
  /// Throws [ArgumentError] if inputs are malformed.
  static Uint8List derive({
    required Uint8List macKey,
    required int window,
    required Uint8List nonce,
  }) {
    if (macKey.isEmpty) {
      throw ArgumentError('macKey must not be empty.');
    }
    // Enforce 8-byte nonce (wire contract).
    NonceGenerator.validate(nonce);

    // Prepare input = "iv" || u64be(window) || nonce
    final wBytes = Bytes.u64beInt(window);
    final tagInputParts = <Uint8List>[
      Bytes.ivLabel,
      wBytes,
      nonce,
    ];

    // Compute HMAC and truncate to 16 bytes (AES-CBC IV length).
    final full = HmacSha256.computeParts(macKey, tagInputParts);
    final iv = Uint8List.sublistView(full, 0, 16);

    // Defensive copy to detach from `full` and then wipe `full`.
    final ivCopy = Uint8List.fromList(iv);
    Bytes.secureZero(full);

    return ivCopy;
  }
}
