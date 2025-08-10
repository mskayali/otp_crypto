/// OTP Crypto – Random 8-byte nonce generator
/// -----------------------------------------
/// Generates cryptographically-secure nonces of exactly 8 bytes.
/// Used in the wire header as `n` (Base64-encoded).
///
/// SECURITY NOTES:
/// - Uses `Random.secure()` which delegates to the platform CSPRNG.
/// - Nonce is **not** a secret, but must be unpredictable to reduce
///   collision risk within a time-window.
/// - Upstream layers may track seen nonces (per-window) to mitigate replay.
///
/// HINTS:
/// - Use `NonceGenerator.default()` for production.
/// - In tests, stub with `FixedNonceGenerator` for deterministic output.

import 'dart:math';
import 'dart:typed_data';

/// Abstract nonce generator interface to enable testing/mocking.
abstract class NonceGenerator {
  /// Returns a fresh **8-byte** nonce from a cryptographically secure source.
  ///
  /// HINT: The returned buffer is a new allocation every call.
  Uint8List nextNonce();

  /// Validates that [nonce] is exactly 8 bytes.
  ///
  /// Throws [ArgumentError] if invalid.
  ///
  /// HINT: Call this when parsing incoming headers to enforce format.
  static void validate(Uint8List nonce) {
    if (nonce.length != 8) {
      throw ArgumentError.value(
        nonce.length,
        'nonce.length',
        'Nonce must be exactly 8 bytes.',
      );
    }
  }

  /// Factory to obtain the default CSPRNG-backed generator.
  factory NonceGenerator.defaultGenerator() => _DefaultNonceGenerator();
}

/// Default CSPRNG-backed nonce generator using `Random.secure()`.
class _DefaultNonceGenerator implements NonceGenerator {
  final Random _rng = Random.secure();

  /// Fills an 8-byte buffer with random bytes from the CSPRNG.
  @override
  Uint8List nextNonce() {
    final out = Uint8List(8);
    for (var i = 0; i < out.length; i++) {
      // Next secure random 8-bit value (0..255).
      out[i] = _rng.nextInt(256);
    }
    return out;
  }
}

/// Deterministic nonce generator for tests.
/// Repeats the provided sequence cyclically if shorter than 8 bytes.
class FixedNonceGenerator implements NonceGenerator {
  final Uint8List _seed;
  int _counter = 0;

  /// Creates a predictable generator using [seed] bytes.
  ///
  /// HINT: Provide at least 8 bytes to avoid repetition within one nonce.
  FixedNonceGenerator(Uint8List seed)
      : _seed = Uint8List.fromList(seed), // defensive copy
        assert(seed.isNotEmpty, 'seed must not be empty');

  /// Produces an 8-byte nonce by reading forward from [_seed] cyclically.
  @override
  Uint8List nextNonce() {
    final out = Uint8List(8);
    for (var i = 0; i < out.length; i++) {
      out[i] = _seed[(_counter + i) % _seed.length];
    }
    _counter = (_counter + 8) % _seed.length;
    return out;
  }
}
