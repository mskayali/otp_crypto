/// OTP Crypto – Time providers
/// ---------------------------
/// Concrete implementations of the `TimeProvider` abstraction declared in
/// `otp_crypto_config.dart`. These help isolate time from the system clock
/// for testability and skew simulations.
///
/// - `SystemTimeProvider`: uses the real system UTC time.
/// - `AdjustableTimeProvider`: mutable time source for tests; you can set or
///   advance time deterministically.
///
/// HINTS:
/// - Prefer `SystemTimeProvider` in production.
/// - Use `AdjustableTimeProvider` in unit/integration tests to freeze/advance time.
/// - All times are expressed as UNIX epoch seconds (UTC).

import 'otp_crypto_config.dart';

/// Uses the real system clock (UTC) as the current time source.
///
/// HINT: This is the recommended provider for production usage.
class SystemTimeProvider implements TimeProvider {
  /// Returns current UNIX time in seconds (UTC).
  @override
  int nowEpochSeconds() => DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
}

/// Mutable time source for tests and deterministic flows.
///
/// USAGE EXAMPLE:
/// ```dart
/// final tp = AdjustableTimeProvider(initialEpochSeconds: 1_700_000_000);
/// expect(tp.nowEpochSeconds(), 1700000000);
/// tp.advance(seconds: 45);
/// expect(tp.nowEpochSeconds(), 1700000045);
/// tp.setNow(epochSeconds: 1700001000);
/// ```
///
/// SECURITY NOTE:
/// - Never use this provider in production; it is meant for tests only.
class AdjustableTimeProvider implements TimeProvider {
  int _epochSeconds;

  /// Creates an adjustable provider at the given [initialEpochSeconds] (UTC).
  ///
  /// HINT: Provide a deterministic fixed value in tests.
  AdjustableTimeProvider({required int initialEpochSeconds}) : _epochSeconds = _requireNonNegative(initialEpochSeconds);

  /// Returns the current mocked UNIX time in seconds (UTC).
  @override
  int nowEpochSeconds() => _epochSeconds;

  /// Sets the current mocked time to [epochSeconds] (UTC).
  ///
  /// HINT: Use to jump to an exact moment (e.g., next 30s window).
  void setNow({required int epochSeconds}) {
    _epochSeconds = _requireNonNegative(epochSeconds);
  }

  /// Advances time by [seconds] (can be negative to move backwards).
  ///
  /// HINT: Useful for simulating window rollovers (±30s).
  void advance({required int seconds}) {
    final next = _epochSeconds + seconds;
    if (next < 0) {
      throw ArgumentError.value(
        seconds,
        'seconds',
        'Advance would result in negative epoch seconds.',
      );
    }
    _epochSeconds = next;
  }

  // -- helpers --

  static int _requireNonNegative(int v) {
    if (v < 0) {
      throw ArgumentError.value(v, 'epochSeconds', 'Must be non-negative.');
    }
    return v;
  }
}
