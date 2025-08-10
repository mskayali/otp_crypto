/// OTP Crypto – Global configuration (Singleton)
/// --------------------------------------------
/// Holds protocol settings and keying material shared by both Encryptor/Decryptor.
/// This class does **not** perform crypto itself; it only centralizes configuration
/// like protocol version, window size, and HKDF inputs.
///
/// SECURITY NOTES:
/// - `masterKey` must be at least 32 bytes (AES-256).
/// - Provide the key as bytes (never as a UTF-8 string).
/// - Time is abstracted with `TimeProvider` for testability.
/// - Re-initialization is intentionally disallowed by default to avoid key swaps
///   at runtime. Use `forceReinitialize` only in controlled contexts (e.g., tests).

import 'dart:typed_data';

/// Abstraction for providing current time (UNIX epoch seconds).
/// Implementations should return UTC-based seconds.
///
/// HINT: In production use a monotonic/system clock (UTC).
abstract class TimeProvider {
  /// Returns current UNIX time in seconds (UTC).
  int nowEpochSeconds();
}

/// INTERNAL default time provider used when none is supplied.
/// Kept private to avoid API leakage; a public SystemTimeProvider
/// will be provided in `time_provider.dart`.
class _DefaultSystemTimeProvider implements TimeProvider {
  @override
  int nowEpochSeconds() => DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
}

/// Immutable, process-wide configuration for the OTP crypto protocol.
class OtpCryptoConfig {
  static OtpCryptoConfig? _instance;

  /// Retrieve the globally configured instance.
  /// Throws if `initialize` has not been called.
  ///
  /// HINT: Call `OtpCryptoConfig.initialize(...)` once at app startup.
  static OtpCryptoConfig get instance {
    final inst = _instance;
    if (inst == null) {
      throw StateError('OtpCryptoConfig is not initialized. Call initialize(...) first.');
    }
    return inst;
  }

  /// True if the singleton was already initialized.
  static bool get isInitialized => _instance != null;

  /// Initializes the global configuration (one-time).
  ///
  /// - `masterKey`: ≥ 32 bytes shared secret (IKM for HKDF).
  /// - `salt`: optional HKDF salt (recommend random, app-wide constant).
  /// - `info`: optional HKDF info/context string (protocol-binding).
  /// - `protocolVersion`: wire-level version. Current: 1
  /// - `windowSeconds`: time window size (default 30).
  /// - `verificationSkewWindows`: how many adjacent windows to accept
  ///   during verification (e.g., 1 means try [w-1, w, w+1]).
  /// - `timeProvider`: custom time provider; if null uses a default.
  ///
  /// SECURITY:
  /// - Use `forceReinitialize` only for tests or controlled rotation flows.
  static OtpCryptoConfig initialize({
    required Uint8List masterKey,
    Uint8List? salt,
    Uint8List? info,
    int protocolVersion = 1,
    int windowSeconds = 30,
    int verificationSkewWindows = 0,
    TimeProvider? timeProvider,
    bool forceReinitialize = false,
  }) {
    if (_instance != null && !forceReinitialize) {
      throw StateError('OtpCryptoConfig is already initialized. Set forceReinitialize=true to replace (use with caution).');
    }
    if (masterKey.length < 32) {
      throw ArgumentError.value(masterKey.length, 'masterKey.length', 'Must be at least 32 bytes.');
    }
    if (windowSeconds <= 0) {
      throw ArgumentError.value(windowSeconds, 'windowSeconds', 'Must be a positive integer.');
    }
    if (verificationSkewWindows < 0 || verificationSkewWindows > 2) {
      // keeping this small avoids costly re-MAC attempts; tune as needed
      throw ArgumentError.value(verificationSkewWindows, 'verificationSkewWindows', 'Must be between 0 and 2.');
    }

    final cfg = OtpCryptoConfig._(
      protocolVersion: protocolVersion,
      windowSeconds: windowSeconds,
      verificationSkewWindows: verificationSkewWindows,
      masterKey: _copy(masterKey),
      hkdfSalt: salt != null ? _copy(salt) : null,
      hkdfInfo: info != null ? _copy(info) : null,
      timeProvider: timeProvider ?? _DefaultSystemTimeProvider(),
    );
    _instance = cfg;
    return cfg;
  }

  /// Creates a non-global, immutable config object (not assigned to singleton).
  /// Useful for unit tests that need multiple isolated configs at once.
  ///
  /// HINT: Prefer `initialize` for app-global configuration.
  factory OtpCryptoConfig.ephemeral({
    required Uint8List masterKey,
    Uint8List? salt,
    Uint8List? info,
    int protocolVersion = 1,
    int windowSeconds = 30,
    int verificationSkewWindows = 0,
    TimeProvider? timeProvider,
  }) {
    if (masterKey.length < 32) {
      throw ArgumentError.value(masterKey.length, 'masterKey.length', 'Must be at least 32 bytes.');
    }
    if (windowSeconds <= 0) {
      throw ArgumentError.value(windowSeconds, 'windowSeconds', 'Must be a positive integer.');
    }
    if (verificationSkewWindows < 0 || verificationSkewWindows > 2) {
      throw ArgumentError.value(verificationSkewWindows, 'verificationSkewWindows', 'Must be between 0 and 2.');
    }
    return OtpCryptoConfig._(
      protocolVersion: protocolVersion,
      windowSeconds: windowSeconds,
      verificationSkewWindows: verificationSkewWindows,
      masterKey: _copy(masterKey),
      hkdfSalt: salt != null ? _copy(salt) : null,
      hkdfInfo: info != null ? _copy(info) : null,
      timeProvider: timeProvider ?? _DefaultSystemTimeProvider(),
    );
  }

  final int protocolVersion;
  final int windowSeconds;
  final int verificationSkewWindows;
  final Uint8List masterKey;
  final Uint8List? hkdfSalt;
  final Uint8List? hkdfInfo;
  final TimeProvider timeProvider;

  OtpCryptoConfig._({
    required this.protocolVersion,
    required this.windowSeconds,
    required this.verificationSkewWindows,
    required this.masterKey,
    required this.hkdfSalt,
    required this.hkdfInfo,
    required this.timeProvider,
  });

  /// Computes the time window for a given epoch seconds using:
  ///   window = floor(epochSeconds / windowSeconds)
  ///
  /// HINT: Use this when building headers (`w`).
  int windowForEpochSeconds(int epochSeconds) {
    if (epochSeconds < 0) {
      throw ArgumentError.value(epochSeconds, 'epochSeconds', 'Must be non-negative.');
    }
    return epochSeconds ~/ windowSeconds;
  }

  /// Returns the current time window using the configured `TimeProvider`.
  ///
  /// HINT: Encryptor will call this when generating a new request.
  int currentWindow() => windowForEpochSeconds(timeProvider.nowEpochSeconds());

  /// Returns the list of acceptable windows for verification.
  /// Example: w=100, skew=1 => [99, 100, 101]
  ///
  /// HINT: Decryptor should iterate these when verifying tags.
  List<int> acceptableWindows(int receivedWindow) {
    if (verificationSkewWindows == 0) return [receivedWindow];
    final List<int> ws = <int>[];
    for (int d = -verificationSkewWindows; d <= verificationSkewWindows; d++) {
      ws.add(receivedWindow + d);
    }
    return ws;
  }

  /// BEST PRACTICE: Zeroize temporary buffers you create in callers after use.
  /// Dart's GC does not guarantee immediate scrubbing of `Uint8List` contents.
  static Uint8List _copy(Uint8List src) => Uint8List.fromList(src);
}
