/// OTP Crypto – Error types and safe messages
/// ------------------------------------------
/// Centralizes exception classes and user-facing safe messages so that
/// cryptographic internals are not leaked through error text.
///
/// SECURITY NOTES:
/// - Never expose low-level failure reasons (e.g., "MAC mismatch at index…").
/// - Keep messages generic and consistent across platforms (Dart/PHP).
/// - Prefer throwing specific subclasses to aid debugging in logs while still
///   returning generic messages to callers/UI.
///
/// HINT:
/// - Use `SafeErrorMessages` when you need a generic string for UI/log.
/// - Catch low-level exceptions and wrap them with `OtpCryptoException.wrap(...)`.

/// Canonical, generic messages to avoid information leakage.
class SafeErrorMessages {
  SafeErrorMessages._(); // static-only

  /// For invalid wire format, version, missing fields, bad b64, etc.
  static const String invalidMessage = 'Invalid message';

  /// For failed authentication/MAC verification.
  static const String authenticationFailed = 'Authentication failed';

  /// For AES decryption or padding failures.
  static const String decryptionFailed = 'Decryption failed';

  /// For messages outside the accepted time window (skew/tolerance).
  static const String expiredOrNotYetValid = 'Expired or not yet valid';

  /// For unexpected internal errors.
  static const String internalError = 'Internal error';
}

/// Base class for all OTP crypto exceptions.
class OtpCryptoException implements Exception {
  /// Stable error code (not localized) for programmatic handling.
  final String code;

  /// Human-readable, **generic** message safe to show to users.
  final String message;

  /// Optional cause (low-level exception) for diagnostics.
  final Object? cause;

  /// Optional stack trace from the originating error.
  final StackTrace? stackTrace;

  const OtpCryptoException(
    this.code,
    this.message, {
    this.cause,
    this.stackTrace,
  });

  @override
  String toString() => 'OtpCryptoException($code): $message';

  /// Wraps any [error] as an [OtpCryptoException] with the given [code] and
  /// generic [message]. If [error] is already an [OtpCryptoException], it is
  /// returned unchanged.
  ///
  /// HINT: Use in catch blocks to ensure uniform, safe error reporting.
  static OtpCryptoException wrap(
    Object error, {
    required String code,
    required String message,
    StackTrace? stackTrace,
  }) {
    if (error is OtpCryptoException) return error;
    return OtpCryptoException(
      code,
      message,
      cause: error,
      stackTrace: stackTrace,
    );
  }
}

/// Thrown when the wire format is invalid (bad version/fields/base64, etc).
class InvalidMessageException extends OtpCryptoException {
  InvalidMessageException({Object? cause, StackTrace? stackTrace})
      : super(
          'invalid_message',
          SafeErrorMessages.invalidMessage,
          cause: cause,
          stackTrace: stackTrace,
        );
}

/// Thrown when HMAC verification fails.
class AuthenticationFailedException extends OtpCryptoException {
  AuthenticationFailedException({Object? cause, StackTrace? stackTrace})
      : super(
          'authentication_failed',
          SafeErrorMessages.authenticationFailed,
          cause: cause,
          stackTrace: stackTrace,
        );
}

/// Thrown when decryption or padding check fails after successful MAC.
class DecryptionFailedException extends OtpCryptoException {
  DecryptionFailedException({Object? cause, StackTrace? stackTrace})
      : super(
          'decryption_failed',
          SafeErrorMessages.decryptionFailed,
          cause: cause,
          stackTrace: stackTrace,
        );
}

/// Thrown when the message window is outside the accepted tolerance.
class WindowOutOfRangeException extends OtpCryptoException {
  WindowOutOfRangeException({Object? cause, StackTrace? stackTrace})
      : super(
          'window_out_of_range',
          SafeErrorMessages.expiredOrNotYetValid,
          cause: cause,
          stackTrace: stackTrace,
        );
}

/// Thrown for unexpected internal failures (should be rare).
class InternalCryptoException extends OtpCryptoException {
  InternalCryptoException({Object? cause, StackTrace? stackTrace})
      : super(
          'internal_error',
          SafeErrorMessages.internalError,
          cause: cause,
          stackTrace: stackTrace,
        );
}
