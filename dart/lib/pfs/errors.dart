/// v2/PFS error types.
///
/// Design goals:
/// - Avoid oracle behavior: callers should usually treat all failures the same
///   at the API boundary (e.g. HTTP 400/401 with generic message).
/// - Still allow internal diagnostics via error codes.
enum PfsErrorCode {
  unknown,
  invalidInput,
  unsupportedVersion,
  handshakeFailed,
  signatureInvalid,
  keyNotFound,
  timestampSkew,
  sidMismatch,
  replayDetected,
  authFailed,
  payloadTooLarge,
}

class PfsException implements Exception {
  final PfsErrorCode code;
  final String message;

  /// Optional internal detail (do not expose to untrusted clients).
  final Object? detail;

  const PfsException(
    this.code,
    this.message, {
    this.detail,
  });

  @override
  String toString() => 'PfsException($code): $message';
}

/// Factory helpers to standardize thrown errors.
///
/// Recommendation:
/// - At transport boundary, map *all* PfsException to a generic response.
/// - Log only code + detail internally.
final class PfsErrors {
  static PfsException invalidInput([Object? detail]) => PfsException(
        PfsErrorCode.invalidInput,
        'invalid input',
        detail: detail,
      );

  static PfsException unsupportedVersion([Object? detail]) => PfsException(
        PfsErrorCode.unsupportedVersion,
        'unsupported version',
        detail: detail,
      );

  static PfsException handshakeFailed([Object? detail]) => PfsException(
        PfsErrorCode.handshakeFailed,
        'handshake failed',
        detail: detail,
      );

  static PfsException signatureInvalid([Object? detail]) => PfsException(
        PfsErrorCode.signatureInvalid,
        'signature invalid',
        detail: detail,
      );

  static PfsException keyNotFound([Object? detail]) => PfsException(
        PfsErrorCode.keyNotFound,
        'key not found',
        detail: detail,
      );

  static PfsException timestampSkew([Object? detail]) => PfsException(
        PfsErrorCode.timestampSkew,
        'timestamp skew',
        detail: detail,
      );

  static PfsException sidMismatch([Object? detail]) => PfsException(
        PfsErrorCode.sidMismatch,
        'sid mismatch',
        detail: detail,
      );

  static PfsException replayDetected([Object? detail]) => PfsException(
        PfsErrorCode.replayDetected,
        'replay detected',
        detail: detail,
      );

  static PfsException authFailed([Object? detail]) => PfsException(
        PfsErrorCode.authFailed,
        'authentication failed',
        detail: detail,
      );

  static PfsException payloadTooLarge([Object? detail]) => PfsException(
        PfsErrorCode.payloadTooLarge,
        'payload too large',
        detail: detail,
      );

  static PfsException unknown([Object? detail]) => PfsException(
        PfsErrorCode.unknown,
        'error',
        detail: detail,
      );
}
