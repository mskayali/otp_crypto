<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * Errors – Exception types and safe, generic messages
 * ---------------------------------------------------
 * Centralizes exception classes and non-leaking messages so cryptographic
 * internals are not exposed through error text.
 *
 * SECURITY NOTES:
 * - Keep messages generic (do not reveal whether MAC or padding failed, etc.).
 * - Log details server-side if needed, but surface generic messages to clients.
 * - Mirror names/messages with the Dart side for consistency.
 */

final class SafeErrorMessages
{
    private function __construct() {}

    /** For invalid wire format, version, missing fields, bad Base64, etc. */
    public const INVALID_MESSAGE = 'Invalid message';

    /** For failed authentication / MAC verification. */
    public const AUTHENTICATION_FAILED = 'Authentication failed';

    /** For AES decryption or padding failures. */
    public const DECRYPTION_FAILED = 'Decryption failed';

    /** For messages outside the accepted time window (skew/tolerance). */
    public const EXPIRED_OR_NOT_YET_VALID = 'Expired or not yet valid';

    /** For unexpected internal errors. */
    public const INTERNAL_ERROR = 'Internal error';
}

/**
 * Base class for all OTP crypto exceptions.
 * Adds a stable string error code in addition to the standard message.
 */
class OtpCryptoException extends \RuntimeException
{
    /** Stable code for programmatic handling (e.g., 'invalid_message'). */
    private string $errorCode;

    public function __construct(string $errorCode, string $message = "", ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->errorCode = $errorCode;
    }

    /** Returns the stable error code (non-localized). */
    public function errorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * Wrap any throwable into an OtpCryptoException with the provided code/message.
     * If $t is already an OtpCryptoException, it is returned as-is.
     */
    public static function wrap(\Throwable $t, string $errorCode, string $message): OtpCryptoException
    {
        if ($t instanceof OtpCryptoException) {
            return $t;
        }
        return new OtpCryptoException($errorCode, $message, $t);
    }
}

/** Thrown when the wire format is invalid (bad version/fields/base64, etc.). */
final class InvalidMessageException extends OtpCryptoException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('invalid_message', SafeErrorMessages::INVALID_MESSAGE, $previous);
    }
}

/** Thrown when HMAC verification fails. */
final class AuthenticationFailedException extends OtpCryptoException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('authentication_failed', SafeErrorMessages::AUTHENTICATION_FAILED, $previous);
    }
}

/** Thrown when decryption or padding check fails after successful MAC. */
final class DecryptionFailedException extends OtpCryptoException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('decryption_failed', SafeErrorMessages::DECRYPTION_FAILED, $previous);
    }
}

/** Thrown when the message window is outside the accepted tolerance. */
final class WindowOutOfRangeException extends OtpCryptoException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('window_out_of_range', SafeErrorMessages::EXPIRED_OR_NOT_YET_VALID, $previous);
    }
}

/** Thrown for unexpected internal failures (should be rare). */
final class InternalCryptoException extends OtpCryptoException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('internal_error', SafeErrorMessages::INTERNAL_ERROR, $previous);
    }
}
