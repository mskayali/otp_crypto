<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * Global, immutable configuration (Singleton) for the OTP crypto protocol.
 * -----------------------------------------------------------------------
 * Holds protocol versioning, time windowing, and HKDF inputs shared by
 * Encryptor/Decryptor. This class **does not** perform any crypto itself.
 *
 * SECURITY NOTES:
 * - `masterKey` MUST be at least 32 bytes (AES-256).
 * - Provide raw binary bytes (PHP string) — avoid hex/base64 here.
 * - Time is abstracted via `TimeProvider` for testability.
 * - Re-initialization is disabled by default; use `forceReinitialize` only for tests.
 *
 * HINTS:
 * - Call `OtpCryptoConfig::init([...])` once during bootstrap.
 * - Access the instance with `OtpCryptoConfig::instance()`.
 */
final class OtpCryptoConfig
{
    /** @var OtpCryptoConfig|null Singleton instance. */
    private static ?OtpCryptoConfig $instance = null;

    /** Wire protocol version (e.g., 1). */
    private int $protocolVersion;

    /** Time window size in seconds (default 30). */
    private int $windowSeconds;

    /**
     * Number of adjacent windows to accept during verification (±N).
     * Example: 1 means try [w-1, w, w+1].
     */
    private int $verificationSkewWindows;

    /**
     * Master key (IKM) used by HKDF. Raw binary string (>=32 bytes).
     * NOTE: This is stored as-is; callers must manage secrecy carefully.
     */
    private string $masterKey;

    /** Optional HKDF salt (binary string) or null. */
    private ?string $hkdfSalt;

    /** Optional HKDF info/context (binary string) or null. */
    private ?string $hkdfInfo;

    /** Time source (UTC epoch seconds). */
    private TimeProvider $timeProvider;

    /**
     * Initialize the global configuration singleton (one-time).
     *
     * Required options:
     * - 'masterKey' (string, binary) : ≥ 32 bytes shared secret
     *
     * Optional options:
     * - 'salt' (string|null)         : HKDF salt (recommended protocol constant)
     * - 'info' (string|null)         : HKDF info/context (binds keys to protocol)
     * - 'protocolVersion' (int)      : default 1
     * - 'windowSeconds' (int)        : default 30
     * - 'verificationSkewWindows'    : default 0 (acceptable ± windows)
     * - 'timeProvider' (TimeProvider): default SystemTimeProvider()
     * - 'forceReinitialize' (bool)   : default false (use only for tests/rotation)
     *
     * @throws \InvalidArgumentException if inputs are invalid
     * @throws \RuntimeException if already initialized and forceReinitialize=false
     */
    public static function init(array $opts): OtpCryptoConfig
    {
        $force = (bool)($opts['forceReinitialize'] ?? false);
        if (self::$instance !== null && !$force) {
            throw new \RuntimeException(
                'OtpCryptoConfig is already initialized. Set forceReinitialize=true to replace it (use with caution).'
            );
        }

        if (!isset($opts['masterKey']) || !is_string($opts['masterKey'])) {
            throw new \InvalidArgumentException('masterKey (binary string) is required.');
        }
        $masterKey = $opts['masterKey'];
        if (strlen($masterKey) < 32) {
            throw new \InvalidArgumentException('masterKey must be at least 32 bytes.');
        }

        $protocolVersion = (int)($opts['protocolVersion'] ?? 1);
        if ($protocolVersion < 1) {
            throw new \InvalidArgumentException('protocolVersion must be >= 1.');
        }

        $windowSeconds = (int)($opts['windowSeconds'] ?? 30);
        if ($windowSeconds <= 0) {
            throw new \InvalidArgumentException('windowSeconds must be a positive integer.');
        }

        $skew = (int)($opts['verificationSkewWindows'] ?? 0);
        if ($skew < 0 || $skew > 2) {
            // keep small to avoid excessive re-HMAC attempts; tune as needed
            throw new \InvalidArgumentException('verificationSkewWindows must be between 0 and 2.');
        }

        /** @var string|null $salt */
        $salt = $opts['salt'] ?? null;
        if ($salt !== null && !is_string($salt)) {
            throw new \InvalidArgumentException('salt must be a binary string or null.');
        }

        /** @var string|null $info */
        $info = $opts['info'] ?? null;
        if ($info !== null && !is_string($info)) {
            throw new \InvalidArgumentException('info must be a binary string or null.');
        }

        /** @var TimeProvider|null $tp */
        $tp = $opts['timeProvider'] ?? null;
        if ($tp !== null && !($tp instanceof TimeProvider)) {
            throw new \InvalidArgumentException('timeProvider must implement TimeProvider.');
        }
        $timeProvider = $tp ?? new SystemTimeProvider();

        $cfg = new OtpCryptoConfig(
            protocolVersion: $protocolVersion,
            windowSeconds: $windowSeconds,
            verificationSkewWindows: $skew,
            masterKey: $masterKey,
            hkdfSalt: $salt,
            hkdfInfo: $info,
            timeProvider: $timeProvider
        );

        self::$instance = $cfg;
        return $cfg;
    }

    /**
     * Retrieve the configured singleton instance.
     *
     * @throws \RuntimeException if init() has not been called yet
     */
    public static function instance(): OtpCryptoConfig
    {
        if (self::$instance === null) {
            throw new \RuntimeException('OtpCryptoConfig is not initialized. Call OtpCryptoConfig::init(...) first.');
        }
        return self::$instance;
    }

    /**
     * Create an ephemeral (non-singleton) configuration object.
     * Useful for tests needing multiple isolated configs.
     *
     * HINT: Does NOT alter the existing singleton.
     *
     * @throws \Throwable rethrows validation errors from init()
     */
    public static function ephemeral(array $opts): OtpCryptoConfig
    {
        $backup = self::$instance;
        try {
            $opts['forceReinitialize'] = true;
            $cfg = self::init($opts);
            self::$instance = $backup; // restore original singleton
            return $cfg;
        } catch (\Throwable $e) {
            self::$instance = $backup;
            throw $e;
        }
    }

    // -- Instance state -------------------------------------------------------

    private function __construct(
        int $protocolVersion,
        int $windowSeconds,
        int $verificationSkewWindows,
        string $masterKey,
        ?string $hkdfSalt,
        ?string $hkdfInfo,
        TimeProvider $timeProvider
    ) {
        $this->protocolVersion         = $protocolVersion;
        $this->windowSeconds           = $windowSeconds;
        $this->verificationSkewWindows = $verificationSkewWindows;
        $this->masterKey               = $masterKey;
        $this->hkdfSalt                = $hkdfSalt;
        $this->hkdfInfo                = $hkdfInfo;
        $this->timeProvider            = $timeProvider;
    }

    /**
     * Computes the time window for a given epoch seconds:
     *   window = floor(epochSeconds / windowSeconds)
     *
     * @param int $epochSeconds Non-negative UNIX time (UTC).
     * @return int Window index.
     */
    public function windowForEpochSeconds(int $epochSeconds): int
    {
        if ($epochSeconds < 0) {
            throw new \InvalidArgumentException('epochSeconds must be non-negative.');
        }
        return intdiv($epochSeconds, $this->windowSeconds);
    }

    /**
     * Returns the current window based on the configured TimeProvider.
     *
     * HINT: Used by Encryptor when creating a new request.
     */
    public function currentWindow(): int
    {
        return $this->windowForEpochSeconds($this->timeProvider->nowEpochSeconds());
    }

    /**
     * Returns the list of acceptable windows for verification.
     * Example: received w=100, skew=1 => [99, 100, 101]
     *
     * HINT: Decryptor should iterate these when checking HMAC for adjacent windows.
     *
     * @param int $receivedWindow
     * @return int[]
     */
    public function acceptableWindows(int $receivedWindow): array
    {
        if ($this->verificationSkewWindows === 0) {
            return [$receivedWindow];
        }
        $out = [];
        for ($d = -$this->verificationSkewWindows; $d <= $this->verificationSkewWindows; $d++) {
            $out[] = $receivedWindow + $d;
        }
        return $out;
    }

    // -- Getters --------------------------------------------------------------

    /** Protocol version (wire `v`). */
    public function protocolVersion(): int
    {
        return $this->protocolVersion;
    }

    /** Window size in seconds. */
    public function windowSeconds(): int
    {
        return $this->windowSeconds;
    }

    /** Verification skew (±N). */
    public function verificationSkewWindows(): int
    {
        return $this->verificationSkewWindows;
    }

    /** Master key (binary string, ≥32 bytes). */
    public function masterKey(): string
    {
        return $this->masterKey;
    }

    /** HKDF salt (binary string or null). */
    public function hkdfSalt(): ?string
    {
        return $this->hkdfSalt;
    }

    /** HKDF info/context (binary string or null). */
    public function hkdfInfo(): ?string
    {
        return $this->hkdfInfo;
    }

    /** Time provider (UTC epoch seconds). */
    public function timeProvider(): TimeProvider
    {
        return $this->timeProvider;
    }
}

/**
 * TimeProvider interface and a default SystemTimeProvider implementation.
 * ----------------------------------------------------------------------
 * These are kept here so this file is self-contained. In the final structure,
 * you may move them into `src/Crypto/TimeProvider.php`.
 *
 * HINT: Provide a mock implementation in tests to control the clock.
 */
interface TimeProvider
{
    /**
     * Returns current UNIX time in seconds (UTC).
     */
    public function nowEpochSeconds(): int;
}

/**
 * Uses PHP's system clock as the time source.
 *
 * SECURITY: Use only in production; for tests, provide a mock implementation.
 */
final class SystemTimeProvider implements TimeProvider
{
    /** @inheritDoc */
    public function nowEpochSeconds(): int
    {
        return time(); // UTC seconds from the system clock
    }
}
