<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * RandNonce – Cryptographically secure 8-byte nonce generator
 * -----------------------------------------------------------
 * Produces exactly 8 random bytes using PHP's CSPRNG (`random_bytes`).
 * The nonce is **not secret**, but must be unpredictable to minimize
 * collisions within a time-window. It is sent on the wire as Base64.
 *
 * SECURITY NOTES:
 * - Always call this per message to avoid IV reuse (since IV is derived
 *   from (macKey, window, nonce)).
 * - For replay mitigation, consider tracking seen nonces per-window in
 *   your application layer (LRU/cache).
 *
 * HINTS:
 * - Use `RandNonce::generate()` in the sender (Encryptor).
 * - Use `RandNonce::validate($nonce)` when parsing incoming headers.
 */
final class RandNonce
{
    private function __construct() {}

    /**
     * Returns a fresh **8-byte** nonce from the CSPRNG.
     *
     * @return string Binary string of length 8.
     *
     * @throws \Exception if `random_bytes` fails (rare).
     */
    public static function generate(): string
    {
        return random_bytes(8);
    }

    /**
     * Validates that the provided nonce is exactly 8 bytes.
     *
     * @param string $nonce Binary string.
     * @throws \InvalidArgumentException if length != 8.
     */
    public static function validate(string $nonce): void
    {
        if (strlen($nonce) !== 8) {
            throw new \InvalidArgumentException('nonce must be exactly 8 bytes.');
        }
    }
}
