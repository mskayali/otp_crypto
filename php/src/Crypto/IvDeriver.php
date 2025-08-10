<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * IvDeriver – Deterministic IV derivation (OTP-like, time-windowed)
 * -----------------------------------------------------------------
 * Derives a 16-byte AES-CBC IV that is **not transmitted**. Both sides
 * compute the same IV from:
 *
 *   iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]
 *
 * INPUTS:
 * - $macKey : 32-byte HMAC-SHA256 key (binary string) derived via HKDF.
 * - $window : floor(epochSeconds / windowSeconds), non-negative integer.
 * - $nonce  : exactly 8 random bytes (binary string).
 *
 * SECURITY NOTES:
 * - Never reuse (window, nonce) pairs within the acceptance window; always
 *   generate a fresh 8-byte nonce per message to avoid IV repetition.
 * - IV depends on the secret `macKey`; never expose `macKey`.
 * - IV is deterministic; **do not send it** on the wire.
 *
 * HINTS:
 * - Use `RandNonce` (CSPRNG) on the sender to produce the 8-byte nonce.
 * - Reuse `Utils::IV_LABEL` and `Utils::u64be($window)` to build input.
 */
final class IvDeriver
{
    private function __construct() {}

    /**
     * Derives a 16-byte IV using:
     *   HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]
     *
     * @param string $macKey  32-byte HMAC-SHA256 key (binary).
     * @param int    $window  Non-negative window index.
     * @param string $nonce   8-byte random nonce (binary).
     * @return string         16-byte IV (binary).
     *
     * @throws \InvalidArgumentException if inputs are malformed.
     */
    public static function derive(string $macKey, int $window, string $nonce): string
    {
        if ($window < 0) {
            throw new \InvalidArgumentException('window must be non-negative.');
        }
        if (strlen($nonce) !== 8) {
            throw new \InvalidArgumentException('nonce must be exactly 8 bytes.');
        }
        if ($macKey === '') {
            throw new \InvalidArgumentException('macKey must not be empty.');
        }

        // Prepare input: "iv" || u64be(window) || nonce
        $wBytes = Utils::u64be($window);
        $parts  = [Utils::IV_LABEL, $wBytes, $nonce];

        // Compute HMAC and take the first 16 bytes for the IV.
        $full = HmacSha256::computeParts($macKey, $parts);
        return substr($full, 0, 16);
    }
}
