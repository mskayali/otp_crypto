<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * TagDeriver – Authentication tag (Encrypt-then-MAC)
 * --------------------------------------------------
 * Computes the HMAC tag over the ciphertext per protocol:
 *
 *   tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)
 *
 * INPUTS:
 * - $macKey     : 32-byte HMAC-SHA256 key (binary) derived via HKDF.
 * - $window     : floor(epochSeconds / windowSeconds), non-negative integer.
 * - $nonce      : exactly 8 random bytes (binary).
 * - $ciphertext : AES-256-CBC output (binary).
 *
 * OUTPUT:
 * - 32-byte tag (binary) for transmission in the message body (Base64 on wire).
 *
 * SECURITY NOTES:
 * - Always verify this tag in constant time *before* attempting decryption.
 * - Do not MAC the plaintext; MAC the ciphertext (Encrypt-then-MAC).
 */
final class TagDeriver
{
    private function __construct() {}

    /**
     * Computes:
     *   HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)
     *
     * @param string $macKey
     * @param int    $window
     * @param string $nonce
     * @param string $ciphertext
     * @return string 32-byte HMAC tag (binary).
     *
     * @throws \InvalidArgumentException if inputs are malformed.
     */
    public static function derive(string $macKey, int $window, string $nonce, string $ciphertext): string
    {
        if ($window < 0) {
            throw new \InvalidArgumentException('window must be non-negative.');
        }
        if ($macKey === '') {
            throw new \InvalidArgumentException('macKey must not be empty.');
        }
        if (strlen($nonce) !== 8) {
            throw new \InvalidArgumentException('nonce must be exactly 8 bytes.');
        }
        if ($ciphertext === '') {
            throw new \InvalidArgumentException('ciphertext must not be empty.');
        }

        // Build input: "tag" || u64be(window) || nonce || ciphertext
        $wBytes = Utils::u64be($window);
        return HmacSha256::computeParts($macKey, [
            Utils::TAG_LABEL,
            $wBytes,
            $nonce,
            $ciphertext,
        ]);
    }
}
