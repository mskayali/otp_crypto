<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * HmacSha256 – HMAC(SHA-256) helper
 * ---------------------------------
 * Thin wrapper around PHP's `hash_hmac()`/`hash_init()` to produce
 * 32-byte HMAC-SHA256 tags. Operates on **binary strings**.
 *
 * SECURITY NOTES:
 * - Output length is always 32 bytes (raw binary).
 * - Do not convert secrets to hex/base64 in this layer; keep bytes.
 * - Compare tags using `Utils::constantTimeEquals(...)`.
 *
 * HINTS:
 * - Use `compute($key, $data)` for single buffer inputs.
 * - Use `computeParts($key, $parts)` to avoid concatenating large buffers.
 */
final class HmacSha256
{
    /** Digest algorithm name for PHP hash API. */
    private const ALG = 'sha256';

    private function __construct() {}

    /**
     * Computes HMAC-SHA256(key, data) and returns a 32-byte tag.
     *
     * @param string $key  Secret key (binary string; any length).
     * @param string $data Input data (binary string).
     * @return string 32-byte raw binary tag.
     *
     * HINT: For multiple chunks, prefer `computeParts` to reduce copies.
     */
    public static function compute(string $key, string $data): string
    {
        // raw_output=true → binary (32 bytes)
        $tag = hash_hmac(self::ALG, $data, $key, true);
        // Defensive check (should always be 32 for sha256).
        if (strlen($tag) !== 32) {
            throw new \RuntimeException('HMAC-SHA256 returned unexpected length.');
        }
        return $tag;
    }

    /**
     * Computes HMAC-SHA256 over multiple parts without external concatenation.
     *
     * @param string   $key   Secret key (binary string; any length).
     * @param string[] $parts Array of binary strings appended in order.
     * @return string 32-byte raw binary tag.
     *
     * HINT: Pass each chunk (e.g., label, u64be(window), nonce, ciphertext)
     *       to mirror the protocol without extra allocations.
     */
    public static function computeParts(string $key, array $parts): string
    {
        // Streaming HMAC: hash_init with HMAC option, then update per chunk.
        $ctx = hash_init(self::ALG, HASH_HMAC, $key);
        foreach ($parts as $i => $p) {
            if (!is_string($p)) {
                throw new \InvalidArgumentException("parts[$i] must be a binary string.");
            }
            hash_update($ctx, $p);
        }
        $tag = hash_final($ctx, true); // raw binary
        if (strlen($tag) !== 32) {
            throw new \RuntimeException('HMAC-SHA256 returned unexpected length.');
        }
        return $tag;
    }
}
