<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * Utils – Low-level helpers (Base64, u64be, constant-time compare)
 * ----------------------------------------------------------------
 * Collection of byte helpers shared across the crypto stack:
 *  - Standard Base64 encode/decode with strict parsing & padding normalization.
 *  - u64 big-endian encoding (for the `window` field in derivations).
 *  - Constant-time byte comparison for MAC/tag checks.
 *
 * SECURITY NOTES:
 * - Always use `constantTimeEquals` to compare HMAC tags (prevents timing leaks).
 * - `fromBase64Strict` rejects malformed Base64 after trimming/padding.
 * - PHP strings are byte arrays; treat them as binary here (no encoding).
 *
 * HINTS:
 * - Labels "iv" and "tag" are provided as constants to avoid re-allocations.
 * - `u64be()` supports non-negative integers; window values are well within range.
 */
final class Utils
{
    /** ASCII label "iv" used in IV derivation (binary string). */
    public const IV_LABEL  = "iv";

    /** ASCII label "tag" used in MAC derivation (binary string). */
    public const TAG_LABEL = "tag";

    private function __construct() {}

    // ---------------------------------------------------------------------
    // Base64 helpers (standard Base64 with padding)
    // ---------------------------------------------------------------------

    /**
     * Encodes binary data to **standard** Base64 (with padding).
     *
     * @param string $bin Binary input.
     * @return string Base64 string (with '=' padding).
     *
     * HINT: Use for wire fields `n`, `c`, and the body tag.
     */
    public static function toBase64(string $bin): string
    {
        return base64_encode($bin);
    }

    /**
     * Decodes a **standard** Base64 string to binary (strict).
     * - Trims ASCII whitespace.
     * - Auto-pads to a multiple of 4 ('=') if necessary.
     * - Throws \InvalidArgumentException if invalid after normalization.
     *
     * @param string $b64 Base64 input (possibly with whitespace / missing padding).
     * @return string Binary output.
     */
    public static function fromBase64Strict(string $b64): string
    {
        $normalized = self::normalizeB64($b64);
        $decoded = base64_decode($normalized, true); // strict
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid Base64 input.');
        }
        return $decoded;
    }

    /**
     * Normalizes a Base64 string:
     * - Removes ASCII whitespace (\r, \n, space, \t).
     * - Adds missing '=' padding so that length % 4 == 0.
     *
     * @param string $s
     * @return string
     */
    private static function normalizeB64(string $s): string
    {
        // Strip common whitespace characters.
        $trimmed = (string)preg_replace('/\s+/', '', $s);
        $mod = strlen($trimmed) % 4;
        if ($mod === 0) {
            return $trimmed;
        }
        return $trimmed . str_repeat('=', 4 - $mod);
    }

    // ---------------------------------------------------------------------
    // Integer encoding helpers
    // ---------------------------------------------------------------------

    /**
     * Encodes an unsigned 64-bit integer as **big-endian** 8 bytes.
     *
     * @param int $value Non-negative integer (0 .. 2^63-1 on typical PHP builds).
     * @return string 8-byte binary string.
     *
     * SECURITY:
     * - The protocol's `window` value fits safely in 64 bits (and well within 32).
     *
     * NOTE:
     * - This implementation relies on PHP integer shifts. For typical epoch/30
     *   window sizes (~tens of millions), this is portable on 32/64-bit builds.
     */
    public static function u64be(int $value): string
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('u64be expects a non-negative integer.');
        }
        // Highest byte first.
        $out = '';
        for ($i = 7; $i >= 0; $i--) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }
        return $out;
    }

    // ---------------------------------------------------------------------
    // Constant-time compare
    // ---------------------------------------------------------------------

    /**
     * Constant-time comparison of two binary strings.
     * - Time is proportional to the longest input.
     * - Does not short-circuit on the first difference.
     *
     * @param string $a
     * @param string $b
     * @return bool true if equal, false otherwise
     *
     * HINT: Use for HMAC tag checks.
     */
    public static function constantTimeEquals(string $a, string $b): bool
    {
        // Prefer native hash_equals if available (constant-time).
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }
        // Fallback: manual constant-time loop.
        $lenA = strlen($a);
        $lenB = strlen($b);
        $len  = max($lenA, $lenB);

        $diff = $lenA ^ $lenB; // include length difference
        for ($i = 0; $i < $len; $i++) {
            $ai = $i < $lenA ? ord($a[$i]) : 0;
            $bi = $i < $lenB ? ord($b[$i]) : 0;
            $diff |= ($ai ^ $bi);
        }
        return $diff === 0;
    }
}
