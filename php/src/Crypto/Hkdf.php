<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * HKDF-SHA256 (extract + expand)
 * ------------------------------
 * Implements HKDF (RFC 5869) over SHA-256 using our HMAC helper.
 * Used to derive two 32-byte keys from a shared master key:
 *   - encKey (AES-256 key)
 *   - macKey (HMAC-SHA256 key)
 *
 * SCHEME:
 *  PRK = HMAC(salt, IKM)                      // extract
 *  OKM = T(1) || T(2) || ... up to L bytes   // expand
 *    where T(i) = HMAC(PRK, T(i-1) || info || i)
 *
 * NOTES:
 * - HashLen = 32 (SHA-256)
 * - Max output length L ≤ 255 * HashLen
 * - If `salt` is null/empty, a zero-array of HashLen is used (per RFC 5869).
 *
 * SECURITY:
 * - Keep inputs in raw binary (PHP strings) — avoid hex/base64 conversions here.
 * - Compare secrets using constant-time methods only at higher layers.
 */
final class Hkdf
{
    /** SHA-256 digest length in bytes. */
    private const HASH_LEN = 32;

    private function __construct() {}

    /**
     * Extract step: PRK = HMAC(salt, ikm)
     *
     * @param string      $ikm  Input keying material (binary).
     * @param string|null $salt Optional salt (binary). If null/empty, uses zeros.
     * @return string            32-byte PRK (binary).
     *
     * @throws \InvalidArgumentException on invalid inputs.
     */
    public static function extract(string $ikm, ?string $salt = null): string
    {
        $usedSalt = ($salt === null || $salt === '')
            ? str_repeat("\0", self::HASH_LEN)
            : $salt;

        $prk = HmacSha256::compute($usedSalt, $ikm);
        if (strlen($prk) !== self::HASH_LEN) {
            throw new \RuntimeException('HKDF extract produced unexpected length.');
        }
        return $prk;
    }

    /**
     * Expand step to produce $length bytes from a given PRK.
     *
     * @param string      $prk    32-byte PRK from extract().
     * @param string|null $info   Optional context/application info (binary).
     * @param int         $length Desired output length (1..255*HASH_LEN).
     * @return string              OKM of requested length (binary).
     *
     * @throws \InvalidArgumentException if params are out of range.
     */
    public static function expand(string $prk, ?string $info, int $length): string
    {
        if (strlen($prk) !== self::HASH_LEN) {
            throw new \InvalidArgumentException('PRK must be 32 bytes.');
        }
        if ($length <= 0 || $length > 255 * self::HASH_LEN) {
            throw new \InvalidArgumentException('length must be in 1..' . (255 * self::HASH_LEN));
        }

        $infoBytes = $info ?? '';
        $nBlocks   = (int)ceil($length / self::HASH_LEN);

        $okm = '';
        $t   = '';
        for ($i = 1; $i <= $nBlocks; $i++) {
            // T(i) = HMAC(PRK, T(i-1) || info || counter)
            $t = HmacSha256::compute($prk, $t . $infoBytes . chr($i));
            $okm .= $t;
        }

        // Truncate to the requested length.
        return substr($okm, 0, $length);
    }

    /**
     * One-shot HKDF: derive encKey and macKey (32B each) from a master key.
     *
     * @param string      $masterKey IKM; MUST be ≥ 32 bytes (enforced at config layer).
     * @param string|null $salt      Optional salt (binary).
     * @param string|null $info      Optional info/context (binary).
     * @return DerivedKeys           Pair of 32B keys {encKey, macKey}.
     */
    public static function deriveKeys(string $masterKey, ?string $salt = null, ?string $info = null): DerivedKeys
    {
        $prk = self::extract($masterKey, $salt);
        $okm = self::expand($prk, $info, 64);

        $encKey = substr($okm, 0, 32);
        $macKey = substr($okm, 32, 32);

        // Basic sanity check.
        if (strlen($encKey) !== 32 || strlen($macKey) !== 32) {
            throw new \RuntimeException('HKDF deriveKeys produced invalid key lengths.');
        }

        // Best-effort cleanup of intermediates (PHP GC; not guaranteed).
        unset($prk, $okm);

        return new DerivedKeys($encKey, $macKey);
    }
}

/**
 * Value object holding two 32-byte keys: encryption and MAC.
 *
 * HINT:
 * - Keep as binary strings; do not hex/base64 here.
 */
final class DerivedKeys
{
    public function __construct(
        private readonly string $encKey, // 32 bytes
        private readonly string $macKey  // 32 bytes
    ) {
        if (strlen($encKey) !== 32) {
            throw new \InvalidArgumentException('encKey must be 32 bytes.');
        }
        if (strlen($macKey) !== 32) {
            throw new \InvalidArgumentException('macKey must be 32 bytes.');
        }
    }

    /** 32-byte AES-256 key (binary). */
    public function encKey(): string
    {
        return $this->encKey;
    }

    /** 32-byte HMAC-SHA256 key (binary). */
    public function macKey(): string
    {
        return $this->macKey;
    }
}
