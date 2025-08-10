<?php

declare(strict_types=1);

namespace OtpCrypto\Crypto;

/**
 * OtpCipher – AES-256-CBC with PKCS#7 padding (OpenSSL)
 * -----------------------------------------------------
 * Thin wrapper around PHP OpenSSL to encrypt/decrypt using:
 *   - Algorithm : AES-256-CBC
 *   - Padding   : PKCS#7 (OpenSSL default, i.e., NOT using ZERO_PADDING)
 *   - Inputs    : 32-byte key (encKey) and 16-byte IV
 *
 * This class does **not** derive keys or IVs; higher layers (HKDF + IvDeriver)
 * supply them. It also does **not** compute/verify MACs; always perform
 * Encrypt-then-MAC at a higher layer (TagDeriver + constant-time compare).
 *
 * SECURITY NOTES:
 * - Enforce key length (32) and IV length (16) before calling OpenSSL.
 * - On any failure, return generic error messages to avoid leaking internals.
 * - Decrypt **only after** MAC verification has succeeded.
 */
final class OtpCipher
{
    private const CIPHER = 'aes-256-cbc';

    private function __construct() {}

    /**
     * Encrypts $plaintext with AES-256-CBC + PKCS#7.
     *
     * @param string $encKey   32-byte key (binary).
     * @param string $iv       16-byte IV (binary).
     * @param string $plaintext Binary plaintext.
     * @return string          Binary ciphertext.
     *
     * @throws \InvalidArgumentException for invalid inputs.
     * @throws \RuntimeException on encryption failure (generic message).
     */
    public static function encrypt(string $encKey, string $iv, string $plaintext): string
    {
        self::requireKeyIv($encKey, $iv);

        // OPENSSL_RAW_DATA -> return raw binary, keep PKCS#7 padding enabled.
        $ciphertext = \openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($ciphertext === false) {
            // Do not leak OpenSSL details.
            throw new \RuntimeException('Internal error');
        }
        if ($ciphertext === '') {
            // Extremely unlikely, but reject empty output.
            throw new \RuntimeException('Internal error');
        }
        return $ciphertext;
    }

    /**
     * Decrypts $ciphertext with AES-256-CBC + PKCS#7.
     *
     * @param string $encKey     32-byte key (binary).
     * @param string $iv         16-byte IV (binary).
     * @param string $ciphertext Binary ciphertext.
     * @return string            Binary plaintext.
     *
     * @throws \InvalidArgumentException for invalid inputs.
     * @throws \RuntimeException on decryption failure (generic message).
     *
     * IMPORTANT:
     * - Callers must verify HMAC *before* calling this method.
     */
    public static function decrypt(string $encKey, string $iv, string $ciphertext): string
    {
        self::requireKeyIv($encKey, $iv);

        $plaintext = \openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($plaintext === false) {
            // Includes bad padding, wrong key/iv, corrupted input, etc.
            throw new \RuntimeException('Decryption failed');
        }
        return $plaintext;
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /**
     * Validates key and IV lengths for AES-256-CBC.
     *
     * @param string $encKey
     * @param string $iv
     *
     * @throws \InvalidArgumentException if lengths are incorrect.
     */
    private static function requireKeyIv(string $encKey, string $iv): void
    {
        if (\strlen($encKey) !== 32) {
            throw new \InvalidArgumentException('encKey must be 32 bytes.');
        }
        if (\strlen($iv) !== 16) {
            throw new \InvalidArgumentException('iv must be 16 bytes.');
        }
    }
}
