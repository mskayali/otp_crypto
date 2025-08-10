<?php

declare(strict_types=1);

namespace OtpCrypto\Http;

use OtpCrypto\Crypto\OtpCryptoConfig;
use OtpCrypto\Crypto\RandNonce;
use OtpCrypto\Crypto\Hkdf;
use OtpCrypto\Crypto\DerivedKeys;
use OtpCrypto\Crypto\IvDeriver;
use OtpCrypto\Crypto\OtpCipher;
use OtpCrypto\Crypto\TagDeriver;
use OtpCrypto\Crypto\InternalCryptoException;
use OtpCrypto\Crypto\InvalidMessageException;
use OtpCrypto\Models\SecureMessage;

/**
 * Encryptor – Builds SecureMessage (headers+body) from plaintext (PHP side)
 * -------------------------------------------------------------------------
 * High-level orchestration (no HTTP):
 *   1) Derive {encKey, macKey} via HKDF-SHA256 from the global config.
 *   2) Compute current time window `w`.
 *   3) Generate 8-byte random nonce `n`.
 *   4) Derive IV = HMAC(macKey, "iv" || u64be(w) || n)[:16].
 *   5) Encrypt plaintext with AES-256-CBC + PKCS#7 using encKey+IV → `c`.
 *   6) Compute tag = HMAC(macKey, "tag" || u64be(w) || n || c).
 *   7) Produce SecureMessage { v,w,n,c,tag }.
 *
 * SECURITY:
 * - This class **does not** perform any network I/O.
 * - The IV is never transmitted; both sides recompute it.
 * - Always verify MAC on the receiving side before decryption (EtM).
 */
final class Encryptor
{
    /** Effective configuration (singleton by default). */
    private OtpCryptoConfig $cfg;

    /** Cached HKDF-derived keys (enc + mac). */
    private DerivedKeys $keys;

    /**
     * Creates an Encryptor bound to a given configuration.
     *
     * @param OtpCryptoConfig|null $config If null, uses OtpCryptoConfig::instance().
     *
     * HINT: Instantiate once and reuse; keys are derived in the constructor.
     */
    public function __construct(?OtpCryptoConfig $config = null)
    {
        $this->cfg = $config ?? OtpCryptoConfig::instance();

        // Derive and cache keys (32B each) once per Encryptor instance.
        $this->keys = Hkdf::deriveKeys(
            $this->cfg->masterKey(),
            $this->cfg->hkdfSalt(),
            $this->cfg->hkdfInfo()
        );
    }

    /**
     * Protects plaintext and returns a SecureMessage ready for wire encoding.
     *
     * @param string $plaintext Binary plaintext (non-empty).
     * @return SecureMessage    Message with {v,w,n,c,tag}.
     *
     * @throws InvalidMessageException on malformed inputs (generic).
     * @throws InternalCryptoException on unexpected crypto failures (generic).
     *
     * HINT: Serialize with `$msg->toWireHeaders()` and `$msg->toWireBody()`.
     */
    public function protect(string $plaintext): SecureMessage
    {
        if ($plaintext === '') {
            throw new InvalidMessageException(new \InvalidArgumentException('plaintext must not be empty'));
        }

        try {
            // 1) Current window
            $w = $this->cfg->currentWindow();

            // 2) Fresh 8-byte nonce
            $nonce = RandNonce::generate();

            // 3) Derive IV from macKey + ("iv"||u64be(w)||nonce)
            $iv = IvDeriver::derive(
                $this->keys->macKey(),
                $w,
                $nonce
            );

            // 4) Encrypt plaintext → ciphertext
            $ciphertext = OtpCipher::encrypt(
                $this->keys->encKey(),
                $iv,
                $plaintext
            );

            // 5) Compute tag over ciphertext (Encrypt-then-MAC)
            $tag = TagDeriver::derive(
                $this->keys->macKey(),
                $w,
                $nonce,
                $ciphertext
            );

            // 6) Build immutable message
            return SecureMessage::fromParts(
                $this->cfg->protocolVersion(),
                $w,
                $nonce,
                $ciphertext,
                $tag
            );
        } catch (\Throwable $e) {
            // Hide low-level details; surface a safe, generic error.
            throw new InternalCryptoException($e);
        }
    }
}
