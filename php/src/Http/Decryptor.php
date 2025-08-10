<?php

declare(strict_types=1);

namespace OtpCrypto\Http;

use OtpCrypto\Crypto\OtpCryptoConfig;
use OtpCrypto\Crypto\Hkdf;
use OtpCrypto\Crypto\DerivedKeys;
use OtpCrypto\Crypto\TagDeriver;
use OtpCrypto\Crypto\IvDeriver;
use OtpCrypto\Crypto\OtpCipher;
use OtpCrypto\Crypto\Utils;
use OtpCrypto\Crypto\InvalidMessageException;
use OtpCrypto\Crypto\AuthenticationFailedException;
use OtpCrypto\Crypto\WindowOutOfRangeException;
use OtpCrypto\Crypto\DecryptionFailedException;
use OtpCrypto\Models\SecureMessage;

/**
 * Decryptor – Verifies & decrypts a SecureMessage (Encrypt-then-MAC)
 * ------------------------------------------------------------------
 * Processing order (DO NOT change):
 *   1) Validate protocol version and time-window skew.
 *   2) Derive {encKey, macKey} via HKDF-SHA256 from config (cached).
 *   3) Recompute tag = HMAC(macKey, "tag" || u64be(w) || nonce || ciphertext).
 *   4) Constant-time compare with body tag; if mismatch → AuthenticationFailed.
 *   5) Derive IV = HMAC(macKey, "iv" || u64be(w) || nonce)[:16].
 *   6) Decrypt AES-256-CBC + PKCS#7 using encKey+IV → plaintext.
 *
 * NOTES:
 * - This class does **not** do any HTTP. It only consumes a `SecureMessage`
 *   reconstructed from headers/body.
 * - Always verify the MAC **before** decryption (Encrypt-then-MAC).
 */
final class Decryptor
{
    /** Effective configuration (singleton by default). */
    private OtpCryptoConfig $cfg;

    /** Cached HKDF-derived keys (enc + mac). */
    private DerivedKeys $keys;

    /**
     * Creates a Decryptor bound to a given configuration.
     *
     * @param OtpCryptoConfig|null $config If null, uses OtpCryptoConfig::instance().
     *
     * HINT: Instantiate once and reuse; keys are derived in the constructor.
     */
    public function __construct(?OtpCryptoConfig $config = null)
    {
        $this->cfg = $config ?? OtpCryptoConfig::instance();
        $this->keys = Hkdf::deriveKeys(
            $this->cfg->masterKey(),
            $this->cfg->hkdfSalt(),
            $this->cfg->hkdfInfo()
        );
    }

    /**
     * Verifies and decrypts a previously parsed `SecureMessage`.
     *
     * INPUT:
     * - $msg: a format-validated message (see SecureMessage::fromWire).
     *
     * OUTPUT:
     * - plaintext bytes (binary string) if authentication and decryption succeed.
     *
     * @throws InvalidMessageException        on version mismatch.
     * @throws WindowOutOfRangeException      when outside the accepted time window.
     * @throws AuthenticationFailedException  on HMAC mismatch.
     * @throws DecryptionFailedException      if AES decryption/padding fails.
     */
    public function unprotect(SecureMessage $msg): string
    {
        // 1) Protocol version check (exact match for v1).
        if ($msg->v() !== $this->cfg->protocolVersion()) {
            throw new InvalidMessageException(
                new \InvalidArgumentException(
                    sprintf('Unsupported protocol version %d (expected %d)', $msg->v(), $this->cfg->protocolVersion())
                )
            );
        }

        // 2) Window skew check (reject too old/future messages quickly).
        $this->enforceWindowSkew($msg->w());

        // 3) Verify tag (Encrypt-then-MAC).
        $computedTag = TagDeriver::derive(
            $this->keys->macKey(),
            $msg->w(),
            $msg->nonce(),
            $msg->ciphertext()
        );

        if (!Utils::constantTimeEquals($computedTag, $msg->tag())) {
            throw new AuthenticationFailedException();
        }

        // 4) Derive IV and decrypt.
        $iv = IvDeriver::derive(
            $this->keys->macKey(),
            $msg->w(),
            $msg->nonce()
        );

        try {
            return OtpCipher::decrypt(
                $this->keys->encKey(),
                $iv,
                $msg->ciphertext()
            );
        } catch (\RuntimeException $e) {
            // Normalize OpenSSL errors to a generic, non-leaking exception.
            throw new DecryptionFailedException($e);
        }
    }

    // -- helpers --------------------------------------------------------------

    /**
     * Enforces skew tolerance: abs(receivedW - currentW) <= verificationSkewWindows
     *
     * @throws WindowOutOfRangeException if outside tolerance.
     */
    private function enforceWindowSkew(int $receivedW): void
    {
        $currentW = $this->cfg->currentWindow();
        $delta = abs($receivedW - $currentW);
        if ($delta > $this->cfg->verificationSkewWindows()) {
            throw new WindowOutOfRangeException(
                new \RuntimeException(
                    sprintf(
                        'received window %d outside tolerance of current %d (±%d)',
                        $receivedW,
                        $currentW,
                        $this->cfg->verificationSkewWindows()
                    )
                )
            );
        }
    }
}
