<?php

declare(strict_types=1);

namespace OtpCrypto\Models;

use OtpCrypto\Crypto\RandNonce;
use OtpCrypto\Crypto\Utils;
use OtpCrypto\Crypto\InvalidMessageException;

/**
 * SecureMessage – Wire model (headers/body)
 * -----------------------------------------
 * Represents the protocol wire format that travels alongside HTTP:
 *
 *   Headers:
 *     "v": 1                     // protocol version
 *     "w": <int>                 // time window (floor(epoch/30))
 *     "n": "<b64_nonce>"         // 8-byte random nonce (Base64)
 *     "c": "<b64_ciphertext>"    // AES-256-CBC ciphertext (Base64)
 *
 *   Body:
 *     "<b64_tag>"                // 32-byte HMAC-SHA256 tag (Base64)
 *
 * This class:
 *  - Parses/validates wire fields (format only; no crypto verification).
 *  - Holds binary values (nonce/ciphertext/tag) after Base64 decoding.
 *  - Serializes back to wire form (Base64) for transport.
 *
 * SECURITY:
 *  - Does NOT verify MAC or decrypt; higher layers must do that.
 *  - Keeps messages generic on errors via InvalidMessageException.
 */
final class SecureMessage
{
    /** Protocol version (`v`). */
    private int $v;

    /** Time window (`w`). */
    private int $w;

    /** 8-byte nonce (binary). */
    private string $nonce;

    /** Ciphertext (binary). */
    private string $ciphertext;

    /** 32-byte HMAC-SHA256 tag (binary). */
    private string $tag;

    private function __construct(
        int $v,
        int $w,
        string $nonce,
        string $ciphertext,
        string $tag
    ) {
        $this->v = $v;
        $this->w = $w;
        $this->nonce = $nonce;
        $this->ciphertext = $ciphertext;
        $this->tag = $tag;
    }

    /**
     * Builds a SecureMessage from raw (already-decoded) parts.
     *
     * @param int    $v           Protocol version (>=1).
     * @param int    $w           Time window (>=0).
     * @param string $nonce       8-byte binary nonce.
     * @param string $ciphertext  Binary ciphertext.
     * @param string $tag         32-byte binary HMAC tag.
     * @return self
     *
     * @throws InvalidMessageException on any format error.
     *
     * HINT: Use this when the caller already decoded Base64 fields.
     */
    public static function fromParts(
        int $v,
        int $w,
        string $nonce,
        string $ciphertext,
        string $tag
    ): self {
        try {
            if ($v < 1) {
                throw new \InvalidArgumentException('protocol version must be >= 1');
            }
            if ($w < 0) {
                throw new \InvalidArgumentException('window must be non-negative');
            }
            RandNonce::validate($nonce);
            if ($ciphertext === '') {
                throw new \InvalidArgumentException('ciphertext must not be empty');
            }
            if (\strlen($tag) !== 32) {
                throw new \InvalidArgumentException('tag must be 32 bytes');
            }
            return new self($v, $w, $nonce, $ciphertext, $tag);
        } catch (\Throwable $e) {
            throw new InvalidMessageException($e);
        }
    }

    /**
     * Parses a SecureMessage from **wire** headers/body (Base64 strings).
     *
     * @param array  $headers Must contain keys: "v","w","n","c" (strings).
     * @param string $body    Base64 HMAC tag string.
     * @return self
     *
     * @throws InvalidMessageException if any required field is missing/invalid.
     *
     * HINT: This is a *format* parser only (no MAC/decrypt).
     */
    public static function fromWire(array $headers, string $body): self
    {
        try {
            // Required headers
            $vStr = $headers['v'] ?? null;
            $wStr = $headers['w'] ?? null;
            $nStr = $headers['n'] ?? null;
            $cStr = $headers['c'] ?? null;

            if ($vStr === null || $wStr === null || $nStr === null || $cStr === null) {
                throw new \InvalidArgumentException('missing required headers v/w/n/c');
            }

            // Parse ints
            if (!is_string($vStr) || !is_string($wStr)) {
                throw new \InvalidArgumentException('v and w must be strings');
            }
            $v = (int)$vStr;
            $w = (int)$wStr;
            if ((string)$v !== $vStr || $v < 1) {
                throw new \InvalidArgumentException('invalid v');
            }
            if ((string)$w !== $wStr || $w < 0) {
                throw new \InvalidArgumentException('invalid w');
            }

            if (!is_string($nStr) || !is_string($cStr) || !is_string($body)) {
                throw new \InvalidArgumentException('wire fields must be strings');
            }

            // Decode Base64 fields
            $nonce      = Utils::fromBase64Strict($nStr);
            $ciphertext = Utils::fromBase64Strict($cStr);
            $tag        = Utils::fromBase64Strict($body);

            // Enforce lengths
            RandNonce::validate($nonce);
            if ($ciphertext === '') {
                throw new \InvalidArgumentException('ciphertext must not be empty');
            }
            if (\strlen($tag) !== 32) {
                throw new \InvalidArgumentException('tag must be 32 bytes');
            }

            return new self($v, $w, $nonce, $ciphertext, $tag);
        } catch (\Throwable $e) {
            throw new InvalidMessageException($e);
        }
    }

    /**
     * Serializes this message to **wire headers** (Base64).
     *
     * @return array `["v"=>"1","w"=>"...","n"=>"<b64>","c"=>"<b64>"]`
     *
     * HINT: Attach this map to your HTTP request/response headers.
     */
    public function toWireHeaders(): array
    {
        return [
            'v' => (string)$this->v,
            'w' => (string)$this->w,
            'n' => Utils::toBase64($this->nonce),
            'c' => Utils::toBase64($this->ciphertext),
        ];
    }

    /**
     * Serializes the tag to **wire body** (Base64).
     *
     * @return string Base64 tag string.
     *
     * HINT: Put this as the HTTP body (string).
     */
    public function toWireBody(): string
    {
        return Utils::toBase64($this->tag);
    }

    /**
     * Clone with optional substitutions (re-validates variable-length fields).
     *
     * @param int|null    $v
     * @param int|null    $w
     * @param string|null $nonce
     * @param string|null $ciphertext
     * @param string|null $tag
     * @return self
     *
     * HINT: Useful in tests/tools; not typically needed in handlers.
     */
    public function copyWith(
        ?int $v = null,
        ?int $w = null,
        ?string $nonce = null,
        ?string $ciphertext = null,
        ?string $tag = null
    ): self {
        $nv = $v ?? $this->v;
        $nw = $w ?? $this->w;
        $nn = $nonce ?? $this->nonce;
        $nc = $ciphertext ?? $this->ciphertext;
        $nt = $tag ?? $this->tag;

        // Reuse fromParts for validation
        return self::fromParts($nv, $nw, $nn, $nc, $nt);
    }

    // --- Getters -------------------------------------------------------------

    /** Protocol version (`v`). */
    public function v(): int
    {
        return $this->v;
    }

    /** Time window (`w`). */
    public function w(): int
    {
        return $this->w;
    }

    /** 8-byte nonce (binary). */
    public function nonce(): string
    {
        return $this->nonce;
    }

    /** Ciphertext (binary). */
    public function ciphertext(): string
    {
        return $this->ciphertext;
    }

    /** 32-byte HMAC tag (binary). */
    public function tag(): string
    {
        return $this->tag;
    }
}
