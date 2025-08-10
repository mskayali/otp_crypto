# Changelog

All notable changes to this PHP library are documented in this file.

The format follows **Keep a Changelog**, and the project aims to follow **Semantic Versioning**.

## [Unreleased]

- Add PHPUnit test suite (roundtrip, skew ±1, malformed Base64, large payloads).
- Provide interop test vectors shared with the Dart package.
- Optional nonce replay cache example (per-window) at application layer.

## [0.1.0] - 2025-08-10

### Added
- **Protocol v1** with 30s time window (`window = floor(epochSeconds / 30)`).
- **AES-256-CBC + PKCS#7** encryption via OpenSSL (`openssl_encrypt` / `openssl_decrypt`).
- **HMAC-SHA256** (Encrypt-then-MAC) via `hash_hmac` / streaming `hash_init` (raw 32B tags).
- **HKDF-SHA256** (extract + expand) to derive `encKey` (32B) and `macKey` (32B).
- **Deterministic IV** derivation (OTP-like):  
  `iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]` (IV is **not** transmitted).
- **Tag derivation**:  
  `tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)`.
- **Singleton config** (`OtpCryptoConfig`) with version, window size, salt/info, skew tolerance.
- **Utilities** (`Utils`): strict Base64, `u64be`, constant-time compare.
- **Nonce generator** (`RandNonce`): 8-byte CSPRNG (`random_bytes`).
- **Encryptor / Decryptor** high-level classes (no HTTP; operate on headers/body only).
- **Wire model** (`SecureMessage`) for parsing/serializing the protocol fields.
- **Demo endpoint** (`src/public/index.php`) that parses request headers/body, decrypts, and returns an encrypted response.
- **Composer setup** with PSR-4 autoload.

### Security
- Enforce key (32B) and IV (16B) sizes.
- Constant-time tag comparison (`hash_equals` or manual fallback).
- Strict, non-leaking error messages (`Errors.php`) consistent with the Dart side.

[Unreleased]: https://example.com/php/compare/0.1.0...HEAD
[0.1.0]: https://example.com/php/releases/0.1.0
