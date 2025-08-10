# Changelog

All notable changes to this project will be documented in this file.

The format is based on **Keep a Changelog**, and this project adheres to **Semantic Versioning**.

## [Unreleased]

- Add negative/edge-case tests (skew ±1, malformed Base64, large payloads).
- Example app: real HTTP roundtrip against the PHP demo server.

## [0.1.0] - 2025-08-10

### Added
- **Protocol v1** with 30s time window (`window = floor(epochSeconds / 30)`).
- **AES-256-CBC + PKCS#7** encryption via `encrypt` package.
- **HMAC-SHA256** (Encrypt-then-MAC) implemented in pure Dart (SHA-256 digest via `crypto`).
- **HKDF-SHA256** (extract + expand) to derive `encKey` (32B) and `macKey` (32B).
- **Deterministic IV derivation** (OTP-like): `iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]` (IV is not transmitted).
- **Tag derivation**: `tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)`.
- **Singleton config** (`OtpCryptoConfig`) with window size, version, salts/infos, and skew tolerance.
- **Utilities**: Base64 (strict), `u64be`, constant-time compare, zeroization helpers.
- **Nonce generator**: 8-byte CSPRNG (`Random.secure()`), plus a fixed generator for tests.
- **Encryptor / Decryptor** high-level classes (no HTTP).
- **Wire model** (`SecureMessage`) and **adapters** (`ApiClient`) to map to headers/body (no transport logic).
- **Time providers**: system + adjustable (for tests).
- **Example** app (`example/main.dart`) showing end-to-end flow and a commented Dio integration snippet.

### Security
- Enforce key (32B) and IV (16B) sizes.
- Constant-time tag comparison.
- Strict, non-leaking error messages.

[Unreleased]: https://example.com/compare/0.1.0...HEAD
[0.1.0]: https://example.com/releases/0.1.0
## [0.1.1] - 2025-08-10

### Updated
- **Yaml repository link updated**
- ## [0.1.2] - 2025-08-10

### Updated
- **example/main.dart**