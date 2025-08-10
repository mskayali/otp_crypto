
# otp_crypto (Dart)

A symmetric crypto layer that uses **AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)** with a **time-windowed IV (OTP-like)** and derives keys via **HKDF-SHA256**.  
This library **does not create HTTP requests**; it operates only on **header/body** payloads. Dart (client) and PHP (server) implement the same protocol.

> **Summary**  
> - The IV is **not transmitted**. Both sides derive it as  
>   `iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]`  
> - **Encrypt-then-MAC**: encrypt with `AES-256-CBC`, then MAC with `HMAC-SHA256`.  
> - Keys are derived by HKDF-SHA256: `enc_key` (32B) + `mac_key` (32B).  
> - Time window: `window = floor(epochSeconds / 30)` (default 30s).  
> - Wire format:  
>   - Headers: `{ "v":1, "w":<int>, "n":"<b64_nonce>", "c":"<b64_ciphertext>" }`  
>   - Body: `"<b64_tag>"`

---

## Table of Contents

- [otp\_crypto (Dart)](#otp_crypto-dart)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Architecture \& Layout](#architecture--layout)
  - [Protocol Details](#protocol-details)
  - [Usage (Dart)](#usage-dart)
    - [Configuration (Singleton)](#configuration-singleton)
    - [Encryption (Encryptor)](#encryption-encryptor)
    - [Verify \& Decrypt (Decryptor)](#verify--decrypt-decryptor)
    - [Wire Adapters (ApiClient)](#wire-adapters-apiclient)
    - [Dio Integration Example](#dio-integration-example)
  - [Error Handling](#error-handling)
  - [Security Notes](#security-notes)
  - [Testing / Validation](#testing--validation)
- [otp-crypto (PHP)](#otp-crypto-php)
  - [Requirements](#requirements)
  - [Install](#install)
  - [Protocol (Wire Format)](#protocol-wire-format)
  - [Project Layout](#project-layout)
  - [Usage](#usage)
    - [1) Bootstrap configuration (once)](#1-bootstrap-configuration-once)
    - [2) Parse \& decrypt an incoming request](#2-parse--decrypt-an-incoming-request)
    - [3) Encrypt a response](#3-encrypt-a-response)
  - [Error Handling](#error-handling-1)
  - [Security Notes](#security-notes-1)
  - [Testing](#testing)
  - [Demo Server (built-in)](#demo-server-built-in)

---

## Installation

`pubspec.yaml` is included. Example dependencies:

```yaml
dependencies:
  crypto: ^3.0.3
  encrypt: ^5.0.1
  meta: ^1.11.0

dev_dependencies:
  test: ^1.25.0
  dio: ^5.4.0
  lints: ^3.0.0
````

> Note: The library itself **does not** perform HTTP. The example app (if you choose to send requests) uses `dio`.

---

## Architecture & Layout

```
lib/
├─ otp_crypto/
│  ├─ otp_crypto_config.dart   # Singleton config (v, masterKey, salt/info, windows)
│  ├─ utils.dart               # b64, u64be, constant-time compare, helpers
│  ├─ errors.dart              # safe error messages & exception types
│  ├─ sha256_hmac.dart         # HMAC-SHA256 (pure Dart; SHA-256 digest via crypto)
│  ├─ hkdf.dart                # HKDF-SHA256 (extract+expand)
│  ├─ time_provider.dart       # SystemTimeProvider / AdjustableTimeProvider
│  ├─ rand_nonce.dart          # 8-byte nonce generator (CSPRNG)
│  ├─ iv_deriver.dart          # IV = HMAC(macKey,"iv"||u64be(w)||nonce)[:16]
│  ├─ otp_cipher.dart          # AES-256-CBC + PKCS#7 (uses `encrypt`)
│  ├─ tag_deriver.dart         # tag = HMAC(macKey,"tag"||u64be(w)||n||c)
│  ├─ encryptor.dart           # high-level encryption (produces SecureMessage)
│  └─ decryptor.dart           # verify + decrypt
├─ http/
│  └─ api_client.dart          # header/body adapters (no HTTP)
└─ models/
   └─ secure_message.dart      # wire model (headers/body)
```

---

## Protocol Details

* **Version (`v`)**: `1`
* **Time window (`w`)**: `floor(epochSeconds / 30)` (default `30`)
* **Nonce (`n`)**: 8 bytes, CSPRNG
* **HKDF-SHA256**:

  * PRK = HMAC(salt, masterKey)
  * OKM (64B) = expand(PRK, info, 64) → `encKey` (first 32B) + `macKey` (next 32B)
* **IV derivation**: `HMAC_SHA256(macKey, "iv" || u64be(w) || nonce)[:16]`
* **Encryption**: AES-256-CBC + PKCS#7 (`encKey`, `iv`)
* **MAC (EtM)**: `HMAC_SHA256(macKey, "tag" || u64be(w) || nonce || ciphertext)`
* **Wire format**:

  * Headers:

    ```json
    {
      "v": 1,
      "w": <int>,
      "n": "<b64_nonce>",
      "c": "<b64_ciphertext>"
    }
    ```
  * Body: `"<b64_tag>"`

> **Do not send IV.** Each side computes it with the same algorithm.

---

## Usage (Dart)

### Configuration (Singleton)

```dart
import 'dart:typed_data';
import 'package:otp_crypto/otp_crypto/otp_crypto_config.dart';
import 'package:otp_crypto/otp_crypto/time_provider.dart';

void main() {
  // At least 32 bytes (example only; store securely in production):
  final masterKey = Uint8List.fromList(List<int>.generate(32, (i) => i));

  OtpCryptoConfig.initialize(
    masterKey: masterKey,
    salt: null,                 // optional; recommended: protocol constant
    info: null,                 // optional; recommended: "otp-v1"
    protocolVersion: 1,
    windowSeconds: 30,
    verificationSkewWindows: 0, // acceptable ±N windows
    timeProvider: SystemTimeProvider(),
  );
}
```

### Encryption (Encryptor)

```dart
import 'dart:typed_data';
import 'package:otp_crypto/otp_crypto/encryptor.dart';
import 'package:otp_crypto/models/secure_message.dart';

final enc = Encryptor();
final plaintext = Uint8List.fromList('Hello secure world'.codeUnits);
final SecureMessage msg = enc.protect(plaintext);
// `msg` is ready to be serialized into headers/body
```

### Verify & Decrypt (Decryptor)

```dart
import 'dart:typed_data';
import 'package:otp_crypto/otp_crypto/decryptor.dart';
import 'package:otp_crypto/models/secure_message.dart';

final dec = Decryptor();
final Uint8List plain = dec.unprotect(msg);
```

### Wire Adapters (ApiClient)

```dart
import 'package:otp_crypto/http/api_client.dart';

// Sender side:
final wire = ApiClient.toWire(msg, extraHeaders: {'X-App-Id': 'myapp'});
// wire.headers -> {"v","w","n","c",...}, wire.body -> "<b64_tag>"

// Receiver side:
final parsed = ApiClient.parseWire(headers: wire.headers, body: wire.body);
// parsed -> SecureMessage; then call Decryptor.unprotect(parsed)
```

### Dio Integration Example

> The library does not perform HTTP; the following is **application-level**.

```dart
import 'package:dio/dio.dart';
import 'package:otp_crypto/http/api_client.dart';
import 'package:otp_crypto/otp_crypto/encryptor.dart';
import 'package:otp_crypto/otp_crypto/decryptor.dart';

final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
final enc = Encryptor();
final dec = Decryptor();

// 1) Build encrypted request
final msg = enc.protect(Uint8List.fromList('{"q":"ping"}'.codeUnits));
final wire = ApiClient.toWire(msg, extraHeaders: {'X-App-Id': 'demo'});

// 2) Send (headers/body)
final resp = await dio.post(
  '/secure-endpoint',
  options: Options(headers: wire.headers),
  data: wire.body, // String (Base64 tag)
);

// 3) Parse and decrypt the response
final replyMsg = ApiClient.parseWire(
  headers: Map<String, String>.from(resp.headers.map.map(
    (k, v) => MapEntry(k, v.join(',')),
  )),
  body: resp.data is String ? resp.data as String : resp.data.toString(),
);

final plain = dec.unprotect(replyMsg);
print(String.fromCharCodes(plain));
```

---

## Error Handling

Generic, non-leaking messages:

* `Invalid message`
* `Authentication failed`
* `Decryption failed`
* `Expired or not yet valid`
* `Internal error`

See exception classes under `lib/otp_crypto/errors.dart`.

---

## Security Notes

* **EtM**: never decrypt before MAC verification.
* **No IV transmission**: IV is derived from `macKey`; protect `macKey` carefully.
* **Replay**: within the 30s window, track seen nonces (e.g., LRU/cache) at higher layers.
* **Clock sync**: adjust `verificationSkewWindows` if you must accept ± windows (e.g., `1` → `[w-1, w, w+1]`).
* **Key management**: `masterKey` ≥ 32B; secure distribution/storage is mandatory.
* **Error hygiene**: do not leak cryptographic internals.
* **Constant-time compare**: use `constantTimeEquals` for tag checks.

---

## Testing / Validation

* **Interop**: messages produced in Dart should decrypt in PHP, and vice versa.
* **Wrong key**: MAC/decryption must fail.
* **Wrong window**: reject when outside tolerance.
* **Nonce length**: reject if not exactly 8 bytes.
* **Malformed Base64**: reject.
* **Large payloads**: test padding and performance.

> For full end-to-end samples, see the `example/` folder (to be added in this repo).

---



# otp-crypto (PHP)

A PHP implementation of a **time-windowed IV (OTP-like)** symmetric encryption layer using **AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)** with keys derived by **HKDF-SHA256**.  
This library **does not create HTTP requests/responses**; it only operates on **header/body** content so you can plug it into any framework.

It interoperates with the Dart client library using the exact same protocol.

---

## Requirements

- PHP **8.1+**
- Extensions: `ext-openssl`, `ext-hash`
- Composer (for autoloading and dev tools)

---

## Install

```bash
composer install
````

If you plan to depend on this from another project (monorepo), add a path repository or publish it to your VCS/Packagist accordingly.

---

## Protocol (Wire Format)

Headers:

```json
{
  "v": 1,                     // protocol version
  "w": <int>,                 // time window = floor(epochSeconds / 30)
  "n": "<b64_nonce>",         // 8 random bytes (Base64)
  "c": "<b64_ciphertext>"     // AES-256-CBC ciphertext (Base64)
}
```

Body:

```
"<b64_tag>"                   // HMAC-SHA256(tag input) in Base64
```

Key details:

* HKDF-SHA256 derives two 32B keys: `encKey` (AES) and `macKey` (HMAC).

* IV is **not transmitted**; both sides derive it:

  ```
  iv = HMAC_SHA256(macKey, "iv" || u64be(window) || nonce)[:16]
  ```

* Tag (Encrypt-then-MAC):

  ```
  tag = HMAC_SHA256(macKey, "tag" || u64be(window) || nonce || ciphertext)
  ```

Default window size is **30 seconds** (configurable).

---

## Project Layout

```
src/
├─ Crypto/
│  ├─ OtpCryptoConfig.php   # Singleton config (v, masterKey, salt/info, windows)
│  ├─ Utils.php             # Base64, u64be, constant-time compare
│  ├─ HmacSha256.php        # HMAC-SHA256 helpers (binary)
│  ├─ Hkdf.php              # HKDF-SHA256 (extract+expand), DerivedKeys VO
│  ├─ IvDeriver.php         # iv = HMAC(macKey, "iv"||u64be(w)||nonce)[:16]
│  ├─ TagDeriver.php        # tag = HMAC(macKey, "tag"||u64be(w)||nonce||c)
│  ├─ OtpCipher.php         # AES-256-CBC + PKCS#7 (OpenSSL)
│  ├─ RandNonce.php         # 8-byte CSPRNG nonce
│  └─ Errors.php            # Exceptions & safe messages
├─ Http/
│  ├─ Encryptor.php         # Build SecureMessage (no HTTP)
│  └─ Decryptor.php         # Verify & decrypt SecureMessage (no HTTP)
├─ Models/
│  └─ SecureMessage.php     # Wire model (headers/body parsing/serialization)
└─ public/
   └─ index.php             # Demo endpoint
```

---

## Usage

### 1) Bootstrap configuration (once)

```php
use OtpCrypto\Crypto\OtpCryptoConfig;

$masterKey = base64_decode(getenv('OTP_MASTER_KEY_B64') ?: '', true);
if ($masterKey === false || strlen($masterKey) < 32) {
    // DEV ONLY fallback; use a secure secret in production!
    $masterKey = random_bytes(32);
}

OtpCryptoConfig::init([
    'masterKey' => $masterKey, // binary string (≥32B)
    'salt' => null,            // optional binary; recommend protocol constant
    'info' => "otp-v1",        // optional binary; binds keys to this protocol
    'protocolVersion' => 1,
    'windowSeconds' => 30,
    'verificationSkewWindows' => 0, // set 1 to accept [w-1, w, w+1]
]);
```

### 2) Parse & decrypt an incoming request

```php
use OtpCrypto\Models\SecureMessage;
use OtpCrypto\Http\Decryptor;

$wireHeaders = [
  'v' => $_SERVER['HTTP_V'] ?? null,
  'w' => $_SERVER['HTTP_W'] ?? null,
  'n' => $_SERVER['HTTP_N'] ?? null,
  'c' => $_SERVER['HTTP_C'] ?? null,
];
$wireBody = file_get_contents('php://input') ?: '';

$msg = SecureMessage::fromWire($wireHeaders, $wireBody);
$dec = new Decryptor();
$plaintext = $dec->unprotect($msg);
// $plaintext is a binary string (e.g., JSON)
```

### 3) Encrypt a response

```php
use OtpCrypto\Http\Encryptor;

$enc = new Encryptor();
$respMsg = $enc->protect(json_encode(['ok' => true]) ?: '{}');

$respHeaders = $respMsg->toWireHeaders();
$respBody    = $respMsg->toWireBody();

// write headers v/w/n/c and body (Base64 tag) via your framework
```

> See `src/public/index.php` for a complete demo that echoes back the request.

---

## Error Handling

All errors return **generic, non-leaking** messages (mirrors the Dart side):

* `Invalid message`
* `Authentication failed`
* `Decryption failed`
* `Expired or not yet valid`
* `Internal error`

Use the exception classes in `src/Crypto/Errors.php` for precise handling while keeping responses generic.

---

## Security Notes

* **Encrypt-then-MAC**: always verify the tag before decryption.
* **No IV on the wire**: IV is derived from `macKey`; protect `macKey` carefully.
* **Replay**: consider tracking seen nonces per time-window at the application layer.
* **Clock sync**: use NTP; set `verificationSkewWindows` if you must accept adjacent windows.
* **Key management**: `masterKey` must be ≥32B; store/distribute securely.
* **Constant-time compare**: use `Utils::constantTimeEquals` for tags.
* **Error hygiene**: never leak crypto internals in outward messages/logs.

---

## Testing

Run PHPUnit tests (to be added):

```bash
composer test
```

Suggested scenarios:

* Interop with Dart vectors (same master key & clock).
* Wrong key → authentication/decryption fails.
* Wrong window → rejected when outside tolerance.
* Malformed Base64 / bad lengths → `Invalid message`.
* Large payloads → correct padding and performance.

---

## Demo Server (built-in)

For a quick demo:

```bash
php -S 127.0.0.1:8080 -t src/public
```

Send a request from your Dart client using the wire headers/body as specified. The demo will parse, decrypt, and respond with an encrypted reply in the same wire format.

---

