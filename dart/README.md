
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
