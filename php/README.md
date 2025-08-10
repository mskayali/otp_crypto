
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

