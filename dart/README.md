
# otp_crypto

A small crypto toolkit with:

- **v1**: symmetric encryption utilities (legacy)
- **v2 (PFS)**: a minimal **Perfect Forward Secrecy** session protocol for HTTP payload protection:
  - X25519 (ephemeral ECDH) + HKDF-SHA256
  - AEAD: ChaCha20-Poly1305 (default) or AES-256-GCM
  - Vault Transit–friendly **Ed25519** server signatures
  - **Replay protection** via `sid + seq` and optional sliding window
  - **Endpoint binding** via canonical **AAD** (method/path/query/host)

This repo focuses on *client-side mechanics* in Dart; server-side (PHP) is intended to mirror the same canonicalization and wire formats.

---

## Why this exists

TLS already gives you PFS. This library is for the cases where you still want **message-level security**:
- payload protection at rest (logs, queues, proxies),
- endpoint/method binding (a ciphertext can’t be replayed to a different route),
- explicit replay rules at the application layer.

---

## Security model (v2)

- **Handshake**
  - Client generates ephemeral X25519 keypair.
  - Server responds with ephemeral X25519 public key + server identity metadata.
  - Server signs **SHA-256(transcript)** with **Ed25519** (Vault Transit “sign” output is supported).
- **Key schedule**
  - `shared = X25519(client_priv, server_pub)`
  - `salt = SHA256(transcript_bytes)`
  - `okm = HKDF(shared, salt, info = "<protocolId>/keys", len=44)`
  - `aeadKey = okm[0..31]`, `nonceBase12 = okm[32..43]`
- **Message protection**
  - Per-message nonce is derived from `(nonceBase12 XOR u64be(seq) into last 8 bytes)`.
  - AAD binds: `HTTP context + PfsHeader canonical JSON`.
  - Replay checks: strict monotonic or sliding window.

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  otp_crypto: ^<your-version>
````

---

## Quickstart (v2 client)

### 1) Configure PFS

You must provide a resolver for server identity public keys (and optionally pin keys).

```dart
import 'package:otp_crypto/otp_crypto.dart';

final config = PfsConfig(
  aead: PfsAead.chacha20Poly1305,
  // kid (+ optional keyVersion) -> Ed25519 public key
  resolveServerPublicKey: (kid, {int? keyVersion}) async {
    // Fetch from config, cache, your API, etc.
    // Return SimplePublicKey(bytes, type: KeyPairType.ed25519)
    return null;
  },
  // Optional pinning (kid -> public key)
  pinnedServerKeys: const {},
  maxClockSkew: const Duration(seconds: 60),
  handshakeMaxClockSkew: const Duration(seconds: 60),
  replayWindowSize: 0, // 0 = strict monotonic, >0 = sliding window
);
```

### 2) Create ClientHello

```dart
final hc = HandshakeClient(config);

final state = await hc.createClientHello(
  expectServerIdentity: const ServerIdentityRef(
    kid: 'pfs-server-id',
    keyVersion: 1,
    alg: ServerSigAlg.ed25519,
  ),
);

final clientHelloBytes = state.encodeHello();
// Send to server (HTTP body or whatever transport)
```

### 3) Process ServerHello → Session

```dart
// Receive from server:
final serverHelloBytes = /* bytes from server */;
final serverHello = ServerHello.decode(serverHelloBytes);

// Verify signature + derive keys:
final result = await hc.processServerHello(
  state: state,
  serverHello: serverHello,
);

final session = PfsSession.fromHandshake(
  config: config,
  result: result,
);
```

### 4) Protect / Unprotect HTTP payload

```dart
final http = const HttpContext(
  method: 'POST',
  path: '/api/v1/devices',
  query: {'a': '1'},
  // host: 'example.com', // optional binding
);

// Encrypt
final pt = Uint8List.fromList(utf8.encode('hello'));
final out = await session.protect(plaintext: pt, http: http);

// Put `out.header.toWireHeaders()` into HTTP headers (or carry otherwise)
// Put `out.envelope.encode()` as HTTP body.

// Decrypt (on receiver side with same session keys)
final bodyBytes = out.envelope.encode();
final envelope = PfsEnvelope.decode(bodyBytes);

final header = out.header; // or parse from wire headers: PfsHeader.fromWireHeaders(...)
final decrypted = await session.unprotect(header: header, envelope: envelope, http: http);
```

---

## Canonicalization (interop-critical)

v2 uses **canonical JSON** for:

* `ClientHello.encode()`
* Transcript hash inputs
* `PfsHeader` canonical JSON (AAD)
* HTTP context canonical JSON (AAD)

Do **not** replace this with `jsonEncode()` or you will eventually break Dart↔PHP interop due to ordering/formatting differences.

Canonical encoder lives in:

* `lib/pfs/codec/canonical_json.dart`

Rules (summary):

* map keys are **string-only**, sorted lexicographically
* no whitespace
* doubles are rejected (avoid number formatting drift)

---

## Vault Transit signature compatibility

`ServerHello.sig` can be either:

* raw base64 signature, or
* Vault style: `vault:v1:<base64>` (parser takes substring after last `:`)

Helper:

* `PfsSignature.parseVaultSignature(...)`

---

## Testing

Run:

```bash
dart test
```

Included tests lock down:

* transcript hash determinism
* signature verify flow
* key schedule agreement
* AAD canonicalization

---

## Production notes

* Rotate sessions. Don’t run one session forever.
* Enforce replay checks on the server too.
* Treat all crypto errors uniformly at your API boundary (avoid oracle behavior).
* Use HTTPS anyway; this is message-level defense-in-depth, not a TLS replacement.

---

## License

MIT (or your preferred license).

````

---

## `CHANGELOG.md`

```md
# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

### Added
- v2/PFS module exports from `lib/otp_crypto.dart`.
- Canonical JSON encoder for Dart↔PHP interoperability (`lib/pfs/codec/canonical_json.dart`).
- PFS handshake pipeline: ClientHello, ServerHello, Transcript, KeySchedule, HandshakeClient.
- Session layer with AEAD protect/unprotect, replay checks, and HTTP-bound AAD.
- Vault Transit–compatible signature parsing (`vault:v1:<b64>`).
- Test suite for canonicalization + handshake + message protection:
  - `test/pfs_aad_test.dart`
  - `test/pfs_handshake_test.dart`
  - `test/pfs_message_test.dart`

### Changed
- Transcript/AAD/header canonicalization now uses deterministic canonical JSON (sorted keys) instead of relying on `jsonEncode()` insertion order.
- HandshakeClient now derives keys via `KeySchedule` (single source of truth).
- Session errors shifted toward unified error types (`PfsException`) for oracle-resistance.

### Fixed
- KeyPairData private key extraction compatibility: use `SimpleKeyPairData.bytes` where applicable.
- ServerHello signature field now supports Vault string format parsing during decode.

### Security
- Deterministic canonicalization reduces cross-language signature/transcript mismatch risk.
- Replay protections and endpoint binding are enforced via AAD and seq tracking.

## [0.1.0]
### Added
- Initial v1 symmetric encryption utilities (legacy).
