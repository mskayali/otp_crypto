/// JWT-wrapped wire demo (headers in JWT header, tag in payload)
/// -------------------------------------------------------------
/// This shows how you can **package the protocol’s wire pieces inside a JWT**
/// for transport. This is app-level sugar; the crypto library itself **does not**
/// build HTTP or JWTs. We still follow the exact wire schema:
///   - headers: v, w, n, c
///   - body   : <b64_tag>
///
/// In this example we:
///  0) Initialize the global crypto config (singleton).
///  1) Client encrypts a request → SecureMessage {v,w,n,c,tag}.
///  2) Embed protocol headers into the **JWT header**, and the tag into the **JWT payload**.
///  3) “Server” decodes the JWT, reconstructs SecureMessage, verifies+decrypts.
///  4) Server encrypts a response and we decrypt it on the client.
///
/// REQUIREMENTS:
/// - Add `dart_jsonwebtoken` to your dev dependencies (used only by this demo):
///     dev_dependencies:
///       dart_jsonwebtoken: ^2.13.0
///
/// SECURITY NOTES:
/// - JWT here is **only a transport container**. It does NOT replace the protocol
///   MAC (HMAC-SHA256) which authenticates the ciphertext (Encrypt-then-MAC).
/// - If you sign the JWT, verify it on receipt (`JWT.verify`) before using fields.
/// - Keep the protocol header keys **exactly** "v","w","n","c" for interop.

import 'dart:convert' show base64Encode, jsonDecode, jsonEncode, utf8;
import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:otp_crypto/http/api_client.dart';
import 'package:otp_crypto/models/secure_message.dart';
import 'package:otp_crypto/otp_crypto/decryptor.dart';
import 'package:otp_crypto/otp_crypto/encryptor.dart';
import 'package:otp_crypto/otp_crypto/otp_crypto_config.dart';
import 'package:otp_crypto/otp_crypto/time_provider.dart';

void main() async {
  // ---------------------------------------------------------------------------
  // 0) Global configuration (singleton)
  // ---------------------------------------------------------------------------
  // NOTE: In production, use a cryptographically random 32+ byte key,
  // store it securely (e.g., KeyStore/KeyChain/Env+KMS), and share it with the server.
  final masterKey = Uint8List.fromList(List<int>.generate(32, (i) => i));

  OtpCryptoConfig.initialize(
    masterKey: masterKey,
    salt: null, // Optional; recommended to set as a protocol-wide constant
    info: utf8.encode('otp-v1') as Uint8List?, // Optional; binds keys to this protocol
    protocolVersion: 1,
    windowSeconds: 30,
    verificationSkewWindows: 0, // Set to 1 if you want to accept [w-1, w, w+1]
    timeProvider: SystemTimeProvider(),
  );

  // High-level helpers (stateless per-request)
  final enc = Encryptor();
  final dec = Decryptor();

  // ---------------------------------------------------------------------------
  // 1) CLIENT → Build encrypted request (SecureMessage)
  // ---------------------------------------------------------------------------
  // Prepare some JSON payload to protect.
  final reqJson = <String, dynamic>{
    'q': 'ping',
    'ts': DateTime.now().toUtc().toIso8601String(),
  };
  final reqPlain = Uint8List.fromList(utf8.encode(jsonEncode(reqJson)));

  // Produce SecureMessage with fields v,w,nonce,ciphertext,tag
  final SecureMessage reqMsg = enc.protect(reqPlain);

  // ---------------------------------------------------------------------------
  // Wrap into a JWT for transport (optional, application-level)
  // ---------------------------------------------------------------------------
  // PROTOCOL MAPPING INSIDE JWT:
  //   - JWT header carries *protocol headers* using the exact reserved keys:
  //       v, w, n, c
  //   - JWT payload carries the *body* (Base64-encoded tag) plus any app claims.
  //
  // This keeps our core protocol intact while letting you use JWT tooling.
  final jwt = JWT(
    // Payload (body): put Base64 tag under "body" + any app-level claims.
    {
      'body': base64Encode(reqMsg.tag),
      'X-App-Id': 'demo', // example custom claim
    },
    // Header: MUST use protocol keys exactly as on the wire.
    header: {
      'v': reqMsg.version, // protocol version (number is okay; we'll stringify later)
      'w': reqMsg.window, // time window (number)
      'n': base64Encode(reqMsg.nonce), // Base64 nonce (8 bytes)
      'c': base64Encode(reqMsg.ciphertext), // Base64 ciphertext
      // JWT will also inject std fields like 'alg','typ' automatically.
    },
  );

  // Sign JWT (HS256 by default) with a key known to both client & server.
  // NOTE: This is separate from the protocol HMAC (which authenticates ciphertext).
  final token = jwt.sign(SecretKey(base64Encode(masterKey)));
  print('--- CLIENT → Signed JWT token ---\n$token\n');

  // ---------------------------------------------------------------------------
  // 2) SERVER (simulated) → decode JWT, parse SecureMessage, verify+decrypt
  // ---------------------------------------------------------------------------
  // In production, receive `token` via your transport. Always **verify**:
  final decoded = JWT.verify(token, SecretKey(base64Encode(masterKey)));

  // Extract payload (body/tag) and header (protocol fields).
  final payload = Map<String, dynamic>.from(decoded.payload);
  final hdrDyn = Map<String, dynamic>.from(decoded.header ?? const {});

  // Build the exact wire headers map required by our protocol parser.
  // Convert numbers to strings (as they would appear in real HTTP headers).
  final headers = <String, String>{
    'version': hdrDyn['v'].toString(),
    'window': hdrDyn['w'].toString(),
    'nonce': hdrDyn['n'].toString(),
    'ciphertext': hdrDyn['c'].toString(),
  };

  // The body string is the Base64-encoded tag from the payload.
  final bodyB64 = payload['body'] as String;

  // Parse back to a SecureMessage (format validation only).
  final parsedReq = ApiClient.parseWire(headers: headers, body: bodyB64);

  // On the server, verify tag and decrypt.
  final serverDec = dec; // same instance for demo; would be separate in real app
  final serverReqPlain = serverDec.unprotect(parsedReq);

  final serverReqJson = jsonDecode(utf8.decode(serverReqPlain)) as Map<String, dynamic>;

  print('--- SERVER → Parsed plaintext (request) ---\n$serverReqJson\n');

  // ---------------------------------------------------------------------------
  // 3) SERVER → Build encrypted response (then client will decrypt)
  // ---------------------------------------------------------------------------
  final respJson = <String, dynamic>{
    'ok': true,
    'echo': serverReqJson,
  };
  final respPlain = Uint8List.fromList(utf8.encode(jsonEncode(respJson)));

  // Encrypt response (same protocol)
  final serverEnc = enc; // same instance for demo symmetry
  final respMsg = serverEnc.protect(respPlain);

  // Turn into wire parts (headers/body). You could also wrap into a JWT again.
  final respWire = ApiClient.toWire(respMsg, extraHeaders: {
    'X-Server': 'demo',
  });

  print('--- SERVER → WIRE (response) ---\n'
      'Headers: ${respWire.headers}\n'
      'Body   : ${respWire.body}\n');

  // ---------------------------------------------------------------------------
  // 4) CLIENT ← Parse and decrypt the response
  // ---------------------------------------------------------------------------
  final parsedResp = ApiClient.parseWire(headers: respWire.headers, body: respWire.body);

  final respPlainClient = dec.unprotect(parsedResp);
  final respJsonClient = jsonDecode(utf8.decode(respPlainClient)) as Map<String, dynamic>;

  print('--- CLIENT ← Parsed plaintext (response) ---\n$respJsonClient\n');
}
