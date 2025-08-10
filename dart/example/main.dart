/// Example – End-to-end roundtrip (no HTTP) + optional Dio snippet
/// ---------------------------------------------------------------
/// This example shows how to:
/// 1) Initialize the global crypto config (singleton).
/// 2) Encrypt a plaintext into a SecureMessage (headers+body).
/// 3) Serialize to wire parts (headers map + body string).
/// 4) Simulate a server that parses/verifies/decrypts the message,
///    then encrypts a response using the same protocol.
/// 5) Parse and decrypt the response on the client.
///
/// IMPORTANT:
/// - The library itself does NOT perform HTTP. We only operate on
///   headers/body content. A commented Dio snippet is included to
///   illustrate how to attach these parts to a real request.
///
/// HINTS:
/// - Replace the example `masterKey` with a secure, 32+ byte secret
///   shared between client and server.
/// - Ensure system clocks are reasonably synchronized (NTP).
/// - Consider setting `verificationSkewWindows` (e.g., 1) if you need
///   to accept adjacent 30s windows.

import 'dart:convert' show base64Encode, jsonEncode, utf8, jsonDecode;
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
  // NOTE: Use a cryptographically random 32+ byte key in production,
  // store it securely, and share it with the server.
  final masterKey = Uint8List.fromList(List<int>.generate(32, (i) => i));

  OtpCryptoConfig.initialize(
    masterKey: masterKey,
    salt: null, // optional; recommended to set as protocol constant
    info: utf8.encode('otp-v1') as Uint8List?, // optional; binds keys to this protocol
    protocolVersion: 1,
    windowSeconds: 30,
    verificationSkewWindows: 0, // set to 1 if you want to accept [w-1,w,w+1]
    timeProvider: SystemTimeProvider(),
  );

  // Client-side helpers
  var enc = Encryptor();
  var dec = Decryptor();

  // ---------------------------------------------------------------------------
  // 1) CLIENT → Build encrypted request (headers/body)
  // ---------------------------------------------------------------------------
  var reqJson = <String, dynamic>{
    'q': 'ping',
    'ts': DateTime.now().toUtc().toIso8601String(),
  };
  var reqPlain = Uint8List.fromList(utf8.encode(jsonEncode(reqJson)));

  // Produce SecureMessage
  SecureMessage reqMsg = enc.protect(reqPlain);


final jwt = JWT(
    {
      'body': base64Encode(reqMsg.tag),
      'X-App-Id': 'demo'
    },
    header:{
      'version': reqMsg.version,
      'ciphertext': base64Encode(reqMsg.ciphertext),
      'nonce': base64Encode(reqMsg.nonce),
      'window': reqMsg.window
    }
);

final token = jwt.sign(SecretKey(base64Encode(masterKey)));
  print('Signed token: $token\n');

  // ---------------------------------------------------------------------------
  // 2) SERVER (simulated) → parse, verify, decrypt
  // ---------------------------------------------------------------------------
  // In a real app, the server would receive `reqWire.headers` and `reqWire.body`.
  // Here we parse them back to a SecureMessage and decrypt.

 final jwtt=JWT.decode(token);

final payload = Map<String, dynamic>.from(jwtt.payload);
final Map<String, String> headers = jwtt.header != null ? Map<String, String>.from(jwtt.header!.map((key, value) => MapEntry(key, value.toString()))) : {};

print(headers);

  final parsedReq = ApiClient.parseWire(
    headers: headers,
    body: payload['body'],
  );

  // Server-side decryptor (would be in PHP in real deployment).
  var serverDec = dec; // using same instance just for demo
  var serverReqPlain = serverDec.unprotect(parsedReq);

  var serverReqJson = jsonDecode(utf8.decode(serverReqPlain)) as Map<String, dynamic>;

print('''
  --- SERVER → Parsed plaintext (request) ---
  $serverReqJson
''');

  // ---------------------------------------------------------------------------
  // 3) SERVER → Build encrypted response (headers/body)
  // ---------------------------------------------------------------------------
  var respJson = <String, dynamic>{
    'ok': true,
    'echo': serverReqJson,
  };
  var respPlain = Uint8List.fromList(utf8.encode(jsonEncode(respJson)));

  // Server encryptor (would run in PHP)
  var serverEnc = enc; // using same instance for demo symmetry
  var respMsg = serverEnc.protect(respPlain);
  var respWire = ApiClient.toWire(respMsg, extraHeaders: {
    'X-Server': 'demo',
  });

print('''
  --- SERVER → WIRE (response) ---
  Headers: ${respWire.headers}
  Body   : ${respWire.body}
''');

  // ---------------------------------------------------------------------------
  // 4) CLIENT ← Parse and decrypt the response
  // ---------------------------------------------------------------------------
  final parsedResp = ApiClient.parseWire(
    headers: respWire.headers,
    body: respWire.body,
  );
  var respPlainClient = dec.unprotect(parsedResp);
  var respJsonClient = jsonDecode(utf8.decode(respPlainClient)) as Map<String, dynamic>;

print('''
  --- CLIENT ← Parsed plaintext (response) ---
  $respJsonClient
''');

  // ---------------------------------------------------------------------------
  // OPTIONAL: Real HTTP request using Dio (application-level)
  // ---------------------------------------------------------------------------
  // IMPORTANT:
  // - This library does NOT send HTTP. The snippet below is a suggestion
  //   for how to glue the wire parts to a Dio call in a real app.
  //
  // import 'package:dio/dio.dart';
  //
  // var dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
  //
  // // 1) Build request as above:
  // var msg = enc.protect(Uint8List.fromList(utf8.encode('{"q":"ping"}')));
  // var wire = ApiClient.toWire(msg, extraHeaders: {'X-App-Id': 'demo'});
  //
  // // 2) Send with wire parts:
  // var resp = await dio.post(
  //   '/secure-endpoint',
  //   options: Options(headers: wire.headers),
  //   data: wire.body, // Base64 string
  // );
  //
  // // 3) Parse + decrypt response:
  // var respHeaders = Map<String, String>.from(
  //   resp.headers.map.map((k, v) => MapEntry(k, v.join(','))),
  // );
  // final replyMsg = ApiClient.parseWire(
  //   headers: respHeaders,
  //   body: resp.data is String ? resp.data as String : resp.data.toString(),
  // );
  // var replyPlain = dec.unprotect(replyMsg);
  // print(utf8.decode(replyPlain));
}
