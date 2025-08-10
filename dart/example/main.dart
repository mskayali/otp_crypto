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

import 'dart:convert' show jsonEncode, jsonDecode, utf8;
import 'dart:typed_data';

import 'package:otp_crypto/http/api_client.dart';
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
  final enc = Encryptor();
  final dec = Decryptor();

  // ---------------------------------------------------------------------------
  // 1) CLIENT → Build encrypted request (headers/body)
  // ---------------------------------------------------------------------------
  final reqJson = <String, dynamic>{
    'q': 'ping',
    'ts': DateTime.now().toUtc().toIso8601String(),
  };
  final reqPlain = Uint8List.fromList(utf8.encode(jsonEncode(reqJson)));

  // Produce SecureMessage
  final reqMsg = enc.protect(reqPlain);

  // Turn into wire parts for transport (headers map + body string)
  final reqWire = ApiClient.toWire(
    reqMsg,
    extraHeaders: {
      'X-App-Id': 'demo', // example app header; will be passed along
    },
  );

  print('--- CLIENT → WIRE (request) ---');
  print('Headers: ${reqWire.headers}');
  print('Body   : ${reqWire.body}');
  print('');

  // ---------------------------------------------------------------------------
  // 2) SERVER (simulated) → parse, verify, decrypt
  // ---------------------------------------------------------------------------
  // In a real app, the server would receive `reqWire.headers` and `reqWire.body`.
  // Here we parse them back to a SecureMessage and decrypt.

  final parsedReq = ApiClient.parseWire(
    headers: reqWire.headers,
    body: reqWire.body,
  );

  // Server-side decryptor (would be in PHP in real deployment).
  final serverDec = dec; // using same instance just for demo
  final serverReqPlain = serverDec.unprotect(parsedReq);

  final serverReqJson = jsonDecode(utf8.decode(serverReqPlain)) as Map<String, dynamic>;

  print('--- SERVER → Parsed plaintext (request) ---');
  print(serverReqJson);
  print('');

  // ---------------------------------------------------------------------------
  // 3) SERVER → Build encrypted response (headers/body)
  // ---------------------------------------------------------------------------
  final respJson = <String, dynamic>{
    'ok': true,
    'echo': serverReqJson,
  };
  final respPlain = Uint8List.fromList(utf8.encode(jsonEncode(respJson)));

  // Server encryptor (would run in PHP)
  final serverEnc = enc; // using same instance for demo symmetry
  final respMsg = serverEnc.protect(respPlain);
  final respWire = ApiClient.toWire(respMsg, extraHeaders: {
    'X-Server': 'demo',
  });

  print('--- SERVER → WIRE (response) ---');
  print('Headers: ${respWire.headers}');
  print('Body   : ${respWire.body}');
  print('');

  // ---------------------------------------------------------------------------
  // 4) CLIENT ← Parse and decrypt the response
  // ---------------------------------------------------------------------------
  final parsedResp = ApiClient.parseWire(
    headers: respWire.headers,
    body: respWire.body,
  );
  final respPlainClient = dec.unprotect(parsedResp);
  final respJsonClient = jsonDecode(utf8.decode(respPlainClient)) as Map<String, dynamic>;

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
  // final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
  //
  // // 1) Build request as above:
  // final msg = enc.protect(Uint8List.fromList(utf8.encode('{"q":"ping"}')));
  // final wire = ApiClient.toWire(msg, extraHeaders: {'X-App-Id': 'demo'});
  //
  // // 2) Send with wire parts:
  // final resp = await dio.post(
  //   '/secure-endpoint',
  //   options: Options(headers: wire.headers),
  //   data: wire.body, // Base64 string
  // );
  //
  // // 3) Parse + decrypt response:
  // final respHeaders = Map<String, String>.from(
  //   resp.headers.map.map((k, v) => MapEntry(k, v.join(','))),
  // );
  // final replyMsg = ApiClient.parseWire(
  //   headers: respHeaders,
  //   body: resp.data is String ? resp.data as String : resp.data.toString(),
  // );
  // final replyPlain = dec.unprotect(replyMsg);
  // print(utf8.decode(replyPlain));
}
