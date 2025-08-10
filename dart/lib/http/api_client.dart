/// API Client Helpers (header/body adapters only – no HTTP)
/// --------------------------------------------------------
/// This module provides small adapters to turn a `SecureMessage` into
/// wire-ready parts (headers map + body string) and to parse them back.
/// It **does not** perform any network I/O and does not depend on any
/// HTTP client. You can plug these parts into any client (e.g. Dio).
///
/// WHY:
/// - Project requirement: the library must only operate on given
///   headers/body and **must not** create HTTP requests/responses.
/// - These helpers keep the "reserved" protocol headers isolated
///   from any user/application headers.
///
/// INTEGRATION (example with Dio — outside this library):
/// ```dart
/// final parts = ApiClient.toWire(message, extraHeaders: {
///   'X-App-Id': 'myapp',
/// });
/// await dio.post(
///   '/endpoint',
///   options: Options(headers: parts.headers),
///   data: parts.body, // String: Base64 tag
/// );
/// ```
///
/// HINTS:
/// - Use `ApiClient.parseWire(headers, body)` on the receiving side
///   to reconstruct the `SecureMessage` before verifying/decrypting.
/// - Extra headers cannot override reserved keys: "version","window","nonce","ciphertext".

import 'package:meta/meta.dart';

import '../models/secure_message.dart';
import '../otp_crypto/errors.dart';

/// Immutable wire parts: headers and body.
///
/// HINT: Attach `headers` to your HTTP request and `body` as the string payload.
@immutable
class WireRequestParts {
  /// HTTP-compatible headers containing the protocol fields.
  final Map<String, String> headers;

  /// Body string (Base64 HMAC tag).
  final String body;

  const WireRequestParts({
    required this.headers,
    required this.body,
  });
}

/// Small adapter for (de)serializing protocol messages to/from wire parts.
///
/// SECURITY:
/// - This class does **not** verify or decrypt; it only formats.
/// - Use `Decryptor` to verify MAC and decrypt after parsing.
class ApiClient {
  ApiClient._(); // static-only

  /// Protocol-reserved header keys (lowercase).
  static const Set<String> _reserved = {'version', 'window', 'nonce', 'ciphertext'};

  /// Serializes a `SecureMessage` into wire-ready headers/body.
  ///
  /// [msg] The already-built secure message.
  /// [extraHeaders] Optional application headers to merge (e.g., auth, tracing).
  ///   - Keys are treated as case-sensitive for the caller, but we prevent
  ///     collisions with the reserved protocol keys ("version","window","nonce","ciphertext")
  ///     regardless of the caller's case.
  ///
  /// RETURNS: `WireRequestParts` with immutable headers map and body string.
  ///
  /// Throws [InvalidMessageException] if `extraHeaders` attempts to override
  /// reserved protocol headers.
  static WireRequestParts toWire(
    SecureMessage msg, {
    Map<String, String>? extraHeaders,
  }) {
    // Start from the protocol headers.
    final proto = msg.toWireHeaders();

    // Merge application headers while preventing collisions.
    final merged = <String, String>{...proto};
    if (extraHeaders != null && extraHeaders.isNotEmpty) {
      for (final entry in extraHeaders.entries) {
        final key = entry.key;
        // If extra header collides with reserved keys (case-insensitive), reject.
        if (_isReserved(key)) {
          throw InvalidMessageException(
            cause: ArgumentError('extraHeaders cannot override reserved key: $key'),
          );
        }
        merged[key] = entry.value;
      }
    }

    return WireRequestParts(
      headers: Map.unmodifiable(merged),
      body: msg.toWireBody(),
    );
  }

  /// Parses a `SecureMessage` from wire headers/body.
  ///
  /// [headers] Full headers map as received from the transport layer.
  /// [body]    Request/response body string (Base64 tag).
  ///
  /// RETURNS: `SecureMessage` (format-validated, not yet verified/decrypted).
  ///
  /// Throws [InvalidMessageException] if required fields are missing/invalid.
  static SecureMessage parseWire({
    required Map<String, String> headers,
    required String body,
  }) {
    return SecureMessage.fromWire(headers: headers, body: body);
  }

  // -- helpers ---------------------------------------------------------------

  /// Returns true if [key] (case-insensitive) is a protocol-reserved header.
  static bool _isReserved(String key) {
    final lower = key.toLowerCase();
    return _reserved.contains(lower);
  }
}
