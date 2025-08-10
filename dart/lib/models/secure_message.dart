/// SecureMessage – Wire model for headers/body
/// -------------------------------------------
/// Represents the protocol wire format used over (or alongside) HTTP:
///   Headers (as key-value strings):
///     "version": 1                    // protocol version
///     "window": <int>                // time window (floor(epoch/30))
///     "nonce": "<b64_nonce>"        // 8-byte random nonce (Base64)
///     "ciphertext": "<b64_ciphertext>"   // AES-256-CBC ciphertext (Base64)
///   Body (as string):
///     "<b64_tag>"               // HMAC-SHA256 tag (Base64)
///
/// This type offers:
/// - Construction from raw bytes (`fromParts`)
/// - Parsing from wire headers/body (`fromWire`)
/// - Serialization back to wire headers/body (`toWireHeaders`, `toWireBody`)
///
/// SECURITY NOTES:
/// - This type **does not** verify MACs nor decrypt. It only parses/holds data.
/// - Validation here is strictly for format (presence, base64, lengths).
/// - Keep field names exactly "version","window","nonce","ciphertext" to match the protocol.
///
/// HINTS:
/// - Use with `Encryptor` (to build a SecureMessage) and `Decryptor` (to parse).
/// - Headers are returned as `Map<String,String>` ready to be attached to an
///   HTTP request by a higher-level client (this library does not send HTTP).

import 'dart:convert';
import 'dart:typed_data';

import '../otp_crypto/errors.dart';
import '../otp_crypto/rand_nonce.dart';
import '../otp_crypto/utils.dart';

class SecureMessage {
  /// Protocol version (`version`). Currently 1.
  final int version;

  /// Time window (`window`): floor(epoch / windowSeconds).
  final int window;

  /// Nonce (`nonce`) as raw 8 bytes.
  final Uint8List nonce;

  /// Ciphertext (`ciphertext`) as raw bytes.
  final Uint8List ciphertext;

  /// Tag (body) as raw 32 bytes (HMAC-SHA256).
  final Uint8List tag;

  /// Creates an immutable `SecureMessage` from already-parsed parts.
  ///
  /// HINT: Prefer `fromParts` to enforce basic length checks at creation time.
  SecureMessage._internal({
    required this.version,
    required this.window,
    required this.nonce,
    required this.ciphertext,
    required this.tag,
  });

  Map<String,dynamic> toJson() {
    return {
      'version': version,
      'window': window,
      'nonce': base64.encode(nonce),
      'ciphertext': base64.encode(ciphertext),
      'tag': base64.encode(tag),
    };
  }

  /// Builds a `SecureMessage` from *raw* components.
  ///
  /// [version] protocol version (must be >=1).
  /// [window] time window (non-negative).
  /// [nonce] 8-byte random nonce (validated).
  /// [ciphertext] AES-256-CBC ciphertext bytes.
  /// [tag] 32-byte HMAC-SHA256 tag.
  ///
  /// Throws [InvalidMessageException] if any precondition fails.
  static SecureMessage fromParts({
    required int version,
    required int window,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  }) {
    try {
      if (version < 1) {
        throw ArgumentError.value(version, 'version', 'Protocol version must be >= 1.');
      }
      if (window < 0) {
        throw ArgumentError.value(window, 'window', 'Window must be non-negative.');
      }
      NonceGenerator.validate(nonce);
      if (ciphertext.isEmpty) {
        throw ArgumentError('ciphertext must not be empty.');
      }
      if (tag.length != 32) {
        throw ArgumentError.value(tag.length, 'tag.length', 'HMAC-SHA256 tag must be 32 bytes.');
      }

      // Store defensive copies to maintain immutability guarantees.
      return SecureMessage._internal(
        version: version,
        window: window,
        nonce: Uint8List.fromList(nonce),
        ciphertext: Uint8List.fromList(ciphertext),
        tag: Uint8List.fromList(tag),
      );
    } catch (e, st) {
      throw InvalidMessageException(cause: e, stackTrace: st);
    }
  }

  /// Parses a `SecureMessage` from **wire** headers/body.
  ///
  /// [headers] must contain keys: "version","window","nonce","ciphertext" (all strings).
  /// [body]    must be the Base64-encoded tag string.
  ///
  /// Throws [InvalidMessageException] on missing fields, bad integers/base64,
  /// nonce length != 8, or empty ciphertext.
  ///
  /// HINT: This is a *format* parser only; MAC verification is done elsewhere.
  static SecureMessage fromWire({
    required Map<String, String> headers,
    required String body,
  }) {
    try {
      // -- Required header fields -------------------------------------------
      final versionStr = headers['version'];
      final windowStr = headers['window'];
      final nonceStr = headers['nonce'];
      final ciphertextStr = headers['ciphertext'];

      if (versionStr == null || windowStr == null || nonceStr == null || ciphertextStr == null) {
        throw ArgumentError('missing required headers v/w/n/c');
      }

      // Parse integers (version, window). Reject non-integers / negatives.
      final version = int.parse(versionStr);
      final window = int.parse(windowStr);
      if (version < 1) {
        throw ArgumentError.value(version, 'version', 'Protocol version must be >= 1.');
      }
      if (window < 0) {
        throw ArgumentError.value(window, 'window', 'Window must be non-negative.');
      }

      // Decode Base64 fields.
      final nonce = Bytes.fromBase64Strict(nonceStr);
      final ciphertext = Bytes.fromBase64Strict(ciphertextStr);
      final tag = Bytes.fromBase64Strict(body);

      // Enforce lengths.
      NonceGenerator.validate(nonce);
      if (ciphertext.isEmpty) {
        throw ArgumentError('ciphertext must not be empty.');
      }
      if (tag.length != 32) {
        throw ArgumentError.value(tag.length, 'tag.length', 'HMAC-SHA256 tag must be 32 bytes.');
      }

      return SecureMessage._internal(
        version: version,
        window: window,
        nonce: nonce,
        ciphertext: ciphertext,
        tag: tag,
      );
    } catch (e, st) {
      throw InvalidMessageException(cause: e, stackTrace: st);
    }
  }

  /// Serializes this message to **wire headers** map using Base64 for binary fields.
  ///
  /// RETURNS: `{"version": "$version", "window": "$window", "nonce": "<b64>", "ciphertext": "<b64>"}`
  ///
  /// HINT: Attach this map as HTTP headers at the call site; this library does not send HTTP.
  Map<String, String> toWireHeaders() {
    return {
      'version': version.toString(),
      'window': window.toString(),
      'nonce': Bytes.toBase64(nonce),
      'ciphertext': Bytes.toBase64(ciphertext),
    };
  }

  /// Serializes this message to **wire body** string (Base64 tag).
  ///
  /// RETURNS: `"<b64_tag>"`
  ///
  /// HINT: Put this as the HTTP body (string) at the call site.
  String toWireBody() => Bytes.toBase64(tag);

  /// Convenience: clones this message with new ciphertext/tag (e.g., for re-encrypt).
  ///
  /// HINT: Rarely needed; supplied for completeness in tests/tools.
  SecureMessage copyWith({
    int? version,
    int? window,
    Uint8List? nonce,
    Uint8List? ciphertext,
    Uint8List? tag,
  }) {
    final nextNonce = nonce ?? this.nonce;
    final nextCipher = ciphertext ?? this.ciphertext;
    final nextTag = tag ?? this.tag;

    // Re-validate variable-length fields on mutation.
    NonceGenerator.validate(nextNonce);
    if (nextCipher.isEmpty) {
      throw InvalidMessageException(cause: ArgumentError('ciphertext must not be empty.'));
    }
    if (nextTag.length != 32) {
      throw InvalidMessageException(cause: ArgumentError.value(nextTag.length, 'tag.length', 'HMAC-SHA256 tag must be 32 bytes.'));
    }

    return SecureMessage._internal(
      version: version ?? this.version,
      window: window ?? this.window,
      nonce: Uint8List.fromList(nextNonce),
      ciphertext: Uint8List.fromList(nextCipher),
      tag: Uint8List.fromList(nextTag),
    );
  }
}
