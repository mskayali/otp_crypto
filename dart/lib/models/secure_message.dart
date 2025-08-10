/// SecureMessage – Wire model for headers/body
/// -------------------------------------------
/// Represents the protocol wire format used over (or alongside) HTTP:
///   Headers (as key-value strings):
///     "v": 1                    // protocol version
///     "w": <int>                // time window (floor(epoch/30))
///     "n": "<b64_nonce>"        // 8-byte random nonce (Base64)
///     "c": "<b64_ciphertext>"   // AES-256-CBC ciphertext (Base64)
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
/// - Keep field names exactly "v","w","n","c" to match the protocol.
///
/// HINTS:
/// - Use with `Encryptor` (to build a SecureMessage) and `Decryptor` (to parse).
/// - Headers are returned as `Map<String,String>` ready to be attached to an
///   HTTP request by a higher-level client (this library does not send HTTP).

import 'dart:typed_data';

import '../otp_crypto/errors.dart';
import '../otp_crypto/rand_nonce.dart';
import '../otp_crypto/utils.dart';

class SecureMessage {
  /// Protocol version (`v`). Currently 1.
  final int v;

  /// Time window (`w`): floor(epoch / windowSeconds).
  final int w;

  /// Nonce (`n`) as raw 8 bytes.
  final Uint8List nonce;

  /// Ciphertext (`c`) as raw bytes.
  final Uint8List ciphertext;

  /// Tag (body) as raw 32 bytes (HMAC-SHA256).
  final Uint8List tag;

  /// Creates an immutable `SecureMessage` from already-parsed parts.
  ///
  /// HINT: Prefer `fromParts` to enforce basic length checks at creation time.
  SecureMessage._internal({
    required this.v,
    required this.w,
    required this.nonce,
    required this.ciphertext,
    required this.tag,
  });

  /// Builds a `SecureMessage` from *raw* components.
  ///
  /// [v] protocol version (must be >=1).
  /// [w] time window (non-negative).
  /// [nonce] 8-byte random nonce (validated).
  /// [ciphertext] AES-256-CBC ciphertext bytes.
  /// [tag] 32-byte HMAC-SHA256 tag.
  ///
  /// Throws [InvalidMessageException] if any precondition fails.
  static SecureMessage fromParts({
    required int v,
    required int w,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  }) {
    try {
      if (v < 1) {
        throw ArgumentError.value(v, 'v', 'Protocol version must be >= 1.');
      }
      if (w < 0) {
        throw ArgumentError.value(w, 'w', 'Window must be non-negative.');
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
        v: v,
        w: w,
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
  /// [headers] must contain keys: "v","w","n","c" (all strings).
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
      final vStr = headers['v'];
      final wStr = headers['w'];
      final nStr = headers['n'];
      final cStr = headers['c'];

      if (vStr == null || wStr == null || nStr == null || cStr == null) {
        throw ArgumentError('missing required headers v/w/n/c');
      }

      // Parse integers (v,w). Reject non-integers / negatives.
      final v = int.parse(vStr);
      final w = int.parse(wStr);
      if (v < 1) {
        throw ArgumentError.value(v, 'v', 'Protocol version must be >= 1.');
      }
      if (w < 0) {
        throw ArgumentError.value(w, 'w', 'Window must be non-negative.');
      }

      // Decode Base64 fields.
      final nonce = Bytes.fromBase64Strict(nStr);
      final ciphertext = Bytes.fromBase64Strict(cStr);
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
        v: v,
        w: w,
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
  /// RETURNS: `{"v": "$v", "w": "$w", "n": "<b64>", "c": "<b64>"}`
  ///
  /// HINT: Attach this map as HTTP headers at the call site; this library does not send HTTP.
  Map<String, String> toWireHeaders() {
    return {
      'v': v.toString(),
      'w': w.toString(),
      'n': Bytes.toBase64(nonce),
      'c': Bytes.toBase64(ciphertext),
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
    int? v,
    int? w,
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
      v: v ?? this.v,
      w: w ?? this.w,
      nonce: Uint8List.fromList(nextNonce),
      ciphertext: Uint8List.fromList(nextCipher),
      tag: Uint8List.fromList(nextTag),
    );
  }
}
