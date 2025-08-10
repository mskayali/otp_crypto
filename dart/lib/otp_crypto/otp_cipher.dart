/// OTP Crypto – AES-256-CBC with PKCS#7 padding (via `encrypt` package)
/// --------------------------------------------------------------------
/// Thin wrapper around `package:encrypt` to perform AES-256-CBC encryption
/// and decryption with PKCS#7 padding. This class **does not** derive keys
/// or IVs; it only consumes the `encKey` (32B) and `iv` (16B) provided by
/// higher layers (HKDF + IV derivation).
///
/// SECURITY NOTES:
/// - Enforce key length (32) and IV length (16) before calling AES.
/// - This layer performs **no** MAC verification; always verify the HMAC tag
///   (Encrypt-then-MAC) *before* decryption at a higher layer.
/// - Catch and wrap low-level errors to avoid leaking internals.
///
/// HINTS:
/// - Use `encrypt(...)` to obtain ciphertext bytes for the wire header `c`.
/// - Use `decrypt(...)` only **after** tag verification passes.

import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as enc;

import 'errors.dart';

class OtpCipher {
  OtpCipher._(); // static-only

  /// Encrypts [plaintext] using AES-256-CBC with PKCS#7 padding.
  ///
  /// [encKey] must be exactly 32 bytes.
  /// [iv]     must be exactly 16 bytes.
  ///
  /// RETURNS: ciphertext bytes.
  ///
  /// Throws [InternalCryptoException] if encryption fails unexpectedly.
  static Uint8List encrypt({
    required Uint8List encKey,
    required Uint8List iv,
    required Uint8List plaintext,
  }) {
    _requireKeyIv(encKey, iv);

    try {
      final key = enc.Key(encKey);
      final ivObj = enc.IV(iv);

      // Explicitly request CBC + PKCS7 padding.
      final aes = enc.AES(
        key,
        mode: enc.AESMode.cbc,
        padding: 'PKCS7',
      );
      final encrypter = enc.Encrypter(aes);

      final encrypted = encrypter.encryptBytes(plaintext, iv: ivObj);
      return Uint8List.fromList(encrypted.bytes);
    } catch (e, st) {
      // Avoid surfacing library-specific errors.
      throw InternalCryptoException(cause: e, stackTrace: st);
    }
  }

  /// Decrypts [ciphertext] using AES-256-CBC with PKCS#7 padding.
  ///
  /// [encKey] must be exactly 32 bytes.
  /// [iv]     must be exactly 16 bytes.
  ///
  /// RETURNS: plaintext bytes.
  ///
  /// Throws [DecryptionFailedException] on any failure (including bad padding).
  /// IMPORTANT: Callers must have already verified the HMAC tag.
  static Uint8List decrypt({
    required Uint8List encKey,
    required Uint8List iv,
    required Uint8List ciphertext,
  }) {
    _requireKeyIv(encKey, iv);

    try {
      final key = enc.Key(encKey);
      final ivObj = enc.IV(iv);

      final aes = enc.AES(
        key,
        mode: enc.AESMode.cbc,
        padding: 'PKCS7',
      );
      final encrypter = enc.Encrypter(aes);

      // The `encrypt` package accepts raw bytes via `Encrypted`.
      final decrypted = encrypter.decryptBytes(enc.Encrypted(ciphertext), iv: ivObj);
      return Uint8List.fromList(decrypted);
    } catch (e, st) {
      // On any error, present a generic decryption failure.
      throw DecryptionFailedException(cause: e, stackTrace: st);
    }
  }

  // -- helpers ---------------------------------------------------------------

  /// Validates key and IV lengths for AES-256-CBC.
  ///
  /// HINT: Keep input validation close to crypto calls to fail fast.
  static void _requireKeyIv(Uint8List encKey, Uint8List iv) {
    if (encKey.length != 32) {
      throw ArgumentError.value(encKey.length, 'encKey.length', 'AES-256 key must be 32 bytes.');
    }
    if (iv.length != 16) {
      throw ArgumentError.value(iv.length, 'iv.length', 'AES-CBC IV must be 16 bytes.');
    }
  }
}
