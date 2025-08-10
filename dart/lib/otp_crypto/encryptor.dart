/// Encryptor – Builds SecureMessage (headers+body) from plaintext
/// --------------------------------------------------------------
/// High-level symmetric encryption orchestrator:
///   1) Derive {encKey, macKey} via HKDF-SHA256 from the singleton config.
///   2) Compute current time window `w`.
///   3) Generate 8-byte random nonce `n`.
///   4) Derive IV = HMAC(macKey, "iv" || u64be(w) || n)[:16].
///   5) Encrypt plaintext with AES-256-CBC + PKCS#7 using encKey+IV → `c`.
///   6) Compute tag = HMAC(macKey, "tag" || u64be(w) || n || c).
///   7) Produce `SecureMessage { v,w,n,c,tag }`.
///
/// This class **does not** send HTTP. It only returns a `SecureMessage`.
/// To serialize into headers/body, use `ApiClient.toWire(msg)`.
///
/// SECURITY NOTES:
/// - HKDF keys are derived once per `Encryptor` instance and cached.
/// - Always verify on the recipient before decryption (Encrypt-then-MAC).
/// - IV is never transmitted; both sides recompute it.
///
/// HINTS:
/// - You may keep a single `Encryptor` around (stateless w.r.t. requests).
/// - Provide your own `NonceGenerator` in tests for determinism.

import 'dart:typed_data';

import '../models/secure_message.dart';
import 'errors.dart';
import 'hkdf.dart';
import 'iv_deriver.dart';
import 'otp_cipher.dart';
import 'otp_crypto_config.dart';
import 'rand_nonce.dart';
import 'tag_deriver.dart';

class Encryptor {
  /// Global config (singleton or ephemeral).
  final OtpCryptoConfig _cfg;

  /// Nonce source (CSPRNG by default).
  final NonceGenerator _nonceGen;

  /// Cached HKDF-derived keys (enc + mac).
  final DerivedKeys _keys;

  /// Creates an Encryptor bound to a given [OtpCryptoConfig].
  ///
  /// [config] Defaults to the global singleton `OtpCryptoConfig.instance`.
  /// [nonceGenerator] Defaults to a CSPRNG-backed generator.
  ///
  /// HINT: Pass a `FixedNonceGenerator` in tests for stable outputs.
  Encryptor({
    OtpCryptoConfig? config,
    NonceGenerator? nonceGenerator,
  })  : _cfg = config ?? OtpCryptoConfig.instance,
        _nonceGen = nonceGenerator ?? NonceGenerator.defaultGenerator(),
        _keys = HkdfSha256.deriveKeys(
          masterKey: (config ?? OtpCryptoConfig.instance).masterKey,
          salt: (config ?? OtpCryptoConfig.instance).hkdfSalt,
          info: (config ?? OtpCryptoConfig.instance).hkdfInfo,
        );

  /// Protects [plaintext] and returns a `SecureMessage` ready for wire encoding.
  ///
  /// INPUT:
  /// - [plaintext]: raw bytes to encrypt (non-empty)
  ///
  /// OUTPUT:
  /// - `SecureMessage` with fields:
  ///     v = config.protocolVersion
  ///     w = floor(epochSeconds / windowSeconds)
  ///     n = 8B nonce
  ///     c = AES-256-CBC ciphertext
  ///     tag = HMAC-SHA256 over ("tag" || u64be(w) || n || c)
  ///
  /// Throws:
  /// - [InvalidMessageException] if inputs are malformed.
  /// - [InternalCryptoException]/[DecryptionFailedException] on crypto errors.
  ///
  /// HINT: Serialize with `ApiClient.toWire(message)` to obtain headers/body.
  SecureMessage protect(Uint8List plaintext) {
    if (plaintext.isEmpty) {
      throw InvalidMessageException(
        cause: ArgumentError('plaintext must not be empty.'),
      );
    }

    try {
      // 1) Current window
      final int w = _cfg.currentWindow();

      // 2) Fresh nonce (8 bytes)
      final nonce = _nonceGen.nextNonce();

      // 3) IV from macKey + ("iv"||u64be(w)||nonce)
      final iv = IvDeriver.derive(
        macKey: _keys.macKey,
        window: w,
        nonce: nonce,
      );

      // 4) Encrypt
      final ciphertext = OtpCipher.encrypt(
        encKey: _keys.encKey,
        iv: iv,
        plaintext: plaintext,
      );

      // 5) Tag from macKey + ("tag"||u64be(w)||nonce||ciphertext)
      final tag = TagDeriver.derive(
        macKey: _keys.macKey,
        window: w,
        nonce: nonce,
        ciphertext: ciphertext,
      );

      // 6) Build message
      final msg = SecureMessage.fromParts(
        v: _cfg.protocolVersion,
        w: w,
        nonce: nonce,
        ciphertext: ciphertext,
        tag: tag,
      );

      return msg;
    } catch (e, st) {
      // Wrap unexpected issues in a generic internal error.
      throw InternalCryptoException(cause: e, stackTrace: st);
    }
  }
}
