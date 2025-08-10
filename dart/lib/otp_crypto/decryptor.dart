/// Decryptor – Verifies & decrypts a SecureMessage (Encrypt-then-MAC)
/// ------------------------------------------------------------------
/// Processing order (DO NOT change):
///   1) Validate protocol version and time-window skew.
///   2) Derive {encKey, macKey} via HKDF-SHA256 from config.
///   3) Recompute tag = HMAC(macKey, "tag" || u64be(w) || nonce || ciphertext).
///   4) Constant-time compare with body tag; if mismatch → AuthenticationFailed.
///   5) Derive IV = HMAC(macKey, "iv" || u64be(w) || nonce)[:16].
///   6) Decrypt AES-256-CBC + PKCS#7 using encKey+IV → plaintext.
///
/// NOTES:
/// - This class **does not** handle HTTP. It only consumes a `SecureMessage`
///   reconstructed from wire headers/body.
/// - Time skew tolerance is enforced **before** any crypto to fail fast.
/// - We always verify MAC **before** decrypting (Encrypt-then-MAC).
///
/// HINTS:
/// - Keep a single `Decryptor` around; it caches HKDF-derived keys.
/// - Configure `verificationSkewWindows` in `OtpCryptoConfig` to accept ±N
///   adjacent windows relative to *current* window.

import 'dart:typed_data';

import '../models/secure_message.dart';
import 'errors.dart';
import 'hkdf.dart';
import 'iv_deriver.dart';
import 'otp_cipher.dart';
import 'otp_crypto_config.dart';
import 'tag_deriver.dart';
import 'utils.dart';

class Decryptor {
  /// Global/effective config.
  final OtpCryptoConfig _cfg;

  /// Cached HKDF-derived keys (enc + mac).
  final DerivedKeys _keys;

  /// Creates a Decryptor bound to [OtpCryptoConfig].
  ///
  /// [config] Defaults to the global singleton `OtpCryptoConfig.instance`.
  ///
  /// HINT: Instantiate once and reuse; keys are derived in the constructor.
  Decryptor({OtpCryptoConfig? config})
      : _cfg = config ?? OtpCryptoConfig.instance,
        _keys = HkdfSha256.deriveKeys(
          masterKey: (config ?? OtpCryptoConfig.instance).masterKey,
          salt: (config ?? OtpCryptoConfig.instance).hkdfSalt,
          info: (config ?? OtpCryptoConfig.instance).hkdfInfo,
        );

  /// Verifies and decrypts a previously parsed `SecureMessage`.
  ///
  /// INPUT:
  /// - [msg]: a format-validated message (see `SecureMessage.fromWire`).
  ///
  /// OUTPUT:
  /// - plaintext bytes if authentication and decryption succeed.
  ///
  /// Throws:
  /// - [InvalidMessageException] for version mismatch or window out-of-range.
  /// - [AuthenticationFailedException] on HMAC mismatch.
  /// - [DecryptionFailedException] if AES decryption/padding fails.
  ///
  /// HINT:
  /// - Always call this on the server for incoming requests and on the client
  ///   for responses returned by the server.
  Uint8List unprotect(SecureMessage msg) {
    // 1) Protocol version check (extensible: allow only exact match for v1).
    if (msg.version != _cfg.protocolVersion) {
      throw InvalidMessageException(
        cause: ArgumentError.value(
          msg.version,
          'version',
          'Unsupported protocol version; expected ${_cfg.protocolVersion}.',
        ),
      );
    }

    // 2) Window skew check (reject too old/future messages quickly).
    _enforceWindowSkew(msg.window);

    // 3) Verify tag in constant time (Encrypt-then-MAC).
    final computedTag = TagDeriver.derive(
      macKey: _keys.macKey,
      window: msg.window,
      nonce: msg.nonce,
      ciphertext: msg.ciphertext,
    );
    final ok = Bytes.constantTimeEquals(computedTag, msg.tag);
    // Best-effort zeroization (mutable copy).
    Bytes.secureZero(computedTag);

    if (!ok) {
      throw AuthenticationFailedException();
    }

    // 4) Derive IV and decrypt.
    final iv = IvDeriver.derive(
      macKey: _keys.macKey,
      window: msg.window,
      nonce: msg.nonce,
    );

    // If AES fails (e.g., bad padding), OtpCipher throws DecryptionFailedException.
    final plaintext = OtpCipher.decrypt(
      encKey: _keys.encKey,
      iv: iv,
      ciphertext: msg.ciphertext,
    );

    return plaintext;
  }

  // -- helpers ---------------------------------------------------------------

  /// Enforces skew tolerance: abs(receivedW - currentW) <= verificationSkewWindows
  ///
  /// Throws [WindowOutOfRangeException] if outside tolerance.
  ///
  /// HINT: This prevents accepting stale/future messages even if tags match.
  void _enforceWindowSkew(int receivedW) {
    final currentW = _cfg.currentWindow();
    final delta = (receivedW - currentW).abs();
    if (delta > _cfg.verificationSkewWindows) {
      throw WindowOutOfRangeException(
        cause: StateError(
          'received window $receivedW outside tolerance of current $currentW (±${_cfg.verificationSkewWindows})',
        ),
      );
    }
  }
}
