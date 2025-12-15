import 'dart:convert';
import 'dart:typed_data';

import 'package:otp_crypto/pfs/errors.dart';

/// Compact v2 message envelope (body).
///
/// Fields:
/// - ct  : ciphertext bytes (base64)
/// - tag : authentication tag / MAC (base64)
/// - n   : optional nonce (base64) (NOT used by default; nonce is derived from seq)
///
/// Design:
/// - Minimal JSON to keep payload small and debuggable.
/// - Canonical keys: 'ct', 'tag', optional 'n'
final class PfsEnvelope {
  final Uint8List ct;
  final Uint8List tag;
  final Uint8List? nonce;

  const PfsEnvelope({
    required this.ct,
    required this.tag,
    this.nonce,
  });

  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{
      'ct': base64Encode(ct),
      'tag': base64Encode(tag),
    };
    if (nonce != null) {
      m['n'] = base64Encode(nonce!);
    }
    return m;
  }

  /// Canonical JSON bytes (UTF-8) for transport.
  Uint8List encode() {
    final s = jsonEncode(toJson());
    return Uint8List.fromList(utf8.encode(s));
  }

  static PfsEnvelope decode(Uint8List bytes) {
    final obj = jsonDecode(utf8.decode(bytes));
    if (obj is! Map<String, dynamic>) {
      throw PfsErrors.invalidInput('PfsEnvelope must be a JSON object');
    }
    return fromJson(obj);
  }

  static PfsEnvelope fromJson(Map<String, dynamic> json) {
    final ct = json['ct'];
    final tag = json['tag'];
    final n = json['n'];

    if (ct is! String || ct.isEmpty) {
      throw PfsErrors.invalidInput('PfsEnvelope.ct is required');
    }
    if (tag is! String || tag.isEmpty) {
      throw PfsErrors.invalidInput('PfsEnvelope.tag is required');
    }

    final ctBytes = base64Decode(ct);
    if (ctBytes.isEmpty) {
      throw PfsErrors.invalidInput('PfsEnvelope.ct must not be empty');
    }

    final tagBytes = base64Decode(tag);
    if (tagBytes.isEmpty) {
      throw PfsErrors.invalidInput('PfsEnvelope.tag must not be empty');
    }

    Uint8List? nonceBytes;
    if (n != null) {
      if (n is! String || n.isEmpty) {
        throw PfsErrors.invalidInput('PfsEnvelope.n must be base64 string');
      }
      final nb = base64Decode(n);
      if (nb.isEmpty) {
        throw PfsErrors.invalidInput('PfsEnvelope.n must not be empty');
      }
      nonceBytes = Uint8List.fromList(nb);
    }

    return PfsEnvelope(
      ct: Uint8List.fromList(ctBytes),
      tag: Uint8List.fromList(tagBytes),
      nonce: nonceBytes,
    );
  }
}
