import 'dart:convert';
import 'dart:typed_data';

import '../codec/canonical_json.dart';
import 'pfs_header.dart';

/// HTTP context that is bound into AAD.
///
/// This prevents a valid ciphertext from being replayed to a different
/// endpoint/method without failing authentication.
///
/// Keep this minimal and canonical.
final class HttpContext {
  final String method; // e.g. "GET", "POST"
  final String path; // e.g. "/api/v1/devices"
  final Map<String, String> query; // decoded key/values (no leading '?')
  final String? host; // optional, if you want host binding

  const HttpContext({
    required this.method,
    required this.path,
    this.query = const {},
    this.host,
  });
}

/// Builds canonical AAD bytes for AEAD.
///
/// AAD bytes are:
///   UTF8("otp-pfs-v2/aad/1\n") ||
///   u32be(len(httpJson)) || httpJson ||
///   u32be(len(headerJson)) || headerJson
///
/// Where:
/// - httpJson is canonical JSON for HttpContext
/// - headerJson is PfsHeader canonical JSON
///
/// Both JSON blobs are encoded with canonicalJsonUtf8() (sorted keys, no whitespace).
final class Aad {
  static const String _domain = 'otp-pfs-v2/aad/1\n';

  static Uint8List build({
    required HttpContext http,
    required PfsHeader header,
  }) {
    final httpJson = _canonicalHttpJson(http);
    final headerJson = header.toCanonicalJsonBytes();

    final b = BytesBuilder(copy: false);
    b.add(utf8.encode(_domain));
    b.add(_u32be(httpJson.length));
    b.add(httpJson);
    b.add(_u32be(headerJson.length));
    b.add(headerJson);
    return b.toBytes();
  }

  static Uint8List _canonicalHttpJson(HttpContext http) {
    final method = http.method.trim().toUpperCase();
    if (method.isEmpty) throw const FormatException('HTTP method empty');

    final path = _canonicalPath(http.path);

    // Normalize query keys (trim, drop empty). Values are used as-is.
    final q = <String, String>{};
    http.query.forEach((k, v) {
      final kk = k.trim();
      if (kk.isEmpty) return;
      q[kk] = v;
    });

    final m = <String, dynamic>{
      'm': method,
      'p': path,
      if (q.isNotEmpty) 'q': q, // canonical encoder will sort keys
      if (http.host != null && http.host!.trim().isNotEmpty) 'h': http.host!.trim().toLowerCase(),
    };

    return canonicalJsonUtf8(m);
  }

  static String _canonicalPath(String path) {
    var p = path.trim();
    if (p.isEmpty) return '/';
    if (!p.startsWith('/')) p = '/$p';

    // Remove redundant consecutive slashes.
    while (p.contains('//')) {
      p = p.replaceAll('//', '/');
    }

    // Intentionally not normalizing dot-segments (app-specific).
    return p;
  }

  static Uint8List _u32be(int n) {
    if (n < 0 || n > 0xFFFFFFFF) {
      throw RangeError('u32 out of range: $n');
    }
    final out = Uint8List(4);
    out[0] = (n >>> 24) & 0xFF;
    out[1] = (n >>> 16) & 0xFF;
    out[2] = (n >>> 8) & 0xFF;
    out[3] = n & 0xFF;
    return out;
  }
}
