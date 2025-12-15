import 'dart:convert';
import 'dart:typed_data';

import '../codec/canonical_json.dart';

/// Minimal v2 header.
///
/// Fields:
/// - v   : protocol version (int) -> 2
/// - sid : session id (16 bytes) base64
/// - seq : u64 sequence number (int)
/// - ts  : unix ms timestamp (int)
/// - kid : optional server identity key reference (string, e.g. "pfs-server-id:3")
///
/// This header is:
/// - carried as plaintext metadata (e.g. HTTP headers)
/// - authenticated by AEAD AAD binding (must be canonical and stable)
final class PfsHeader {
  final int v;
  final Uint8List sid16;
  final int seq;
  final int timestampMs;
  final String? kid;

  const PfsHeader({
    required this.v,
    required this.sid16,
    required this.seq,
    required this.timestampMs,
    this.kid,
  })  : assert(seq > 0),
        assert(timestampMs > 0);

  /// Compact wire headers (recommended):
  /// - v, sid, seq, ts, (kid)
  ///
  /// Values are strings suitable for HTTP headers.
  Map<String, String> toWireHeaders() {
    final m = <String, String>{
      'v': v.toString(),
      'sid': base64Encode(sid16),
      'seq': seq.toString(),
      'ts': timestampMs.toString(),
    };
    if (kid != null && kid!.trim().isNotEmpty) {
      m['kid'] = kid!;
    }
    return m;
  }

  /// Parse from wire headers (case-insensitive).
  ///
  /// Accepts both:
  /// - compact keys: v/sid/seq/ts/kid
  /// - long keys: version/session/sequence/timestamp/keyid
  static PfsHeader fromWireHeaders(Map<String, String> headers) {
    final h = <String, String>{};
    headers.forEach((k, v) => h[k.toLowerCase()] = v);

    String? getAny(List<String> keys) {
      for (final k in keys) {
        final v = h[k];
        if (v != null && v.isNotEmpty) return v;
      }
      return null;
    }

    final vStr = getAny(['v', 'version']);
    final sidStr = getAny(['sid', 'session']);
    final seqStr = getAny(['seq', 'sequence']);
    final tsStr = getAny(['ts', 'timestamp']);
    final kidStr = getAny(['kid', 'keyid']);

    if (vStr == null) throw const FormatException('missing header: v');
    if (sidStr == null) throw const FormatException('missing header: sid');
    if (seqStr == null) throw const FormatException('missing header: seq');
    if (tsStr == null) throw const FormatException('missing header: ts');

    final v = int.tryParse(vStr);
    final seq = int.tryParse(seqStr);
    final ts = int.tryParse(tsStr);

    if (v == null) throw const FormatException('invalid v');
    if (seq == null || seq <= 0) throw const FormatException('invalid seq');
    if (ts == null || ts <= 0) throw const FormatException('invalid ts');

    final sid = base64Decode(sidStr);
    if (sid.length != 16) throw const FormatException('invalid sid length');

    final kid = (kidStr == null || kidStr.trim().isEmpty) ? null : kidStr.trim();

    return PfsHeader(
      v: v,
      sid16: Uint8List.fromList(sid),
      seq: seq,
      timestampMs: ts,
      kid: kid,
    );
  }

  /// Canonical JSON map used for AAD binding.
  ///
  /// IMPORTANT: Must be stable across languages.
  /// We encode using canonicalJsonEncode/canonicalJsonUtf8 (sorted keys).
  Map<String, dynamic> toCanonicalJsonMap() {
    final m = <String, dynamic>{
      'v': v,
      'sid': base64Encode(sid16),
      'seq': seq,
      'ts': timestampMs,
    };
    if (kid != null && kid!.trim().isNotEmpty) {
      m['kid'] = kid;
    }
    return m;
  }

  String toCanonicalJsonString() => canonicalJsonEncode(toCanonicalJsonMap());

  Uint8List toCanonicalJsonBytes() => canonicalJsonUtf8(toCanonicalJsonMap());
}
