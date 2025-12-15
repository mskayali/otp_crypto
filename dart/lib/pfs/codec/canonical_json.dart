import 'dart:convert';
import 'dart:typed_data';

/// Minimal canonical JSON encoder for interop (Dart <-> PHP).
///
/// Rules:
/// - Map keys MUST be String.
/// - Map keys are sorted lexicographically.
/// - No whitespace.
/// - Only supports: null, bool, int, String, List, Map<String, dynamic>.
/// - Doubles are rejected (avoid cross-language number formatting differences).
///
/// This is close in spirit to RFC 8785 (JCS), but intentionally minimal for our payloads.
String canonicalJsonEncode(Object? value) {
  final sb = StringBuffer();
  _writeValue(sb, value);
  return sb.toString();
}

Uint8List canonicalJsonUtf8(Object? value) {
  final s = canonicalJsonEncode(value);
  return Uint8List.fromList(utf8.encode(s));
}

void _writeValue(StringBuffer sb, Object? value) {
  if (value == null) {
    sb.write('null');
    return;
  }
  if (value is bool) {
    sb.write(value ? 'true' : 'false');
    return;
  }
  if (value is int) {
    sb.write(value.toString());
    return;
  }
  if (value is double) {
    throw const FormatException('canonical JSON does not allow double');
  }
  if (value is String) {
    // Use Dart's JSON string escaping for correctness.
    sb.write(jsonEncode(value));
    return;
  }
  if (value is Uint8List) {
    throw const FormatException('canonical JSON does not allow raw bytes; encode as base64 string');
  }
  if (value is List) {
    sb.write('[');
    for (var i = 0; i < value.length; i++) {
      if (i > 0) sb.write(',');
      _writeValue(sb, value[i]);
    }
    sb.write(']');
    return;
  }
  if (value is Map) {
    // Enforce String keys and sort.
    final keys = <String>[];
    value.forEach((k, _) {
      if (k is! String) {
        throw const FormatException('canonical JSON map keys must be String');
      }
      keys.add(k);
    });
    keys.sort();

    sb.write('{');
    for (var i = 0; i < keys.length; i++) {
      if (i > 0) sb.write(',');
      final k = keys[i];
      sb.write(jsonEncode(k));
      sb.write(':');
      _writeValue(sb, value[k]);
    }
    sb.write('}');
    return;
  }

  throw FormatException('canonical JSON unsupported type: ${value.runtimeType}');
}
