import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../codec/canonical_json.dart';
import 'client_hello.dart';
import 'server_hello.dart';

/// Transcript utilities for v2 handshake.
///
/// Design goals:
/// - Deterministic, cross-language stable transcript bytes (Dart <-> PHP)
/// - Domain separation to avoid cross-protocol confusion
///
/// Transcript bytes =
///   UTF8("otp-pfs-v2/transcript/1\n") ||
///   u32be(len(ClientHelloCanonicalJson)) || ClientHelloCanonicalJson ||
///   u32be(len(ServerHelloCanonicalJsonNoSig)) || ServerHelloCanonicalJsonNoSig
///
/// The transcript hash is SHA-256 over transcript bytes.
///
/// NOTE:
/// - ServerHello is included WITHOUT the 'sig' field when hashing.
/// - The signature is verified over the transcript hash.
final class HandshakeTranscript {
  static const String _domain = 'otp-pfs-v2/transcript/1\n';

  final ClientHello clientHello;
  final ServerHello serverHello;

  const HandshakeTranscript({
    required this.clientHello,
    required this.serverHello,
  });

  /// Canonical JSON bytes used for transcript hashing.
  Uint8List clientHelloCanonicalBytes() => clientHello.encode();

  /// Canonical ServerHello JSON bytes excluding signature.
  Uint8List serverHelloCanonicalBytesNoSig() => canonicalJsonUtf8(serverHello.toCanonicalJson(includeSignature: false));

  /// Full transcript bytes.
  Uint8List bytes() {
    final c = clientHelloCanonicalBytes();
    final s = serverHelloCanonicalBytesNoSig();

    final b = BytesBuilder(copy: false);
    b.add(utf8.encode(_domain));
    b.add(_u32be(c.length));
    b.add(c);
    b.add(_u32be(s.length));
    b.add(s);
    return b.toBytes();
  }

  /// SHA-256 hash of transcript bytes.
  Future<Uint8List> hashSha256() async {
    final digest = await Sha256().hash(bytes());
    return Uint8List.fromList(digest.bytes);
  }

  /// Session identifier (sid) derived from transcript:
  /// first 16 bytes of SHA-256(transcript).
  Future<Uint8List> sid16() async {
    final h = await hashSha256();
    return Uint8List.sublistView(h, 0, 16);
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
