import 'dart:convert';
import 'dart:typed_data';

import 'package:otp_crypto/pfs/message/aad.dart';
import 'package:otp_crypto/pfs/message/pfs_header.dart';
import 'package:test/test.dart';

void main() {
  group('AAD canonicalization', () {
    test('build() encodes domain + http json + header json with u32 lengths', () {
      final header = PfsHeader(
        v: 2,
        sid16: _sid16(),
        seq: 1,
        timestampMs: 1700000000000,
        kid: 'pfs-server-id:3',
      );

      final http = HttpContext(
        method: 'post', // should canonicalize to POST
        path: 'api//v1//devices', // should canonicalize to /api/v1/devices
        query: {
          ' z ': '9',
          'a': '1',
          'b': '2',
          '': 'should_be_dropped',
          '  ': 'also_dropped',
        },
        host: 'ExAmPlE.COM',
      );

      final aadBytes = Aad.build(http: http, header: header);

      final parsed = _parseAad(aadBytes);

      expect(parsed.domain, 'otp-pfs-v2/aad/1\n');

      final httpObj = jsonDecode(utf8.decode(parsed.httpJsonBytes));
      expect(httpObj, {
        'm': 'POST',
        'p': '/api/v1/devices',
        'q': {
          'a': '1',
          'b': '2',
          'z': '9',
        },
        'h': 'example.com',
      });

      final headerObj = jsonDecode(utf8.decode(parsed.headerJsonBytes));
      expect(headerObj, {
        'v': 2,
        'sid': base64Encode(_sid16()),
        'seq': 1,
        'ts': 1700000000000,
        'kid': 'pfs-server-id:3',
      });
    });

    test('query sorting is stable and whitespace in query keys is trimmed', () {
      final header = PfsHeader(
        v: 2,
        sid16: _sid16(),
        seq: 7,
        timestampMs: 1700000000123,
      );

      final http1 = HttpContext(
        method: 'GET',
        path: '/x',
        query: {'b': '2', 'a': '1'},
      );

      final http2 = HttpContext(
        method: 'GET',
        path: '/x',
        query: {' a ': '1', 'b': '2'},
      );

      final a1 = _parseAad(Aad.build(http: http1, header: header)).httpJsonBytes;
      final a2 = _parseAad(Aad.build(http: http2, header: header)).httpJsonBytes;

      expect(utf8.decode(a1), utf8.decode(a2));
      expect(jsonDecode(utf8.decode(a1)), {
        'm': 'GET',
        'p': '/x',
        'q': {'a': '1', 'b': '2'},
      });
    });

    test('AAD changes when method/path changes (endpoint binding works)', () {
      final header = PfsHeader(
        v: 2,
        sid16: _sid16(),
        seq: 1,
        timestampMs: 1700000000000,
      );

      final a = Aad.build(
        http: const HttpContext(method: 'GET', path: '/a'),
        header: header,
      );
      final b = Aad.build(
        http: const HttpContext(method: 'POST', path: '/a'),
        header: header,
      );
      final c = Aad.build(
        http: const HttpContext(method: 'GET', path: '/b'),
        header: header,
      );

      expect(_b64(a), isNot(_b64(b)));
      expect(_b64(a), isNot(_b64(c)));
    });

    test('AAD changes when header seq changes (replay binding)', () {
      final http = const HttpContext(method: 'GET', path: '/a');

      final h1 = PfsHeader(
        v: 2,
        sid16: _sid16(),
        seq: 1,
        timestampMs: 1700000000000,
      );
      final h2 = PfsHeader(
        v: 2,
        sid16: _sid16(),
        seq: 2,
        timestampMs: 1700000000000,
      );

      final a1 = Aad.build(http: http, header: h1);
      final a2 = Aad.build(http: http, header: h2);

      expect(_b64(a1), isNot(_b64(a2)));
    });
  });
}

Uint8List _sid16() => Uint8List.fromList(List<int>.generate(16, (i) => i));

String _b64(Uint8List b) => base64Encode(b);

class _AadParsed {
  final String domain;
  final Uint8List httpJsonBytes;
  final Uint8List headerJsonBytes;

  _AadParsed(this.domain, this.httpJsonBytes, this.headerJsonBytes);
}

_AadParsed _parseAad(Uint8List aadBytes) {
  final domainBytes = utf8.encode('otp-pfs-v2/aad/1\n');
  if (aadBytes.length < domainBytes.length + 8) {
    throw StateError('AAD too short');
  }

  final domain = utf8.decode(aadBytes.sublist(0, domainBytes.length));
  var offset = domainBytes.length;

  final httpLen = _readU32be(aadBytes, offset);
  offset += 4;
  final httpJson = aadBytes.sublist(offset, offset + httpLen);
  offset += httpLen;

  final headerLen = _readU32be(aadBytes, offset);
  offset += 4;
  final headerJson = aadBytes.sublist(offset, offset + headerLen);

  return _AadParsed(domain, Uint8List.fromList(httpJson), Uint8List.fromList(headerJson));
}

int _readU32be(Uint8List b, int offset) {
  if (offset + 4 > b.length) throw StateError('out of range');
  return (b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | (b[offset + 3]);
}
