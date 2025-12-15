import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../errors.dart';
import '../handshake/handshake_client.dart';
import '../message/aad.dart';
import '../message/pfs_envelope.dart';
import '../message/pfs_header.dart';
import '../pfs_config.dart';
import '../server_identity.dart';

/// Client-side PFS session (v2):
/// - Maintains sending sequence number (seq)
/// - Tracks received seqs for replay protection (optional sliding window)
/// - Provides protect()/unprotect() using AEAD + canonical AAD binding
///
/// Notes:
/// - Nonce is derived deterministically from (nonceBase12, seq) so we don't
///   need to send a nonce in the payload.
/// - Replay protection here is *client-side*. Server must also enforce it.
final class PfsSession {
  static const int protocolVersion = 2;

  // Hard caps (defense-in-depth against memory/CPU abuse).
  static const int maxCiphertextBytes = 1024 * 1024; // 1 MiB
  static const int maxPlaintextBytes = 1024 * 1024; // 1 MiB

  final PfsConfig config;

  /// Session id (16 bytes) derived from transcript.
  final Uint8List sid16;

  /// AEAD key (32 bytes).
  final SecretKey _aeadKey;

  /// 12-byte base nonce material.
  final Uint8List _nonceBase12;

  /// The server identity that authenticated this session (handshake).
  final ServerIdentityRef serverIdentity;

  /// Negotiated suite string.
  final String suite;

  /// Next outgoing sequence number (u64, starts at 1).
  int _sendSeq = 1;

  /// Replay/ordering tracking for incoming messages.
  int _rxMaxSeq = 0;
  late final _ReplayWindow _replay;

  PfsSession._({
    required this.config,
    required this.sid16,
    required SecretKey aeadKey,
    required Uint8List nonceBase12,
    required this.serverIdentity,
    required this.suite,
  })  : _aeadKey = aeadKey,
        _nonceBase12 = nonceBase12 {
    if (sid16.length != 16) {
      throw PfsErrors.invalidInput('sid must be 16 bytes');
    }
    if (_nonceBase12.length != 12) {
      throw PfsErrors.invalidInput('nonceBase must be 12 bytes');
    }
    _replay = _ReplayWindow(size: config.replayWindowSize);
  }

  /// Create a session from a successful handshake result.
  factory PfsSession.fromHandshake({
    required PfsConfig config,
    required HandshakeResult result,
  }) {
    return PfsSession._(
      config: config,
      sid16: result.sid16,
      aeadKey: result.aeadKey,
      nonceBase12: result.nonceBase12,
      serverIdentity: result.serverIdentity,
      suite: result.suite,
    );
  }

  /// Returns the next outgoing sequence number (for diagnostics).
  int get nextSendSeq => _sendSeq;

  /// Protects plaintext into (header + envelope).
  ///
  /// HTTP context is bound into AAD so ciphertext cannot be replayed to a
  /// different endpoint/method without failing authentication.
  Future<({PfsHeader header, PfsEnvelope envelope})> protect({
    required Uint8List plaintext,
    required HttpContext http,
    int? nowMs,
  }) async {
    try {
      if (plaintext.length > maxPlaintextBytes) {
        throw PfsErrors.payloadTooLarge('plaintext too large');
      }

      final ts = nowMs ?? DateTime.now().millisecondsSinceEpoch;
      final seq = _sendSeq;
      _sendSeq = _incU64(_sendSeq);

      final header = PfsHeader(
        v: protocolVersion,
        sid16: sid16,
        seq: seq,
        timestampMs: ts,
        kid: serverIdentity.toWireKid(),
      );

      final aad = Aad.build(http: http, header: header);

      final nonce = _nonceForSeq(seq);
      final secretBox = await config.cipher.encrypt(
        plaintext,
        secretKey: _aeadKey,
        nonce: nonce,
        aad: aad,
      );

      final ct = Uint8List.fromList(secretBox.cipherText);
      final tag = Uint8List.fromList(secretBox.mac.bytes);

      if (ct.length > maxCiphertextBytes) {
        throw PfsErrors.payloadTooLarge('ciphertext too large');
      }

      // We do NOT send nonce; derived from seq.
      final envelope = PfsEnvelope(
        ct: ct,
        tag: tag,
      );

      return (header: header, envelope: envelope);
    } on PfsException {
      rethrow;
    } on SecretBoxAuthenticationError catch (e) {
      throw PfsErrors.authFailed(e);
    } on FormatException catch (e) {
      throw PfsErrors.invalidInput(e.message);
    } on StateError catch (e) {
      throw PfsErrors.unknown(e.message);
    } catch (e) {
      throw PfsErrors.unknown(e);
    }
  }

  /// Unprotects (header + envelope) into plaintext.
  ///
  /// Enforces:
  /// - version, sid match
  /// - timestamp skew (config.maxClockSkew)
  /// - replay protection via seq tracking (strict or sliding window)
  /// - AEAD authentication over canonical AAD (HTTP + header)
  Future<Uint8List> unprotect({
    required PfsHeader header,
    required PfsEnvelope envelope,
    required HttpContext http,
    int? nowMs,
  }) async {
    try {
      _validateHeaderBasic(header);
      _validateEnvelopeBasic(envelope);

      final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
      final skew = (now - header.timestampMs).abs();
      if (skew > config.maxClockSkew.inMilliseconds) {
        throw PfsErrors.timestampSkew('skew ${skew}ms');
      }

      _enforceReplay(header.seq);

      final aad = Aad.build(http: http, header: header);
      final nonce = _nonceForSeq(header.seq);

      final secretBox = SecretBox(
        envelope.ct,
        nonce: nonce,
        mac: Mac(envelope.tag),
      );

      final pt = await config.cipher.decrypt(
        secretBox,
        secretKey: _aeadKey,
        aad: aad,
      );

      return Uint8List.fromList(pt);
    } on PfsException {
      rethrow;
    } on SecretBoxAuthenticationError {
      // Do not leak detail.
      throw PfsErrors.authFailed();
    } on FormatException catch (e) {
      throw PfsErrors.invalidInput(e.message);
    } on StateError catch (e) {
      throw PfsErrors.unknown(e.message);
    } catch (e) {
      throw PfsErrors.unknown(e);
    }
  }

  void _validateHeaderBasic(PfsHeader header) {
    if (header.v != protocolVersion) {
      throw PfsErrors.unsupportedVersion('v=${header.v}');
    }
    if (!_bytesEqual(header.sid16, sid16)) {
      throw PfsErrors.sidMismatch();
    }
    if (header.seq <= 0) {
      throw PfsErrors.invalidInput('invalid seq');
    }
    if (header.timestampMs <= 0) {
      throw PfsErrors.invalidInput('invalid timestamp');
    }
  }

  void _validateEnvelopeBasic(PfsEnvelope env) {
    if (env.ct.isEmpty) {
      throw PfsErrors.invalidInput('empty ciphertext');
    }
    if (env.ct.length > maxCiphertextBytes) {
      throw PfsErrors.payloadTooLarge('ciphertext too large');
    }
    if (env.tag.isEmpty) {
      throw PfsErrors.invalidInput('empty tag');
    }
  }

  /// Replay enforcement strategy:
  /// - If replayWindowSize == 0: require strictly increasing seq (seq > maxSeen).
  /// - Else: accept within a sliding window, reject duplicates.
  void _enforceReplay(int seq) {
    if (config.replayWindowSize == 0) {
      if (seq <= _rxMaxSeq) {
        throw PfsErrors.replayDetected();
      }
      _rxMaxSeq = seq;
      return;
    }

    if (!_replay.accept(seq, maxSeq: _rxMaxSeq)) {
      throw PfsErrors.replayDetected();
    }
    if (seq > _rxMaxSeq) _rxMaxSeq = seq;
  }

  /// Derive a 96-bit nonce as:
  /// nonce = nonceBase12 XOR (0x0000000000000000 || u64be(seq)) in last 8 bytes.
  Uint8List _nonceForSeq(int seq) {
    final nb = Uint8List.fromList(_nonceBase12);
    final s = _u64be(seq);
    for (var i = 0; i < 8; i++) {
      nb[4 + i] ^= s[i];
    }
    return nb;
  }

  static Uint8List _u64be(int n) {
    if (n < 0 || n > 0xFFFFFFFFFFFFFFFF) {
      throw RangeError('seq out of u64 range');
    }
    final out = Uint8List(8);
    out[0] = (n >>> 56) & 0xFF;
    out[1] = (n >>> 48) & 0xFF;
    out[2] = (n >>> 40) & 0xFF;
    out[3] = (n >>> 32) & 0xFF;
    out[4] = (n >>> 24) & 0xFF;
    out[5] = (n >>> 16) & 0xFF;
    out[6] = (n >>> 8) & 0xFF;
    out[7] = n & 0xFF;
    return out;
  }

  static int _incU64(int n) {
    final next = n + 1;
    if (next > 0xFFFFFFFFFFFFFFFF) return 1;
    return next;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.lengthInBytes != b.lengthInBytes) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}

/// Simple replay window tracker.
/// - size == 0 => disabled (handled by caller)
/// - Otherwise tracks last [size] sequence numbers as a bitset relative to maxSeq.
///
/// accept(seq):
/// - Reject if seq too old (<= maxSeq - size)
/// - Reject if already seen in window
/// - Accept and mark seen
final class _ReplayWindow {
  final int size;
  late final Uint8List _bits; // bitset

  _ReplayWindow({required this.size}) {
    if (size < 0) throw ArgumentError.value(size, 'size');
    final bytes = ((size + 7) ~/ 8);
    _bits = Uint8List(bytes);
  }

  bool accept(int seq, {required int maxSeq}) {
    if (size == 0) return true;

    if (seq > maxSeq) {
      final delta = seq - maxSeq;
      _shift(delta);
      _setSeen(0);
      return true;
    }

    final offset = maxSeq - seq;
    if (offset >= size) return false;

    if (_isSeen(offset)) return false;
    _setSeen(offset);
    return true;
  }

  void _shift(int delta) {
    if (delta <= 0) return;
    if (delta >= size) {
      _bits.fillRange(0, _bits.length, 0);
      return;
    }

    final old = Uint8List.fromList(_bits);
    _bits.fillRange(0, _bits.length, 0);

    for (var off = 0; off < size; off++) {
      final wasSeen = _getBit(old, off);
      final newOff = off + delta;
      if (wasSeen && newOff < size) {
        _setBit(_bits, newOff, true);
      }
    }
  }

  bool _isSeen(int offset) => _getBit(_bits, offset);

  void _setSeen(int offset) => _setBit(_bits, offset, true);

  static bool _getBit(Uint8List buf, int bitIndex) {
    final byteIndex = bitIndex >>> 3;
    final bit = bitIndex & 7;
    return (buf[byteIndex] & (1 << bit)) != 0;
  }

  static void _setBit(Uint8List buf, int bitIndex, bool value) {
    final byteIndex = bitIndex >>> 3;
    final bit = bitIndex & 7;
    final mask = 1 << bit;
    final v = buf[byteIndex];
    buf[byteIndex] = value ? (v | mask) : (v & ~mask);
  }
}
