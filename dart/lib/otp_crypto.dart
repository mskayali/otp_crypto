/// Package entrypoint.
///
/// v1: Symmetric protection (AES-CBC + HMAC-SHA256 + HKDF) based on shared masterKey.
/// v2: PFS session protocol (X25519 + HKDF + AEAD) with Vault-signed handshake.
///
/// Keep this file as the single import surface for consumers.
library otp_crypto;

export 'otp_crypto/decryptor.dart';
export 'otp_crypto/encryptor.dart';
export 'otp_crypto/errors.dart';
// ----------------------------
// v1 exports
// ----------------------------
export 'otp_crypto/otp_crypto_config.dart';
export 'pfs/crypto/aead.dart';
export 'pfs/crypto/signature.dart';
export 'pfs/errors.dart';
export 'pfs/handshake/client_hello.dart';
export 'pfs/handshake/handshake_client.dart';
export 'pfs/handshake/key_schedule.dart';
export 'pfs/handshake/server_hello.dart';
export 'pfs/handshake/transcript.dart';
export 'pfs/message/aad.dart';
export 'pfs/message/pfs_envelope.dart';
export 'pfs/message/pfs_header.dart';
// ----------------------------
// v2/PFS exports
// ----------------------------
export 'pfs/pfs_config.dart';
export 'pfs/server_identity.dart';
export 'pfs/session/pfs_session.dart';
