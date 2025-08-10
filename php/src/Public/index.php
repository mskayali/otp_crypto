<?php

declare(strict_types=1);

/**
 * Demo endpoint – parses wire headers/body, decrypts request, responds encrypted.
 * ------------------------------------------------------------------------------
 * NOTE:
 * - This file is only a demo. The library itself does NOT create HTTP messages.
 * - It expects the client to send headers {v,w,n,c} and body "<b64_tag>".
 * - On success, it returns the same wire format in the response.
 * - On error, it returns a plain-text generic message with an HTTP error code.
 */

use OtpCrypto\Crypto\OtpCryptoConfig;
use OtpCrypto\Crypto\InternalCryptoException;
use OtpCrypto\Crypto\InvalidMessageException;
use OtpCrypto\Crypto\AuthenticationFailedException;
use OtpCrypto\Crypto\WindowOutOfRangeException;
use OtpCrypto\Crypto\DecryptionFailedException;
use OtpCrypto\Http\Encryptor;
use OtpCrypto\Http\Decryptor;
use OtpCrypto\Models\SecureMessage;

require __DIR__ . '/../../vendor/autoload.php';

// -----------------------------------------------------------------------------
// 1) Bootstrap configuration (shared master key, protocol params)
// -----------------------------------------------------------------------------

/**
 * HINT (production):
 * - Provide a 32+ byte master key via environment variable OTP_MASTER_KEY_B64.
 * - Value should be Base64; we decode it to binary bytes below.
 */
$masterKey = null;
if (($env = getenv('OTP_MASTER_KEY_B64')) !== false && $env !== '') {
    $bin = base64_decode($env, true);
    if ($bin !== false && strlen($bin) >= 32) {
        $masterKey = $bin;
    }
}
if ($masterKey === null) {
    // DEV-ONLY fallback (DO NOT use in production).
    $masterKey = str_repeat("\x42", 32); // 32 bytes of 'B'
}

OtpCryptoConfig::init([
    'masterKey' => $masterKey, // binary
    'salt' => null,            // optional (binary); consider a protocol constant
    'info' => "otp-v1",        // optional (binary); binds keys to this protocol
    'protocolVersion' => 1,
    'windowSeconds' => 30,
    'verificationSkewWindows' => 0, // set 1 to accept [w-1,w,w+1] if needed
]);

// -----------------------------------------------------------------------------
// 2) Read wire headers/body from the HTTP request
// -----------------------------------------------------------------------------

/** Returns request headers as lowercase-keyed array. */
function headers_lower(): array
{
    if (function_exists('getallheaders')) {
        $h = getallheaders() ?: [];
    } else {
        // Fallback for servers without getallheaders()
        $h = [];
        foreach ($_SERVER as $k => $v) {
            if (str_starts_with($k, 'HTTP_')) {
                $name = str_replace(' ', '-', strtolower(str_replace('_', ' ', substr($k, 5))));
                $h[$name] = $v;
            }
        }
    }
    // Normalize to lower-case keys, string values.
    $out = [];
    foreach ($h as $k => $v) {
        $out[strtolower((string)$k)] = is_array($v) ? implode(',', $v) : (string)$v;
    }
    return $out;
}

$headers = headers_lower();
$body    = file_get_contents('php://input');
if (!is_string($body)) {
    $body = '';
}

// Extract protocol headers (case-insensitive on receive)
$wireHeaders = [
    'v' => $headers['v'] ?? null,
    'w' => $headers['w'] ?? null,
    'n' => $headers['n'] ?? null,
    'c' => $headers['c'] ?? null,
];

// -----------------------------------------------------------------------------
// 3) Parse & decrypt request → build response JSON → encrypt response
// -----------------------------------------------------------------------------

try {
    // Parse request message
    $reqMsg = SecureMessage::fromWire($wireHeaders, $body);

    // Verify & decrypt
    $dec = new Decryptor();
    $plaintext = $dec->unprotect($reqMsg);

    // Application logic (demo): echo payload back with server timestamp
    $reqText = $plaintext; // binary string; could be JSON
    $respPayload = json_encode([
        'ok'         => true,
        'echo'       => $reqText,
        'serverTime' => gmdate('c'),
    ], JSON_UNESCAPED_SLASHES);

    if ($respPayload === false) {
        throw new InternalCryptoException(); // keep generic
    }

    // Encrypt response
    $enc = new Encryptor();
    $respMsg = $enc->protect($respPayload);

    // Serialize to wire
    $respHeaders = $respMsg->toWireHeaders();
    $respBody    = $respMsg->toWireBody();

    // -------------------------------------------------------------------------
    // 4) Send response (headers: v,w,n,c ; body: <b64_tag>)
    // -------------------------------------------------------------------------
    header('Content-Type: text/plain; charset=utf-8');

    // IMPORTANT: send the protocol headers as-is (lowercase keys).
    // Depending on server, header names may be capitalized by the stack,
    // but the client should treat them case-insensitively.
    header('v: ' . $respHeaders['v']);
    header('w: ' . $respHeaders['w']);
    header('n: ' . $respHeaders['n']);
    header('c: ' . $respHeaders['c']);

    // Body is the Base64 tag
    echo $respBody . "\n";
    exit(0);
} catch (InvalidMessageException $e) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Invalid message';
    exit(0);
} catch (WindowOutOfRangeException $e) {
    http_response_code(401);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Expired or not yet valid';
    exit(0);
} catch (AuthenticationFailedException $e) {
    http_response_code(401);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Authentication failed';
    exit(0);
} catch (DecryptionFailedException $e) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Decryption failed';
    exit(0);
} catch (\Throwable $e) {
    // Generic internal error (do not leak details)
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Internal error';
    exit(0);
}
