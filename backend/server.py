from __future__ import annotations

import json
import os
import socket
import sys
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any
import time
import urllib.request
import urllib.error


PORT = int(os.environ.get("PORT", "8081"))
MAX_LOGS = int(os.environ.get("MAX_LOGS", "100"))

LOG_LOCK = threading.Lock()
LOGS: deque[dict[str, Any]] = deque(maxlen=MAX_LOGS)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_request(conn: socket.socket) -> bytes:
    # Wait a bit longer for the first byte so proxied requests are captured,
    # but still return quickly once the stream goes idle.
    conn.settimeout(0.25)
    data = b""
    first_byte_deadline = time.time() + 2.0
    try:
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                if not data and time.time() < first_byte_deadline:
                    continue
                break
            if not chunk:
                break
            data += chunk
            conn.settimeout(0.25)
    except socket.timeout:
        pass
    return data


def snapshot_logs() -> list[dict[str, Any]]:
    with LOG_LOCK:
        return list(LOGS)


def clear_logs() -> None:
    with LOG_LOCK:
        LOGS.clear()


def append_connection(raw_text: str, addr: tuple[str, int]) -> dict[str, Any]:
    raw_bytes = raw_text.encode("utf-8", errors="replace")
    entry = {
        "timestamp": utc_now(),
        "from": str(addr),
        "raw": raw_text,
        "request_size": len(raw_bytes),
    }

    with LOG_LOCK:
        LOGS.append(entry)
    return entry


def http_response(status: str, body: bytes, content_type: str = "application/json") -> bytes:
    headers = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body


def handle_api(conn: socket.socket, raw_text: str) -> None:
    first_line = raw_text.split("\r\n", 1)[0]

    if first_line.startswith("GET /logs"):
        body = json.dumps(snapshot_logs()).encode("utf-8")
        conn.sendall(http_response("200 OK", body))
    elif first_line.startswith("POST /clear") or first_line.startswith("GET /clear"):
        clear_logs()
        conn.sendall(http_response("200 OK", b'{"cleared": true}'))
    elif first_line.startswith("GET /health"):
        conn.sendall(http_response("200 OK", b'{"ok": true}', "application/json"))
    else:
        conn.sendall(http_response("404 Not Found", b'{"error": "not found"}'))

    conn.close()


def handle_logger(conn: socket.socket, addr: tuple[str, int], raw_text: str) -> None:
    entry = append_connection(raw_text, addr)

    print(f"\n{'=' * 60}", flush=True)
    print(f"[CONNECTION FROM {addr}]", flush=True)
    print(entry["raw"], flush=True)
    print(f"{'=' * 60}\n", flush=True)
    sys.stdout.flush()

    conn.sendall(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"\r\nOK"
    )
    conn.close()


def handle_connection(conn: socket.socket, addr: tuple[str, int]) -> None:
    raw_bytes = read_request(conn)
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    first_line = raw_text.split("\r\n", 1)[0] if raw_text else ""

    if not raw_text.strip():
        conn.close()
        return

    if first_line.startswith("GET /logs") or first_line.startswith("POST /clear") or first_line.startswith("GET /health"):
        handle_api(conn, raw_text)
        return

    handle_logger(conn, addr, raw_text)
def eureka_register_and_heartbeat() -> None:
    EUREKA_URL = os.environ.get("EUREKA_URL", "http://eureka:8761/eureka")
    APP_NAME = os.environ.get("EUREKA_APP", "API").upper()
    VIP = os.environ.get("EUREKA_VIP", "api")
    instance_id = f"{socket.gethostname()}:{PORT}"

    payload = {
        "instance": {
            "hostName": "backend-service",
            "app": APP_NAME,
            "vipAddress": VIP,
            "secureVipAddress": VIP,
            "ipAddr": "127.0.0.1",
            "status": "UP",
            "port": {"$": PORT, "@enabled": "true"},
            "dataCenterInfo": {
                "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
                "name": "MyOwn",
            },
        }
    }

    headers = {"Content-Type": "application/json"}

    register_url = f"{EUREKA_URL.rstrip('/')}/apps/{APP_NAME}"
    heartbeat_url = f"{EUREKA_URL.rstrip('/')}/apps/{APP_NAME}/{instance_id}"

    def do_post(url: str, data: bytes) -> bool:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 201, 204)
        except Exception:
            return False

    def do_put(url: str) -> bool:
        req = urllib.request.Request(url, data=b"", headers=headers, method="PUT")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False

    # Try to register, with retries
    for attempt in range(1, 21):
        try:
            ok = do_post(register_url, json.dumps(payload).encode("utf-8"))
            if ok:
                print(f"[EUREKA] Registered {APP_NAME} at {register_url}", flush=True)
                break
        except Exception:
            pass
        print(f"[EUREKA] registration attempt {attempt} failed, retrying...", flush=True)
        time.sleep(1)

    # Heartbeat loop
    while True:
        try:
            ok = do_put(heartbeat_url)
            if ok:
                # print minimal heartbeat info
                print(f"[EUREKA] heartbeat OK for {instance_id}", flush=True)
            else:
                print(f"[EUREKA] heartbeat failed for {instance_id}", flush=True)
        except Exception:
            print(f"[EUREKA] heartbeat exception", flush=True)
        time.sleep(30)


def main() -> None:
    # Start Eureka registration/heartbeat thread (best-effort)
    threading.Thread(target=eureka_register_and_heartbeat, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", PORT))
        server_socket.listen(20)
        print(f"[*] Backend raw logger on :{PORT}", flush=True)

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()