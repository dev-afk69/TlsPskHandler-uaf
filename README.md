# Zuul TlsPskHandler — Use-After-Free & Memory Disclosure PoC
 
Reproduces the Use-After-Free and buffer over-read in `TlsPskHandler` described in the vulnerability report.
A single TLS-PSK connection returns the full Netty pool chunk (up to 16 KB) instead of the actual HTTP
response, leaking stale cross-channel data to the caller.
 
---
 
## What the bug is
 
`TlsPskUtils.getAppDataBytesAndRelease` calls `byteBufMsg.array()` which returns the raw backing
array from Netty's `PooledByteBufAllocator` — not the slice of readable bytes. It then immediately
calls `safeRelease`, freeing the buffer back to the pool. `TlsPskHandler.write` then passes the
freed array to `writeApplicationData(appDataBytes, 0, appDataBytes.length)`, where `length` is the
pool chunk capacity (e.g. 2048, 4096, 16384 bytes), not `readableBytes()`.
 
Two consequences:
 
1. **Use-After-Free.** The array is freed before encryption. The pool can reallocate it to another
   channel mid-write, creating a race between the encryption thread and the new owner.
2. **Buffer over-read.** The encrypted TLS record contains the real HTTP payload followed by
   however many stale bytes fill the rest of the pool chunk — HTTP headers, cookies, and
   authorization tokens from prior requests on that buffer, sent in plaintext after decryption.
---
 
## Services
 
| Container            | Purpose                                       | Port  |
|----------------------|-----------------------------------------------|-------|
| `psk-poc-zuul`       | Zuul sample with PSK listener and the bug     | 7001 (HTTP), 7002 (PSK) |
| `psk-poc-backend`    | Raw HTTP sink for proxied requests            | 8081  |
| `psk-poc-eureka`     | Minimal Eureka stub for service discovery     | 8761  |
| `psk-poc-launcher`   | Flask UI that runs the PSK disclosure probes  | 5000  |
 
---
 
## Files changed from the original SSE PoC
 
**Delete these files** (SSE-specific, not used):
 
- `launcher/static/app.js` — replaced entirely
- `launcher/static/styles.css` — replaced entirely
- `launcher/templates/index.html` — replaced entirely
- `launcher/app.py` — replaced entirely
- `launcher/requirements.txt` — replaced
- `launcher/Dockerfile` — replaced
- `docker-compose.yml` — replaced
- `run_local.sh` — replaced
- `render.yaml` — delete (deploy config for Render.com, not needed)
**Add these files:**
 
- `zuul/zuul-core/src/main/java/com/netflix/zuul/netty/server/psk/HardcodedPskProvider.java`
**Modify these files:**
 
- `zuul/zuul-sample/src/main/java/com/netflix/zuul/sample/SampleServerStartup.java`
  — adds `PSK` to the `ServerType` enum, adds PSK listener on port 7002
All other files under `zuul/` are untouched upstream source.
 
---
 
## Quick start
 
```
./run_local.sh start
```
 
Wait for all four containers to reach a healthy state (Zuul takes ~30 s to start):
 
```
docker compose -f docker-compose.yml logs -f zuul
# wait for: "Zuul Sample: finished startup"
```
 
Open the launcher:
 
```
http://localhost:5000
```
 
### Step 1 — Verify the PSK handshake
 
Click **run handshake check**. This opens one TLS 1.2 PSK connection to `zuul:7002` using
the 32-byte zero key. A successful response confirms the PSK listener is reachable.
 
### Step 2 — Run the disclosure probes
 
Click **run 10 probes**. Each probe sends an 84-byte HTTP GET and measures how many decrypted
bytes come back. Correct behaviour is ~200 bytes. The bug causes the server to return the full
Netty pool chunk. The **overflow bytes** column shows how many extra bytes were received beyond
the expected ceiling. Click **hex** on any row to see the raw tail bytes — those bytes are not
part of the HTTP response.
 
### Step 3 — Inspect the output
 
`total leaked bytes` in the header counters is the cumulative over-read across all probes.
`max per probe` is the single-probe high-water mark. A non-zero value on either counter is
evidence of the bug. In a loaded server the tail bytes will contain readable HTTP data from
other connections.
 
---
 
## Verifying with Netty leak detection
 
```
./run_local.sh leak-detect
docker compose -f docker-compose.yml logs -f zuul | grep -i leak
```
 
---
 
## Stop
 
```
./run_local.sh stop
```
 
---
 
## PSK credentials used by the PoC
 
```
identity   poc-client
key        00000000000000000000000000000000
           00000000000000000000000000000000  (32 zero bytes)
suite      TLS_PSK_WITH_AES_128_CBC_SHA (0x008C)
```
 
Defined in `HardcodedPskProvider.POC_PSK` (Java) and `POC_PSK = bytes(32)` (Python).
 
---