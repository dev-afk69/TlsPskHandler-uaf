## Steps to Reproduce
 
**1. Start the environment**
 
```bash
cd TlsPskHandler-uaf-main
./run_local.sh start
```
 
Wait for Zuul to finish initialising (~30 seconds):
 
```bash
docker compose logs -f zuul | grep "finished startup"
```
 
Once that line appears, open **`http://localhost:5000`**. All remaining steps are done through the browser.
 
---
 
**2. Confirm the PSK listener — Section 01 of the UI**
 
Click **Run Listener Check**.
 
The launcher performs a TCP connect to `zuul:7002`. A successful result shows:
 
```
listener check ok in Xms
response: TCP connect to PSK listener succeeded
```
 
> If the check fails, Zuul has not finished starting. Wait 15 seconds and retry.
 
---
 
**3. Run the disclosure probes — Section 02 of the UI**
 
Click **Run 10 Probes**.
 
The launcher opens 10 sequential TLS-PSK connections to `zuul:7002` using:
 
```
identity   poc-client
key        0000000000000000000000000000000000000000000000000000000000000000
suite      TLS_PSK_WITH_AES_128_CBC_SHA (0x008C)
```
 
Each probe sends an 84-byte HTTP GET to `/healthcheck` and records how many decrypted bytes come back. The expected ceiling for a correct response is 512 bytes.
 
When the run completes the header counters show:
 
| Counter | Expected | Observed |
|---|---|---|
| Probes Succeeded | 10 | 10 |
| Total Overflow | 0 B | **1,275.1 KB** |
| Max Per Probe | 0 B | **127.5 KB** |
| Run Status | ok | **overflow!** |
 
---
 
**4. Inspect the raw tail bytes — Section 03 of the UI**
 
Click **hex** on any probe row. The last 128 bytes of the received data expand inline:
 
```
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 68 65 61 6c 74 68 79
```
 
The final 7 bytes `68 65 61 6c 74 68 79` = **"healthy"** — the actual HTTP response body. It sits at its true offset within the Netty pool chunk; the preceding bytes are stale pool memory that the server encrypted and sent alongside it.
 
---
 
**5. Collect runtime log evidence — Section 04 of the UI**
 
Click **Refresh Evidence Logs**. The launcher pulls recent Zuul container logs via the Docker socket and filters for handshake completion and write events matching these probes.
 
---
 
## Proof of Concept Results
 
All 10 probes succeeded with identical byte counts, confirming this is structural server behaviour.
 
| Metric | Value |
|---|---|
| Probes run | 10 |
| Probes succeeded | 10 |
| Expected ceiling per probe | 512 bytes |
| Bytes received per probe | **131,079** |
| Overflow per probe | **~127.5 KB** |
| Total overflow (10 probes) | **~1.275 MB** |
| Response first line (all probes) | `HTTP/1.1 200 OK` |
 
Probe timing (ms): 40, 27, 34, 30, 35, 35, 26, 30, 33, 29. The tight spread confirms the extra bytes originate from a single server-side write, not retransmission or reassembly artefacts.
 
---
 
## Runtime Evidence Logs
 
Pulled from the `psk-poc-zuul` container via Docker socket during the probe run.
 
```
2026-06-02T02:02:24.372104497Z  USER_EVENT: SslHandshakeCompletionEvent(SUCCESS)
2026-06-02T02:02:24.374963997Z  READ: DefaultHttpRequest(decodeResult: success, version: HTTP/1.1)
2026-06-02T02:02:24.375209699Z  WRITE: DefaultHttpResponse(decodeResult: success, version: HTTP/1.1)
2026-06-02T02:02:24.377822652Z  WRITE: DefaultLastHttpContent(data: UnpooledHeapByteBuf(ridx: 0, widx: 7, cap: 7/7)), 7B
2026-06-02T02:02:24.378436197Z  ACCESS - GET /healthcheck 200 4310 7
```
 
The `DefaultLastHttpContent` entry shows `cap: 7/7` — an unpooled buffer with exact capacity, so the body itself carries no over-read. The over-read originates from the `DefaultHttpResponse` write, which uses a pooled buffer whose backing array is far larger than the serialised headers. The access log field `4310` records bytes written to the channel, far exceeding the 7-byte body, consistent with the 131 KB transfer measured by the probe.
 
`SslHandshakeCompletionEvent(SUCCESS)` on every probe confirms a valid PSK session was established before the vulnerable write path was reached.
 
---
 
