"use strict";

// ── DOM refs ──────────────────────────────────────────────────────────────────

const handshakeBtn   = document.getElementById("handshake-btn");
const handshakeRes   = document.getElementById("handshake-result");
const floodBtn       = document.getElementById("flood-btn");
const clearBtn       = document.getElementById("clear-btn");
const floodStatus    = document.getElementById("flood-status");
const progressFill   = document.getElementById("progress-fill");
const progressLabel  = document.getElementById("progress-label");
const floodSummary   = document.getElementById("flood-summary");
const resultsPanel   = document.getElementById("results-panel");
const resultsBody    = document.getElementById("results-body");

const statProbes     = document.getElementById("stat-probes-val");
const statOverflow   = document.getElementById("stat-overflow-val");
const statMax        = document.getElementById("stat-max-val");
const statStatus     = document.getElementById("stat-status-val");

const sumSuccess     = document.getElementById("sum-success");
const sumFail        = document.getElementById("sum-fail");
const sumOverflow    = document.getElementById("sum-overflow");
const sumMax         = document.getElementById("sum-max");

// ── Utilities ─────────────────────────────────────────────────────────────────

function fmtBytes(n) {
  if (n === 0 || n == null) return "0 B";
  if (n < 1024) return n + " B";
  return (n / 1024).toFixed(1) + " KB";
}

function setStatus(text, cls) {
  statStatus.textContent = text;
  statStatus.className = "stat-value" + (cls ? " " + cls : "");
}

// ── Handshake check ───────────────────────────────────────────────────────────

handshakeBtn.addEventListener("click", async () => {
  handshakeBtn.disabled = true;
  handshakeRes.className = "result-block";
  handshakeRes.textContent = "connecting…";
  setStatus("connecting", "");

  try {
    const res = await fetch("/run/handshake", { method: "POST" });
    const data = await res.json();

    if (data.ok) {
      handshakeRes.className = "result-block is-ok";
      handshakeRes.textContent =
        `handshake ok — ${data.bytes_received} bytes received in ${data.elapsed_ms}ms\n` +
        `response: ${data.response_first_line}`;
      setStatus("connected", "is-ok");
    } else {
      handshakeRes.className = "result-block is-err";
      handshakeRes.textContent = "error: " + (data.error || "unknown");
      setStatus("error", "is-overflow");
    }
  } catch (err) {
    handshakeRes.className = "result-block is-err";
    handshakeRes.textContent = "fetch failed: " + err.message;
    setStatus("error", "is-overflow");
  }

  handshakeBtn.disabled = false;
});

// ── Flood probes ──────────────────────────────────────────────────────────────

floodBtn.addEventListener("click", async () => {
  floodBtn.disabled = true;
  clearBtn.disabled = true;
  floodStatus.classList.remove("hidden");
  floodSummary.classList.add("hidden");
  resultsPanel.style.display = "none";
  resultsBody.innerHTML = "";
  progressFill.style.width = "0%";
  setStatus("running", "");

  try {
    const res = await fetch("/run/leak", { method: "POST" });
    const data = await res.json();

    if (!data.ok) {
      setStatus("error", "is-overflow");
      return;
    }

    const results = data.results || [];
    const total = results.length;

    // Render rows
    resultsPanel.style.display = "";
    results.forEach((r, i) => {
      renderRow(r, total);
      const pct = Math.round(((i + 1) / total) * 100);
      progressFill.style.width = pct + "%";
      progressLabel.textContent = `ran ${i + 1} / ${total} probes`;
    });

    // Update header stats
    statProbes.textContent    = data.successes;
    statOverflow.textContent  = fmtBytes(data.total_overflow_bytes || 0);
    statMax.textContent       = fmtBytes(data.max_overflow_bytes || 0);

    const hasOverflow = (data.total_overflow_bytes || 0) > 0;
    setStatus(hasOverflow ? "overflow!" : "ok", hasOverflow ? "is-overflow" : "is-ok");

    // Summary strip
    sumSuccess.textContent  = data.successes;
    sumFail.textContent     = data.failures;
    sumOverflow.textContent = fmtBytes(data.total_overflow_bytes || 0);
    sumMax.textContent      = fmtBytes(data.max_overflow_bytes || 0);
    floodSummary.classList.remove("hidden");

  } catch (err) {
    setStatus("fetch error", "is-overflow");
    console.error(err);
  }

  floodStatus.classList.add("hidden");
  floodBtn.disabled = false;
  clearBtn.disabled = false;
});

// ── Clear ─────────────────────────────────────────────────────────────────────

clearBtn.addEventListener("click", () => {
  resultsBody.innerHTML = "";
  resultsPanel.style.display = "none";
  floodSummary.classList.add("hidden");
  statProbes.textContent   = "0";
  statOverflow.textContent = "0 B";
  statMax.textContent      = "0 B";
  setStatus("idle", "");
});

// ── Row renderer ─────────────────────────────────────────────────────────────

function renderRow(r, total) {
  const overflow = r.overflow_bytes || 0;
  const hasOverflow = overflow > 0;

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${r.index}</td>
    <td>${r.ok
      ? '<span class="badge badge-ok">ok</span>'
      : '<span class="badge badge-err">err</span>'
    }</td>
    <td>${r.ok ? r.bytes_received : "—"}</td>
    <td class="${hasOverflow ? "overflow-cell" : "zero-overflow"}">${
      r.ok ? fmtBytes(overflow) : (r.error || "—")
    }</td>
    <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${
      r.response_first_line || ""
    }">${r.response_first_line || "—"}</td>
    <td>${r.elapsed_ms || "—"}</td>
    <td>${r.ok && r.tail_hex
      ? `<button class="expand-btn" data-idx="${r.index}">hex</button>`
      : ""
    }</td>
  `;
  resultsBody.appendChild(tr);

  // Hex expand row
  if (r.ok && r.tail_hex) {
    const hexRow = document.createElement("tr");
    hexRow.className = "hex-row hidden";
    hexRow.id = "hex-row-" + r.index;
    const hexTd = document.createElement("td");
    hexTd.colSpan = 7;
    hexTd.innerHTML = `<div class="hex-block"><div class="hex-label">tail hex (last 128 bytes received)</div>${
      formatHex(r.tail_hex)
    }</div>`;
    hexRow.appendChild(hexTd);
    resultsBody.appendChild(hexRow);
  }
}

// ── Hex expand toggle ─────────────────────────────────────────────────────────

resultsBody.addEventListener("click", (e) => {
  if (!e.target.matches(".expand-btn")) return;
  const idx = e.target.dataset.idx;
  const row = document.getElementById("hex-row-" + idx);
  if (!row) return;
  const hidden = row.classList.toggle("hidden");
  e.target.textContent = hidden ? "hex" : "hide";
});

// ── Hex formatter ─────────────────────────────────────────────────────────────

function formatHex(hexStr) {
  let out = "";
  for (let i = 0; i < hexStr.length; i += 64) {
    const chunk = hexStr.slice(i, i + 64);
    const spaced = chunk.match(/.{1,2}/g).join(" ");
    const ascii = chunk.match(/.{1,2}/g).map(b => {
      const c = parseInt(b, 16);
      return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
    }).join("");
    out += spaced.padEnd(49) + "  " + ascii + "\n";
  }
  return out;
}
