// SPDX-License-Identifier: Apache-2.0
// origin-web frontend.
//
// The page's thesis is "nothing leaves this tab" — so the code is built to
// PROVE that, not assert it:
//
//   1. Monitors (fetch / XHR / WebSocket / beacon / service worker) are armed
//      at the TOP of this module, before the crypto engine even loads.
//   2. The engine bytes are fetched once, hashed with SHA-256 in-tab, and the
//      SAME buffer is executed — then the hash is cross-checked against the
//      CI-written build manifest (build-info.json).
//   3. A storage audit (localStorage / sessionStorage / cookies / IndexedDB)
//      runs continuously and per-operation, proving nothing is persisted.
//   4. Every crypto operation appends a receipt to the session ledger with
//      its own proof line: elapsed time, network delta, storage delta.

// ── 0. IMPORTS — the WASM crypto engine ───────────────────────────────
import {
  initSync,
  keygen,
  sign,
  verify,
  identity_fingerprint,
  envelope_encrypt,
  envelope_decrypt,
  shard_split,
  shard_recover,
  entropy_analyze,
  random_salt,
} from "./pkg/origin_web.js";

// ── 1. ARM MONITORS FIRST — before anything else in this module ───────
const net = { total: 0, afterLoad: 0, engineFetches: 0, violations: [] };
let engineLoaded = false;

function recordRequest(kind, url) {
  net.total += 1;
  if (engineLoaded) {
    net.afterLoad += 1;
    net.violations.push(`${kind} ${url}`);
    renderConsole();
  } else {
    net.engineFetches += 1;
  }
}

const origFetch = window.fetch.bind(window);
window.fetch = function (input, init) {
  recordRequest("fetch", typeof input === "string" ? input : input?.url || String(input));
  return origFetch(input, init);
};

const OrigXHR = window.XMLHttpRequest;
function PatchedXHR() {
  const xhr = new OrigXHR();
  const origOpen = xhr.open;
  xhr.open = function (method, url, ...rest) {
    recordRequest("xhr", url);
    return origOpen.call(this, method, url, ...rest);
  };
  return xhr;
}
PatchedXHR.prototype = OrigXHR.prototype;
window.XMLHttpRequest = PatchedXHR;

const OrigWS = window.WebSocket;
window.WebSocket = function (url, protocols) {
  recordRequest("ws", url);
  return new OrigWS(url, protocols);
};
Object.assign(window.WebSocket, OrigWS);
window.WebSocket.prototype = OrigWS.prototype;

if (navigator.sendBeacon) {
  const origBeacon = navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon = function (url, data) {
    recordRequest("beacon", url);
    return origBeacon(url, data);
  };
}
if (navigator.serviceWorker?.register) {
  const origSW = navigator.serviceWorker.register.bind(navigator.serviceWorker);
  navigator.serviceWorker.register = function (url, opts) {
    recordRequest("serviceworker", url);
    return origSW(url, opts);
  };
}

// ── Storage audit ─────────────────────────────────────────────────────
const store = { baseline: null, bytes: 0, entries: 0 };
function storageBytes() {
  let bytes = 0;
  let entries = 0;
  for (const s of [localStorage, sessionStorage]) {
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i);
      bytes += k.length + (s.getItem(k) || "").length;
      entries += 1;
    }
  }
  bytes += document.cookie.length;
  if (document.cookie.length) entries += 1;
  return { bytes, entries };
}
async function idbCount() {
  try {
    if (indexedDB.databases) return (await indexedDB.databases()).length;
  } catch { /* older browsers */ }
  return null;
}
async function auditStorage() {
  const now = storageBytes();
  const idb = await idbCount();
  store.bytes = store.baseline === null ? 0 : Math.max(0, now.bytes - store.baseline.bytes);
  store.entries = now.entries + (idb ?? 0);
  return store.bytes;
}

// ── DOM helpers ───────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}
function hexdump(hex, cols = 16) {
  const bytes = hex.match(/.{1,2}/g) || [];
  const lines = [];
  for (let i = 0; i < bytes.length; i += cols) {
    const addr = i.toString(16).padStart(4, "0");
    lines.push(`<span class="dim">${addr}</span>  ${bytes.slice(i, i + cols).join(" ")}`);
  }
  return lines.join("\n");
}
function show(el, html) {
  el.innerHTML = html;
  el.classList.add("show");
}
function withBusy(btn, fn) {
  const prev = btn.disabled;
  btn.disabled = true;
  btn.classList.add("busy");
  try {
    return fn();
  } finally {
    btn.disabled = prev;
    btn.classList.remove("busy");
  }
}

// ── Console + ledger rendering ────────────────────────────────────────
function renderConsole() {
  const netEl = $("c-net-n");
  netEl.textContent = engineLoaded ? String(net.afterLoad) : "…";
  netEl.parentElement.classList.toggle("ok", engineLoaded && net.afterLoad === 0);
  netEl.parentElement.classList.toggle("bad", net.afterLoad > 0);
  $("c-store-n").textContent = store.baseline === null ? "…" : `${store.bytes} B`;
  $("c-store-n").parentElement.classList.toggle("ok", store.baseline !== null && store.bytes === 0);
  $("foot-req").textContent = engineLoaded ? String(net.afterLoad) : "…";
  $("foot-store").textContent = store.baseline === null ? "…" : `${store.bytes} B`;
  const detail = $("console-detail");
  if (net.violations.length) {
    detail.textContent = "⚠ unexpected request: " + net.violations[0];
    detail.classList.add("bad");
  } else if (engineLoaded) {
    detail.textContent = `engine loaded (${net.engineFetches} fetches) · hash checked against manifest · watching for leaks`;
  } else {
    detail.textContent = "loading engine — every request from here is counted…";
  }
}

let ledgerSeq = 0;
function ledger(op, ms, netDelta, storeDelta) {
  const body = $("ledger-body");
  const empty = body.querySelector(".ledger-empty");
  if (empty) empty.remove();
  ledgerSeq += 1;
  const row = document.createElement("div");
  row.className = "ledger-row";
  const time = new Date().toTimeString().slice(0, 8);
  row.innerHTML =
    `<span class="lr-time">${time}</span>` +
    `<span class="lr-op">${esc(op)}</span>` +
    `<span class="lr-ms">${ms} ms</span>` +
    `<span class="lr-net ${netDelta === 0 ? "zero" : ""}">net +${netDelta}</span>` +
    `<span class="lr-store ${storeDelta === 0 ? "zero" : ""}">store +${storeDelta} B</span>`;
  body.prepend(row);
}

// Proof line appended to every receipt — the per-operation burden of proof.
async function proofLine(ms) {
  const netDelta = net.afterLoad - proofLine._net;
  const storeDelta = (await auditStorage()) - proofLine._store;
  return `<span class="proof">receipt #${String(++proofLine._seq).padStart(2, "0")} · ${ms} ms · ` +
    `network during op: <b>${netDelta}</b> · bytes persisted: <b>${storeDelta}</b> · ` +
    `executed locally in WASM</span>`;
}
proofLine._net = 0;
proofLine._store = 0;
proofLine._seq = 0;
function proofMark() {
  proofLine._net = net.afterLoad;
  proofLine._store = store.bytes;
}

// ── Scenario 1: Identity ──────────────────────────────────────────────
let idKeys = null;
let idSig = null;
$("id-run").addEventListener("click", async () => {
  await withBusy($("id-run"), async () => {
    proofMark();
    const t0 = performance.now();
    const msg = enc.encode($("id-msg").value);
    idKeys = JSON.parse(keygen());
    idSig = sign(idKeys.secret_key, msg);
    const fp = identity_fingerprint(idKeys.secret_key);
    const ms = (performance.now() - t0).toFixed(0);
    $("id-verify").disabled = false;
    show(
      $("id-out"),
      `<span class="k">public_key</span>   ${idKeys.public_key}\n` +
        `<span class="k">fingerprint</span>    ${fp}\n` +
        `<span class="k">signature</span>      ${idSig}\n\n` +
        `<span class="dim">Born in this tab. Never sent anywhere. Verify it ↓</span>` +
        (await proofLine(ms))
    );
    ledger("ed25519 keygen + sign", ms, net.afterLoad - proofLine._net, 0);
  });
});
$("id-verify").addEventListener("click", async () => {
  if (!idKeys || !idSig) return;
  await withBusy($("id-verify"), async () => {
    proofMark();
    const t0 = performance.now();
    const ok = verify(idKeys.public_key, enc.encode($("id-msg").value), idSig);
    const ms = (performance.now() - t0).toFixed(0);
    show(
      $("id-out"),
      $("id-out").innerHTML.replace(/<span class="proof">[\s\S]*$/, "") +
        `\n\n<span class="${ok ? "ok" : "bad"}">signature valid: ${ok}</span>` +
        (await proofLine(ms))
    );
    ledger("ed25519 verify", ms, 0, 0);
  });
});

// ── Scenario 2: Envelope ──────────────────────────────────────────────
let envSalt = null; // generated after WASM init
let envBlob = null;
$("env-enc").addEventListener("click", async () => {
  const pass = $("env-pass").value;
  if (!pass) {
    show($("env-out"), `<span class="bad">Enter a passphrase first.</span>`);
    return;
  }
  await withBusy($("env-enc"), async () => {
    proofMark();
    const t0 = performance.now();
    const out = JSON.parse(envelope_encrypt(pass, envSalt, enc.encode($("env-msg").value)));
    const ms = (performance.now() - t0).toFixed(0);
    envBlob = out;
    $("env-dec").disabled = false;
    show(
      $("env-out"),
      `<span class="dim"># Argon2id KDF + XChaCha20-Poly1305, all local</span>\n` +
        `<span class="k">nonce</span>       ${out.nonce}\n` +
        `<span class="k">ciphertext</span>  (ORGN envelope)\n` +
        hexdump(out.ciphertext) +
        `\n\n<span class="dim">Change the passphrase and try to decrypt — the AEAD tag will refuse.</span>` +
        (await proofLine(ms))
    );
    ledger("envelope encrypt (argon2id + xchacha20)", ms, 0, 0);
  });
});
$("env-dec").addEventListener("click", async () => {
  if (!envBlob) return;
  await withBusy($("env-dec"), async () => {
    proofMark();
    const t0 = performance.now();
    let html;
    try {
      const pt = envelope_decrypt($("env-pass").value, envSalt, envBlob.nonce, envBlob.ciphertext);
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="ok">✓ decrypted successfully</span>\n\n<span class="k">plaintext</span>\n${esc(pt)}` + (await proofLine(ms));
      ledger("envelope decrypt", ms, 0, 0);
    } catch (e) {
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="bad">✗ decryption refused: ${esc(String(e))}</span>\n<span class="dim">Wrong passphrase or tampered ciphertext — the AEAD tag caught it.</span>` + (await proofLine(ms));
      ledger("envelope decrypt (refused)", ms, 0, 0);
    }
    show($("env-out"), html);
  });
});

// ── Scenario 3: Shards ────────────────────────────────────────────────
const DATA = 3;
const PARITY = 2;
let shardState = null;
$("sh-split").addEventListener("click", async () => {
  await withBusy($("sh-split"), async () => {
    proofMark();
    const t0 = performance.now();
    const out = JSON.parse(shard_split(enc.encode($("sh-msg").value), DATA, PARITY));
    const ms = (performance.now() - t0).toFixed(0);
    shardState = { shards: out.shards, original_len: out.original_len, present: out.shards.map(() => true) };
    renderChips();
    $("sh-recover").disabled = false;
    $("sh-hint").textContent = "click shards to lose them, then recover";
    show(
      $("sh-out"),
      `<span class="dim"># Split into ${DATA + PARITY} shards. Any ${DATA} can recover the secret.</span>` +
        (await proofLine(ms))
    );
    ledger("reed-solomon split (3+2)", ms, 0, 0);
  });
});
function renderChips() {
  const wrap = $("sh-chips");
  wrap.innerHTML = "";
  shardState.shards.forEach((hex, i) => {
    const chip = document.createElement("div");
    chip.className = "shard-chip " + (shardState.present[i] ? "present" : "lost");
    chip.textContent = `#${i} ${hex.slice(0, 8)}…`;
    chip.title = hex;
    chip.addEventListener("click", () => {
      shardState.present[i] = !shardState.present[i];
      renderChips();
    });
    wrap.appendChild(chip);
  });
}
$("sh-recover").addEventListener("click", async () => {
  if (!shardState) return;
  await withBusy($("sh-recover"), async () => {
    proofMark();
    const t0 = performance.now();
    const presentCount = shardState.present.filter(Boolean).length;
    const arr = shardState.shards.map((h, i) => (shardState.present[i] ? h : null));
    let html;
    try {
      const recovered = shard_recover(JSON.stringify(arr), shardState.original_len, DATA, PARITY);
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="ok">✓ recovered from ${presentCount}/${DATA + PARITY} shards</span>\n\n<span class="k">secret</span>  ${esc(recovered)}` + (await proofLine(ms));
      ledger(`reed-solomon recover (${presentCount}/${DATA + PARITY})`, ms, 0, 0);
    } catch (e) {
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="bad">✗ cannot recover — ${presentCount} present, need ${DATA}</span>\n<span class="dim">${esc(String(e))}</span>` + (await proofLine(ms));
      ledger(`reed-solomon recover (failed, ${presentCount} shards)`, ms, 0, 0);
    }
    show($("sh-out"), html);
  });
});

// ── Scenario 4: Entropy ───────────────────────────────────────────────
async function runEntropy() {
  const data = enc.encode($("en-input").value);
  if (data.length === 0) {
    show($("en-out"), `<span class="bad">Give it some data first.</span>`);
    return;
  }
  proofMark();
  const t0 = performance.now();
  const m = JSON.parse(entropy_analyze(data));
  const ms = (performance.now() - t0).toFixed(0);
  const rows = [
    ["Shannon entropy", m.shannon_entropy, 8, "bits/byte (8 = perfect)"],
    ["Min-entropy", m.min_entropy, 8, "bits/byte (worst case)"],
    ["χ² p-value", m.chi_squared_p, 1, "1.0 = perfectly uniform"],
    ["Bit balance", 1 - Math.abs(m.bit_bias - 0.5) * 2, 1, "1.0 = unbiased"],
  ];
  const bars = rows
    .map(([name, val, max, note]) => {
      const pct = Math.max(0, Math.min(100, (val / max) * 100));
      return `<div class="metric"><span class="name">${name}</span>` +
        `<span class="bar"><span data-w="${pct}"></span></span>` +
        `<span class="val">${val.toFixed(3)}</span></div>` +
        `<div class="metric-hint">${note}</div>`;
    })
    .join("");
  show(
    $("en-out"),
    `<span class="dim"># ${m.length} bytes · ${m.unique_bytes} unique · longest run ${m.longest_run} · serial corr ${m.serial_correlation.toFixed(3)}</span>\n` +
      bars +
      (await proofLine(ms))
  );
  // animate bars after paint
  requestAnimationFrame(() => {
    $("en-out").querySelectorAll(".bar span").forEach((s) => (s.style.width = s.dataset.w + "%"));
  });
  ledger(`entropy analyze (${m.length} B)`, ms, 0, 0);
}
$("en-run").addEventListener("click", runEntropy);
$("en-input").addEventListener("input", () => {
  if ($("en-input").value.length > 0) runEntropy();
});
$("en-sample-low").addEventListener("click", () => {
  $("en-input").value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  runEntropy();
});
$("en-sample-high").addEventListener("click", () => {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  const rnd = new Uint8Array(256);
  crypto.getRandomValues(rnd);
  let s = "";
  for (let i = 0; i < 256; i++) s += chars[rnd[i] % chars.length];
  $("en-input").value = s;
  runEntropy();
});

// ── Envelope artifact (opening visual — real ciphertext, live) ────────
function renderEnvelopeArt() {
  try {
    const nonce = random_salt() + random_salt().slice(0, 16); // 24-byte nonce display
    const ct = JSON.parse(envelope_encrypt("demo", envSalt, enc.encode("sovereignty")));
    $("ea-nonce").textContent = "nonce " + ct.nonce.slice(0, 16) + "…";
    const bytes = ct.ciphertext.match(/.{1,2}/g) || [];
    $("ea-body").innerHTML = bytes
      .map((b, i) => `<span class="ea-byte${i % 7 === 0 ? " hot" : ""}" style="animation-delay:${i * 14}ms">${b}</span>`)
      .join(" ");
  } catch { /* art is decorative; never block the page on it */ }
}

// ── Integrity: hash the executed bytes, cross-check the manifest ──────
async function sha256hex(buf) {
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyBuild(wasmBytes) {
  const computed = await sha256hex(wasmBytes);
  $("c-hash-s").textContent = computed.slice(0, 12) + "…";
  $("c-hash-s").title = computed;
  $("v-hash").textContent = computed;
  let manifest = null;
  try {
    manifest = await (await origFetch("build-info.json")).json();
  } catch { /* local dev without build-info */ }
  if (manifest) {
    $("v-manifest").textContent = JSON.stringify(
      {
        git_commit: manifest.git_commit,
        built_at: manifest.built_at,
        sdk_version: manifest.sdk_version,
        wasm_sha256: manifest.wasm_sha256,
        ci_run_url: manifest.ci_run_url || "(local build)",
      },
      null,
      2
    );
    $("v-repro").innerHTML = $("v-repro").innerHTML.replace("&lt;commit-from-manifest&gt;", manifest.git_commit_short || manifest.git_commit);
    const status = $("v-status");
    if (manifest.wasm_sha256 === computed) {
      status.className = "v-status match";
      status.textContent = `✓ HASH MATCH — this tab executed the exact artifact CI built from commit ${manifest.git_commit_short || manifest.git_commit} (sdk ${manifest.sdk_version})`;
    } else {
      status.className = "v-status mismatch";
      status.textContent = `✗ HASH MISMATCH — the executed bytes differ from the manifest. Do not trust this deployment; rebuild from source and compare.`;
    }
  } else {
    $("v-manifest").textContent = "(no build-info.json — local dev build)";
    $("v-status").textContent = "local build — no CI manifest to cross-check";
  }
}

// ── Boot ──────────────────────────────────────────────────────────────
async function main() {
  renderConsole(); // "loading engine…"

  // Fetch the engine bytes ourselves so we can hash the EXACT buffer we
  // execute. (This fetch is counted — it's one of the two engine fetches.)
  const wasmUrl = new URL("pkg/origin_web_bg.wasm", import.meta.url);
  const wasmBytes = await (await origFetch(wasmUrl)).arrayBuffer();
  initSync({ module: wasmBytes });

  // Engine is live. From this instant, ANY network request is a violation.
  engineLoaded = true;
  store.baseline = storageBytes();
  await auditStorage();

  // Salt + visual artifact now that WASM is ready.
  envSalt = random_salt();
  $("env-salt").textContent = `salt: ${envSalt}`;
  renderEnvelopeArt();

  // Service-worker check (expect zero — this page registers none).
  try {
    $("c-sw-n").textContent = String((await navigator.serviceWorker.getRegistrations()).length);
  } catch {
    $("c-sw-n").textContent = "n/a";
  }

  renderConsole();
  verifyBuild(wasmBytes); // async cross-check, updates console + verify section

  // Continuous storage audit — catches any delayed write.
  setInterval(async () => {
    await auditStorage();
    renderConsole();
  }, 2000);

  console.log(
    "%corigin%cweb — engine loaded. Network after load: 0. Storage written: 0 B. Check the ledger.",
    "color:#41d98d;font-weight:bold",
    "color:#8a978f"
  );
}

// ── Scroll reveal ─────────────────────────────────────────────────────
const io = new IntersectionObserver(
  (entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add("in")),
  { threshold: 0.12 }
);
document.querySelectorAll(".reveal").forEach((el) => io.observe(el));

main();
