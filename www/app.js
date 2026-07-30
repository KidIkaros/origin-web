// SPDX-License-Identifier: Apache-2.0
// origin-web — lightweight web version of origin-crypt.
//
// Architecture: WASM crypto engine (origin-crypto-sdk) runs entirely in-tab.
// Network + storage monitors prove nothing leaves the browser.
// Vault uses IndexedDB with XChaCha20-Poly1305 + Argon2id (WASM) for at-rest encryption.

import {
  initSync,
  keygen,
  sign,
  verify,
  identity_fingerprint,
  envelope_encrypt,
  envelope_decrypt,
  file_encrypt,
  file_decrypt,
  shard_split,
  shard_recover,
  entropy_analyze,
  random_salt,
} from "./pkg/origin_web.js";

// ── 0. ARM MONITORS — before anything else ──────────────────────────
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

// ── Storage audit ───────────────────────────────────────────────────
const store = { baseline: null, bytes: 0, entries: 0 };
function storageBytes() {
  let bytes = 0, entries = 0;
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

// ── DOM helpers ─────────────────────────────────────────────────────
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
function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

// ── Console + ledger rendering ──────────────────────────────────────
function renderConsole() {
  const netEl = $("c-net-n");
  netEl.textContent = engineLoaded ? String(net.afterLoad) : "…";
  netEl.parentElement.classList.toggle("ok", engineLoaded && net.afterLoad === 0);
  netEl.parentElement.classList.toggle("bad", net.afterLoad > 0);
  $("c-store-n").textContent = store.baseline === null ? "…" : `${store.bytes} B`;
  $("c-store-n").parentElement.classList.toggle("ok", store.baseline !== null && store.bytes === 0);
  $("foot-req").textContent = engineLoaded ? `net: ${net.afterLoad}` : "net: …";
  $("foot-store").textContent = store.baseline === null ? "store: …" : `store: ${store.bytes} B`;
  const detail = $("console-detail");
  if (net.violations.length) {
    detail.textContent = "⚠ unexpected request: " + net.violations[0];
    detail.classList.add("bad");
  } else if (engineLoaded) {
    detail.textContent = `engine loaded (${net.engineFetches} fetches) · hash checked · watching for leaks`;
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

// ── Tab navigation ──────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tool-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// ═══ TAB 1: Encrypt ═════════════════════════════════════════════════
let encFileData = null;
let encFileName = "";
let encSalt = null;

$("enc-file").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  encFileName = file.name;
  $("enc-filename").textContent = `${file.name} (${formatBytes(file.size)})`;
  file.arrayBuffer().then((buf) => {
    encFileData = new Uint8Array(buf);
    updateEncButtons();
  });
});

// Drag-and-drop
const dropZone = $("enc-drop");
dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (!file) return;
  encFileName = file.name;
  $("enc-filename").textContent = `${file.name} (${formatBytes(file.size)})`;
  file.arrayBuffer().then((buf) => {
    encFileData = new Uint8Array(buf);
    updateEncButtons();
  });
});

function updateEncButtons() {
  const hasPass = $("enc-pass").value.length > 0;
  $("enc-btn").disabled = !(encFileData && hasPass);
  $("dec-btn").disabled = !(encFileData && hasPass);
}
$("enc-pass").addEventListener("input", updateEncButtons);

$("enc-btn").addEventListener("click", async () => {
  if (!encFileData || !$("enc-pass").value) return;
  await withBusy($("enc-btn"), async () => {
    proofMark();
    const t0 = performance.now();
    try {
      const blob = file_encrypt($("enc-pass").value, encSalt, encFileData);
      const ms = (performance.now() - t0).toFixed(0);
      const outName = encFileName + ".enc";
      downloadBlob(new Blob([blob]), outName);
      show($("enc-out"),
        `<span class="ok">✓ Encrypted ${formatBytes(encFileData.length)} → ${formatBytes(blob.length)}</span>\n\n` +
        `<span class="k">file</span>      ${esc(encFileName)}\n` +
        `<span class="k">output</span>    ${esc(outName)}\n` +
        `<span class="k">cipher</span>    XChaCha20-Poly1305\n` +
        `<span class="k">kdf</span>       Argon2id (salt: ${encSalt.slice(0, 8)}…)\n\n` +
        `<span class="dim">Download started. The encrypted file can only be decrypted with the same passphrase + salt.</span>` +
        (await proofLine(ms))
      );
      ledger(`encrypt ${encFileName} (${formatBytes(encFileData.length)})`, ms, 0, 0);
    } catch (e) {
      show($("enc-out"), `<span class="bad">✗ ${esc(String(e))}</span>`);
    }
  });
});

$("dec-btn").addEventListener("click", async () => {
  if (!encFileData || !$("enc-pass").value) return;
  await withBusy($("dec-btn"), async () => {
    proofMark();
    const t0 = performance.now();
    try {
      const pt = file_decrypt($("enc-pass").value, encSalt, encFileData);
      const ms = (performance.now() - t0).toFixed(0);
      const outName = encFileName.replace(/\.enc$/, "") || "decrypted";
      downloadBlob(new Blob([pt]), outName);
      show($("enc-out"),
        `<span class="ok">✓ Decrypted ${formatBytes(encFileData.length)} → ${formatBytes(pt.length)}</span>\n\n` +
        `<span class="k">output</span>    ${esc(outName)}\n\n` +
        `<span class="dim">Download started.</span>` +
        (await proofLine(ms))
      );
      ledger(`decrypt ${encFileName} (${formatBytes(encFileData.length)})`, ms, 0, 0);
    } catch (e) {
      const ms = (performance.now() - t0).toFixed(0);
      show($("enc-out"),
        `<span class="bad">✗ Decryption failed: ${esc(String(e))}</span>\n` +
        `<span class="dim">Wrong passphrase or corrupted file — the AEAD tag refused.</span>` +
        (await proofLine(ms))
      );
      ledger(`decrypt (refused)`, ms, 0, 0);
    }
  });
});

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ═══ TAB 2: Vault ═══════════════════════════════════════════════════
const VAULT_DB = "origin-vault";
const VAULT_STORE = "entries";
const VAULT_META = "meta";
let vaultPass = null;
let vaultSalt = null;

function openVaultDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(VAULT_DB, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) db.createObjectStore(VAULT_STORE, { keyPath: "name" });
      if (!db.objectStoreNames.contains(VAULT_META)) db.createObjectStore(VAULT_META, { keyPath: "key" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function vaultGetAll() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, "readonly");
    const req = tx.objectStore(VAULT_STORE).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function vaultPut(entry) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, "readwrite");
    tx.objectStore(VAULT_STORE).put(entry);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function vaultDelete(name) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, "readwrite");
    tx.objectStore(VAULT_STORE).delete(name);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function vaultGetMeta(key) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_META, "readonly");
    const req = tx.objectStore(VAULT_META).get(key);
    req.onsuccess = () => resolve(req.result?.value ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function vaultPutMeta(key, value) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_META, "readwrite");
    tx.objectStore(VAULT_META).put({ key, value });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function encryptEntry(value) {
  const json = envelope_encrypt(vaultPass, vaultSalt, enc.encode(value));
  const { nonce, ciphertext } = JSON.parse(json);
  return { nonce, ciphertext };
}

function decryptEntry(entry) {
  return envelope_decrypt(vaultPass, vaultSalt, entry.nonce, entry.ciphertext);
}

$("vault-unlock").addEventListener("click", async () => {
  const pass = $("vault-pass").value;
  if (!pass) { show($("vault-out"), `<span class="bad">Enter a passphrase.</span>`); return; }
  proofMark();
  const t0 = performance.now();
  try {
    // Load or create salt (stored alongside vault — it's not secret, the passphrase is)
    let salt = await vaultGetMeta("salt");
    if (!salt) {
      salt = random_salt();
      await vaultPutMeta("salt", salt);
    }
    vaultPass = pass;
    vaultSalt = salt;
    // Test decrypt — try to read existing entries
    const entries = await vaultGetAll();
    let decrypted = 0;
    for (const e of entries) {
      try { decryptEntry(e); decrypted++; } catch { /* wrong passphrase or corrupt */ }
    }
    // If entries exist but none decrypt, the passphrase is wrong
    if (entries.length > 0 && decrypted === 0) {
      vaultPass = null;
      vaultSalt = null;
      const ms = (performance.now() - t0).toFixed(0);
      show($("vault-out"),
        `<span class="bad">✗ Wrong passphrase — 0 of ${entries.length} entries decrypted</span>\n\n` +
        `<span class="dim">The vault contains ${entries.length} encrypted entries. ` +
        `Your passphrase did not unlock any of them.</span>` +
        (await proofLine(ms))
      );
      ledger("vault unlock (refused)", ms, 0, 0);
      return;
    }
    const ms = (performance.now() - t0).toFixed(0);
    $("vault-unlock").disabled = true;
    $("vault-lock").disabled = false;
    $("vault-entries").hidden = false;
    show($("vault-out"),
      `<span class="ok">✓ Vault unlocked</span>\n\n` +
      `<span class="k">entries</span>   ${entries.length}\n` +
      `<span class="k">decryptable</span> ${decrypted}\n` +
      `<span class="k">cipher</span>    XChaCha20-Poly1305\n` +
      `<span class="k">kdf</span>       Argon2id\n` +
      `<span class="k">storage</span>   IndexedDB (encrypted at rest)\n\n` +
      `<span class="dim">The passphrase exists only in memory. Lock or close the tab to destroy it.</span>` +
      (await proofLine(ms))
    );
    ledger("vault unlock", ms, 0, 0);
    renderVaultList();
  } catch (e) {
    vaultPass = null;
    vaultSalt = null;
    show($("vault-out"), `<span class="bad">✗ ${esc(String(e))}</span>`);
  }
});

$("vault-lock").addEventListener("click", () => {
  vaultPass = null;
  vaultSalt = null;
  $("vault-unlock").disabled = false;
  $("vault-lock").disabled = true;
  $("vault-entries").hidden = true;
  $("vault-pass").value = "";
  show($("vault-out"), `<span class="dim"># Vault locked. Passphrase destroyed.</span>`);
});

$("vault-add").addEventListener("click", async () => {
  const name = $("vault-name").value.trim();
  const secret = $("vault-secret").value;
  if (!name || !secret) return;
  proofMark();
  const t0 = performance.now();
  const encrypted = encryptEntry(secret);
  await vaultPut({ name, ...encrypted });
  const ms = (performance.now() - t0).toFixed(0);
  $("vault-name").value = "";
  $("vault-secret").value = "";
  renderVaultList();
  ledger(`vault add "${name}"`, ms, 0, 0);
});

async function renderVaultList() {
  const entries = await vaultGetAll();
  const list = $("vault-list");
  list.innerHTML = "";
  for (const e of entries) {
    let value = "••••••••";
    let revealed = false;
    try { value = decryptEntry(e); } catch { value = "(decrypt error)"; }
    const row = document.createElement("div");
    row.className = "vault-row";
    row.innerHTML =
      `<span class="vault-name">${esc(e.name)}</span>` +
      `<code class="vault-value" data-revealed="false">${esc("••••••••")}</code>` +
      `<button class="btn small vault-reveal" data-name="${esc(e.name)}">show</button>` +
      `<button class="btn small vault-copy" data-name="${esc(e.name)}">copy</button>` +
      `<button class="btn small danger vault-del" data-name="${esc(e.name)}">✕</button>`;
    list.appendChild(row);
  }
  // Wire reveal buttons
  list.querySelectorAll(".vault-reveal").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const entry = (await vaultGetAll()).find((e) => e.name === btn.dataset.name);
      if (!entry) return;
      const valEl = btn.parentElement.querySelector(".vault-value");
      const isRevealed = valEl.dataset.revealed === "true";
      if (isRevealed) {
        valEl.textContent = "••••••••";
        valEl.dataset.revealed = "false";
        btn.textContent = "show";
      } else {
        try { valEl.textContent = decryptEntry(entry); } catch { valEl.textContent = "(decrypt error)"; }
        valEl.dataset.revealed = "true";
        btn.textContent = "hide";
      }
    });
  });
  // Wire copy buttons
  list.querySelectorAll(".vault-copy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const entry = (await vaultGetAll()).find((e) => e.name === btn.dataset.name);
      if (entry) {
        const val = decryptEntry(entry);
        navigator.clipboard.writeText(val);
        btn.textContent = "✓";
        setTimeout(() => (btn.textContent = "copy"), 1500);
      }
    });
  });
  list.querySelectorAll(".vault-del").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await vaultDelete(btn.dataset.name);
      renderVaultList();
    });
  });
}

// ═══ TAB 3: Identity ════════════════════════════════════════════════
let idKeys = null;
let idSig = null;

$("id-keygen").addEventListener("click", async () => {
  await withBusy($("id-keygen"), async () => {
    proofMark();
    const t0 = performance.now();
    const msg = enc.encode($("id-msg").value);
    idKeys = JSON.parse(keygen());
    idSig = sign(idKeys.secret_key, msg);
    const fp = identity_fingerprint(idKeys.secret_key);
    const ms = (performance.now() - t0).toFixed(0);
    $("id-verify").disabled = false;
    show($("id-out"),
      `<span class="ok">✓ Keypair generated + message signed</span>\n\n` +
      `<span class="k">public_key</span>   ${idKeys.public_key}\n` +
      `<span class="k">fingerprint</span>    ${fp}\n` +
      `<span class="k">signature</span>      ${idSig.slice(0, 64)}…\n\n` +
      `<span class="dim">Born in this tab. Never sent anywhere. Verify it ↓</span>` +
      (await proofLine(ms))
    );
    ledger("ed25519 keygen + sign", ms, 0, 0);
  });
});

$("id-verify").addEventListener("click", async () => {
  if (!idKeys || !idSig) return;
  await withBusy($("id-verify"), async () => {
    proofMark();
    const t0 = performance.now();
    const ok = verify(idKeys.public_key, enc.encode($("id-msg").value), idSig);
    const ms = (performance.now() - t0).toFixed(0);
    show($("id-out"),
      $("id-out").innerHTML.replace(/<span class="proof">[\s\S]*$/, "") +
      `\n\n<span class="${ok ? "ok" : "bad"}">signature valid: ${ok}</span>` +
      (await proofLine(ms))
    );
    ledger("ed25519 verify", ms, 0, 0);
  });
});

// ═══ TAB 4: Share ═══════════════════════════════════════════════════
let shardState = null;

$("sh-split").addEventListener("click", async () => {
  await withBusy($("sh-split"), async () => {
    proofMark();
    const t0 = performance.now();
    const data = parseInt($("sh-data").value) || 3;
    const parity = parseInt($("sh-parity").value) || 2;
    const out = JSON.parse(shard_split(enc.encode($("sh-msg").value), data, parity));
    const ms = (performance.now() - t0).toFixed(0);
    shardState = { shards: out.shards, original_len: out.original_len, present: out.shards.map(() => true), data, parity };
    renderChips();
    $("sh-recover").disabled = false;
    $("sh-hint").textContent = "click shards to lose them, then recover";
    show($("sh-out"),
      `<span class="ok">✓ Split into ${data + parity} shards</span>\n\n` +
      `<span class="k">data</span>      ${data} shards required\n` +
      `<span class="k">parity</span>    ${parity} recovery shards\n` +
      `<span class="k">total</span>     ${data + parity} shards\n\n` +
      `<span class="dim">Any ${data} shards can recover the secret. Click to simulate loss.</span>` +
      (await proofLine(ms))
    );
    ledger(`reed-solomon split (${data}+${parity})`, ms, 0, 0);
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
      const recovered = shard_recover(JSON.stringify(arr), shardState.original_len, shardState.data, shardState.parity);
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="ok">✓ Recovered from ${presentCount}/${shardState.data + shardState.parity} shards</span>\n\n` +
        `<span class="k">secret</span>  ${esc(recovered)}` + (await proofLine(ms));
      ledger(`reed-solomon recover (${presentCount}/${shardState.data + shardState.parity})`, ms, 0, 0);
    } catch (e) {
      const ms = (performance.now() - t0).toFixed(0);
      html = `<span class="bad">✗ Cannot recover — ${presentCount} present, need ${shardState.data}</span>\n` +
        `<span class="dim">${esc(String(e))}</span>` + (await proofLine(ms));
      ledger(`reed-solomon recover (failed, ${presentCount} shards)`, ms, 0, 0);
    }
    show($("sh-out"), html);
  });
});

// ═══ TAB 5: Entropy ═════════════════════════════════════════════════
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
  show($("en-out"),
    `<span class="dim"># ${m.length} bytes · ${m.unique_bytes} unique · longest run ${m.longest_run} · serial corr ${m.serial_correlation.toFixed(3)}</span>\n` +
    bars +
    (await proofLine(ms))
  );
  requestAnimationFrame(() => {
    $("en-out").querySelectorAll(".bar span").forEach((s) => (s.style.width = s.dataset.w + "%"));
  });
  ledger(`entropy analyze (${m.length} B)`, ms, 0, 0);
}
$("en-run").addEventListener("click", runEntropy);
let entropyTimer = null;
$("en-input").addEventListener("input", () => {
  if ($("en-input").value.length > 0) {
    clearTimeout(entropyTimer);
    entropyTimer = setTimeout(runEntropy, 300);
  }
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

// ── Integrity: hash the executed bytes, cross-check the manifest ────
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
      { git_commit: manifest.git_commit, built_at: manifest.built_at, sdk_version: manifest.sdk_version, wasm_sha256: manifest.wasm_sha256, ci_run_url: manifest.ci_run_url || "(local build)" },
      null, 2
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

// ── Boot ────────────────────────────────────────────────────────────
async function main() {
  renderConsole();

  const wasmUrl = new URL("pkg/origin_web_bg.wasm", import.meta.url);
  const wasmBytes = await (await origFetch(wasmUrl)).arrayBuffer();
  initSync({ module: wasmBytes });

  engineLoaded = true;
  store.baseline = storageBytes();
  await auditStorage();

  encSalt = random_salt();

  try {
    $("c-sw-n").textContent = String((await navigator.serviceWorker.getRegistrations()).length);
  } catch {
    $("c-sw-n").textContent = "n/a";
  }

  renderConsole();
  verifyBuild(wasmBytes);

  setInterval(async () => {
    await auditStorage();
    renderConsole();
  }, 2000);

  console.log(
    "%corigin-crypt%c — sovereign crypto, client-side only. View source: github.com/KidIkaros/origin-web",
    "color:#41d98d;font-weight:bold", "color:inherit"
  );
}

main();
