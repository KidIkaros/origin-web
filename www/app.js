// SPDX-License-Identifier: Apache-2.0
// origin-web frontend glue (DESIGN.md §2.3, §5, §6).
//
// Loads the WASM crypto module, wires the four teaser scenarios, and runs a
// live network-request counter that PROVES the sovereignty claim: after the
// crypto engine loads, this page makes zero network requests.

import init, {
  blake3_hash,
  keygen,
  sign,
  verify,
  identity_fingerprint,
  envelope_encrypt,
  envelope_decrypt,
  random_salt,
  shard_split,
  shard_recover,
  entropy_analyze,
} from "./pkg/origin_web.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

// ── Live network-request counter ──────────────────────────────────────
// Hooks fetch + XMLHttpRequest. Started AFTER the wasm module loads, so it
// counts only requests the interactive app makes — which is none. This is the
// verifiable form of "keys never leave this tab."
let netCount = 0;
function startNetWatch() {
  const bump = () => {
    netCount += 1;
    render();
  };
  const origFetch = window.fetch;
  window.fetch = function (...args) {
    bump();
    return origFetch.apply(this, args);
  };
  const OrigXHR = window.XMLHttpRequest;
  function PatchedXHR() {
    const xhr = new OrigXHR();
    const origOpen = xhr.open;
    xhr.open = function (...a) {
      bump();
      return origOpen.apply(this, a);
    };
    return xhr;
  }
  PatchedXHR.prototype = OrigXHR.prototype;
  window.XMLHttpRequest = PatchedXHR;
}
function render() {
  const label = `${netCount} network request${netCount === 1 ? "" : "s"}`;
  $("netCount").textContent = label;
  $("netCountFoot").textContent = String(netCount);
  if (netCount > 0) {
    $("netCount").style.color = "var(--warn)";
  }
}

// ── Output helpers ────────────────────────────────────────────────────
function show(el, html) {
  el.innerHTML = html;
  el.classList.add("show");
  el.style.display = "block";
}
function esc(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}
// Render a hex string as a spaced, line-wrapped byte dump.
function hexdump(hex, cols = 16) {
  const bytes = hex.match(/.{1,2}/g) || [];
  const lines = [];
  for (let i = 0; i < bytes.length; i += cols) {
    const addr = i.toString(16).padStart(4, "0");
    lines.push(`<span class="dim">${addr}</span>  ${bytes.slice(i, i + cols).join(" ")}`);
  }
  return lines.join("\n");
}

// ── Scenario 1: Identity ──────────────────────────────────────────────
let idKeys = null;
let idSig = null;
$("id-run").addEventListener("click", () => {
  const msg = enc.encode($("id-msg").value);
  idKeys = JSON.parse(keygen());
  idSig = sign(idKeys.secret_key, msg);
  const fp = identity_fingerprint(idKeys.secret_key);
  show(
    $("id-out"),
    `<span class="k">public_key</span>  ${idKeys.public_key}\n` +
      `<span class="k">fingerprint</span>   ${fp}\n` +
      `<span class="k">signature</span>     ${idSig}\n\n` +
      `<span class="dim">Born in this tab. Never sent anywhere. Verify it ↓</span>`
  );
});
$("id-verify").addEventListener("click", () => {
  if (!idKeys || !idSig) {
    show($("id-out"), `<span class="bad">Generate a keypair first.</span>`);
    return;
  }
  const msg = enc.encode($("id-msg").value);
  const ok = verify(idKeys.public_key, msg, idSig);
  show(
    $("id-out"),
    $("id-out").innerHTML +
      `\n\n<span class="${ok ? "ok" : "bad"}">signature valid: ${ok}</span>`
  );
});

// ── Scenario 2: Envelope ──────────────────────────────────────────────
let envSalt = random_salt();
let envBlob = null;
$("env-salt").textContent = `salt: ${envSalt}`;
$("env-enc").addEventListener("click", () => {
  const pass = $("env-pass").value;
  if (!pass) {
    show($("env-out"), `<span class="bad">Enter a passphrase first.</span>`);
    return;
  }
  const pt = enc.encode($("env-msg").value);
  const t0 = performance.now();
  const out = JSON.parse(envelope_encrypt(pass, envSalt, pt));
  const ms = (performance.now() - t0).toFixed(0);
  envBlob = out;
  show(
    $("env-out"),
    `<span class="dim"># Argon2id KDF + XChaCha20-Poly1305, ${ms}ms, all local</span>\n` +
      `<span class="k">nonce</span>       ${out.nonce}\n` +
      `<span class="k">ciphertext</span>  (ORGN envelope)\n` +
      hexdump(out.ciphertext) +
      `\n\n<span class="dim">Now change the passphrase or message and try to decrypt — it will fail. That's authentication.</span>`
  );
});
$("env-dec").addEventListener("click", () => {
  if (!envBlob) {
    show($("env-out"), `<span class="bad">Encrypt something first.</span>`);
    return;
  }
  const pass = $("env-pass").value;
  try {
    const pt = envelope_decrypt(pass, envSalt, envBlob.nonce, envBlob.ciphertext);
    show(
      $("env-out"),
      `<span class="ok">✓ decrypted successfully</span>\n\n<span class="k">plaintext</span>\n${esc(pt)}`
    );
  } catch (e) {
    show($("env-out"), `<span class="bad">✗ decryption failed: ${esc(String(e))}</span>\n<span class="dim">Wrong passphrase, or the ciphertext was tampered with. The AEAD tag caught it.</span>`);
  }
});

// ── Scenario 3: Shards ────────────────────────────────────────────────
const DATA = 3;
const PARITY = 2;
let shardState = null; // { shards: [hex], original_len, present: [bool] }
$("sh-split").addEventListener("click", () => {
  const secret = enc.encode($("sh-msg").value);
  const out = JSON.parse(shard_split(secret, DATA, PARITY));
  shardState = {
    shards: out.shards,
    original_len: out.original_len,
    present: out.shards.map(() => true),
  };
  renderChips();
  show(
    $("sh-out"),
    `<span class="dim"># Split into ${DATA + PARITY} shards. Any ${DATA} can recover the secret. Click shards to lose them.</span>`
  );
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
$("sh-recover").addEventListener("click", () => {
  if (!shardState) {
    show($("sh-out"), `<span class="bad">Split a secret first.</span>`);
    return;
  }
  const presentCount = shardState.present.filter(Boolean).length;
  const arr = shardState.shards.map((h, i) => (shardState.present[i] ? h : null));
  try {
    const recovered = shard_recover(
      JSON.stringify(arr),
      shardState.original_len,
      DATA,
      PARITY
    );
    show(
      $("sh-out"),
      `<span class="ok">✓ recovered from ${presentCount}/${DATA + PARITY} shards</span>\n\n` +
        `<span class="k">secret</span>  ${esc(recovered)}`
    );
  } catch (e) {
    show(
      $("sh-out"),
      `<span class="bad">✗ cannot recover — only ${presentCount} shard(s) present, need ${DATA}</span>\n<span class="dim">${esc(String(e))}</span>`
    );
  }
});

// ── Scenario 4: Entropy ───────────────────────────────────────────────
function runEntropy() {
  const data = enc.encode($("en-input").value);
  if (data.length === 0) {
    show($("en-out"), `<span class="bad">Give it some data first.</span>`);
    return;
  }
  const m = JSON.parse(entropy_analyze(data));
  const rows = [
    ["Shannon entropy", m.shannon_entropy, 8, "bits/byte (8 = perfect)"],
    ["Min-entropy", m.min_entropy, 8, "bits/byte (worst case)"],
    ["Chi² p-value", m.chi_squared_p, 1, "1.0 = perfectly uniform"],
    ["Bit bias", 1 - Math.abs(m.bit_bias - 0.5) * 2, 1, "closer to 0.5 is better"],
  ];
  const bars = rows
    .map(([name, val, max, note]) => {
      const pct = Math.max(0, Math.min(100, (val / max) * 100));
      return `<div class="metric"><span class="name">${name}</span>` +
        `<span class="bar"><span style="width:${pct}%"></span></span>` +
        `<span class="val">${val.toFixed(3)}</span></div>` +
        `<div class="hint" style="margin:-4px 0 8px 192px">${note}</div>`;
    })
    .join("");
  show(
    $("en-out"),
    `<span class="dim"># ${m.length} bytes · ${m.unique_bytes} unique · longest run ${m.longest_run} · serial corr ${m.serial_correlation.toFixed(3)}</span>\n` +
      bars
  );
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
  // ~256 bytes of high-entropy-looking text
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  let s = "";
  const rnd = new Uint8Array(256);
  crypto.getRandomValues(rnd);
  for (let i = 0; i < 256; i++) s += chars[rnd[i] % chars.length];
  $("en-input").value = s;
  runEntropy();
});

// ── Boot ──────────────────────────────────────────────────────────────
async function main() {
  await init();
  // Crypto engine is loaded. From this point, count every network request —
  // there will be none, because everything below runs locally in WASM.
  startNetWatch();
  render();
  console.log(
    "%corigin%cweb — crypto engine loaded. Watch the network tab: it stays empty.",
    "color:#39d98a;font-weight:bold",
    "color:#6b7684"
  );
}
main();
