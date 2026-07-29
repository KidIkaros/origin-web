# origin-web — Design Document

**Status:** Draft v1
**Date:** 2026-07-28
**Owner:** KidIkaros (Ikaros Digital LLC)
**License:** Apache-2.0

---

## 1. Purpose

`origin-web` is a **100% client-side teaser** for the Origin cryptographic
suite, compiled to WebAssembly and served as a static site on GitHub Pages. It
exists to *prove* the suite's central claim — that key material never has to
leave your machine — by letting a visitor run the real crypto in their own
browser tab with **zero network requests**.

It is a **polished marketing teaser with a developer-playground flavor**: a
narrative-led page that shows off what `origin-tools` can do, with interactive
moments that let visitors feel it themselves. It is **not** the developer
playground itself — that role belongs to `origin-tools` (the real CLI suite).
This page's job is to make people *want* the real thing. It is not a backend
and never holds anyone's keys.

### Positioning vs. origin-tools

| | origin-web (this) | origin-tools |
|---|---|---|
| Role | Teaser / marketing proof | Developer playground / real tool |
| Audience | Curious visitors, evaluators | Developers, operators |
| Surface | 4 curated moments | Full 9-tool CLI suite |
| Depth | "Look what's possible" | "Here's the whole toolbox" |
| CTA | → go get origin-tools | — (it's the destination) |

Every scenario here ends by pointing at the equivalent `origin-tools` command.
The teaser sells; the CLI delivers.

### 1.1 The one rule

> No server ever sees key material, plaintext, or passphrases. The demo runs
> entirely in the visitor's browser. A live "network requests: 0" counter is
> part of the UI so the claim is verifiable, not asserted.

This rule is the whole point. Any design decision that would weaken it is
rejected by default.

### 1.2 Non-goals

- **No "origin-tools as a service."** A server that holds keys recreates the
  exact centralized trust model the suite exists to avoid. This is a hard no,
  not a "later."
- **No account system, no persistence, no telemetry.**
- **No attempt to expose the full CLI surface.** We demo the four moments that
  prove the thesis (see §5), not all nine tools.
- **No production secret management.** The browser is a demo sandbox; real use
  is the native CLI.

---

## 2. Architecture

Three layers, deliberately separated so the sober crypto library never carries
web concerns.

```
┌─────────────────────────────────────────────────────────────┐
│  origin-crypto-sdk  (existing repo)                          │
│  + new `wasm` cargo feature  (Layer 1 — capability)          │
│    · getrandom "js" feature for wasm32                       │
│    · gate off mlock/munlock (no libc in browser)             │
│    · ring/ed448 WASM compatibility                           │
└───────────────────────────┬─────────────────────────────────┘
                            │ git dependency, features=["wasm"]
┌───────────────────────────▼─────────────────────────────────┐
│  origin-web/crate  (Rust cdylib)  (Layer 2 — bindings)       │
│  #[wasm_bindgen] wrappers: hash, encrypt, decrypt,           │
│  shard_split, shard_recover, entropy_analyze, keygen,        │
│  sign, verify                                                │
└───────────────────────────┬─────────────────────────────────┘
                            │ wasm-pack build --target web
┌───────────────────────────▼─────────────────────────────────┐
│  origin-web/www  (static site)  (Layer 3 — frontend)         │
│  index.html + app.js + style.css                             │
│  imports pkg/*.wasm, drives the four demo scenarios          │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Layer 1 — SDK `wasm` feature (forced, additive)

The SDK cannot be made WASM-compilable from the outside. A `wasm` cargo feature
is added to `origin-crypto-sdk`:

- Enables `getrandom/js` so entropy comes from `crypto.getRandomValues`.
- **Also** must enable `wasm_js` on the transitive `getrandom 0.4` (pulled by
  ed448-goldilocks → elliptic-curve 0.14-rc → crypto-bigint 0.7). Since cargo
  features can't reach a transitive dep's feature directly, the SDK adds a
  direct `getrandom 0.4` dependency (aliased) with `wasm_js` under the `wasm`
  feature, so the 0.4 copy in the tree gets browser entropy too.
- Feature-gates `mlock`/`munlock` memory protection (libc syscalls absent in
  the browser). The native build keeps them; WASM build omits them.
- Resolves `ring` / `ed448-goldilocks` WASM edge cases — **both verified to
  compile in Phase 0** (§12).

**Constraint:** the feature is off by default and must not change the native
build, the public API, or the test suite. The SDK stays a sober crypto library.

### 2.2 Layer 2 — bindings crate (`origin-web/crate`)

A thin Rust cdylib exposing a small, stable JS-facing API via `wasm-bindgen`.
All functions are pure: bytes/hex in, bytes/hex out. No filesystem, no network,
no global mutable state beyond what the SDK requires.

Proposed surface (final names TBD during implementation):

| Binding            | Wraps                          | Returns          |
|--------------------|--------------------------------|------------------|
| `blake3_hash`      | `blake3::hash`                 | hex string       |
| `keygen`           | identity keypair derivation    | pubkey hex + fp  |
| `sign`             | hybrid/ed25519 sign            | signature hex    |
| `verify`           | signature verify               | bool             |
| `envelope_encrypt` | `Envelope` encrypt + AAD       | hex (ORGN blob)  |
| `envelope_decrypt` | `Envelope` decrypt             | plaintext bytes  |
| `shard_split`      | Reed-Solomon split             | JSON shard set   |
| `shard_recover`    | Reed-Solomon recover           | secret bytes     |
| `entropy_analyze`  | Shannon / chi² / min-entropy   | JSON metrics     |

Error handling: bindings return `Result<T, JsError>` so Rust errors surface as
JS exceptions with readable messages.

### 2.3 Layer 3 — frontend (`origin-web/www`)

A single-page app. **Vanilla JS + a clean dark UI** (no framework) to keep the
bundle tiny and the "view source" story honest — a visitor should be able to
read the entire app in one sitting. Styling follows a dark, technical aesthetic
consistent with the Origin brand.

---

## 3. Repository layout

Standalone repo `origin-web`, sibling to `origin-tools` and `origin-crypto-sdk`.

```
origin-web/
├── DESIGN.md                 # this document
├── README.md                 # what it is, how to run locally, the one rule
├── LICENSE                   # Apache-2.0
├── crate/                    # Layer 2 — wasm-bindgen bindings (Rust cdylib)
│   ├── Cargo.toml            # depends on SDK via git, features=["wasm"]
│   └── src/lib.rs            # #[wasm_bindgen] wrappers
├── www/                      # Layer 3 — static site
│   ├── index.html
│   ├── app.js
│   └── style.css
└── .github/workflows/
    └── deploy.yml            # wasm-pack build → assemble site → gh-pages
```

**Why standalone (not a subtree of origin-tools):**
- origin-tools is "nine CLI tools + one binary." A wasm cdylib + JS frontend
  has different tooling (wasm-pack) and a different lifecycle/version.
- GitHub Pages config is per-repo; when the repo *is* the site, deployment is
  trivial.
- Keeps the CLI repo and the SDK repo focused on their single purpose.

**Why bindings are NOT in the SDK:** the SDK is a sober crypto library. Bolting
wasm-bindgen and a demo onto it muddies its identity. The SDK gets only the
feature flag; everything user-facing lives here.

---

## 4. The built artifact

The `.wasm` blob is a **build artifact, never committed**. Flow:

1. CI runs `wasm-pack build crate/ --target web` → emits `crate/pkg/`
   (the `.wasm` + JS glue + `.d.ts`).
2. Deploy step copies `pkg/*` into the site output alongside `www/`.
3. Pushes the assembled site to the `gh-pages` branch (or uses
   `actions/deploy-pages`).
4. Pages serves it at `kidikaros.github.io/origin-web`.

The committed tree contains only source (Rust + HTML/JS/CSS). The wasm is born
in CI and shipped to Pages.

---

## 5. Demo scenarios

Four moments, chosen because each proves part of the thesis and is visually
satisfying. Not the whole suite — the moments that tell the story.

### 5.1 Identity in your browser
Generate a keypair, show the fingerprint, sign a message, verify it.
**Punchline:** a live "network requests: 0" counter. Your keys were born in
this tab and die with it.

### 5.2 The envelope
Type a secret, encrypt it to a passphrase, watch the ORGN binary format
assemble byte-by-byte (live hex dump). Decrypt it back. Shows the format is
real and self-contained.

### 5.3 Shard a secret
Split a secret into 3-of-5, visually drop two shards, recover from the rest.
Reed-Solomon is inherently demo-able and instantly understood.

### 5.4 Entropy audit
Paste text or mash the keyboard; watch Shannon entropy, chi-squared, and
min-entropy update live. Interactive, zero crypto risk, fun.

Each scenario is a self-contained card/section with: a short "what this proves"
caption, the interactive controls, and the live output.

---

## 6. UI/UX direction

- **Dark, technical aesthetic** — monospace accents, subtle grid, terminal
  flavor without being a gimmick.
- **The sovereignty banner** — persistent "0 network requests · keys never
  leave this tab" indicator, backed by a real counter.
- **Show the bytes** — hex dumps, fingerprints, and shard visualizations are
  first-class, not hidden. The demo's credibility is in the visible internals.
- **No dark patterns** — no modals begging for email, no analytics, no cookies.
- **Responsive** — works on a phone, because "open it on your phone and it
  still runs locally" is itself a demo.

---

## 7. CI/CD

`deploy.yml` (on push to `main`, and manual dispatch):

1. Install Rust + `wasm32-unknown-unknown` target + `wasm-pack`.
2. `wasm-pack build crate/ --target web`.
3. Assemble `dist/` = `www/*` + `crate/pkg/*`.
4. Deploy to GitHub Pages (via `actions/deploy-pages` or a `gh-pages` push).

A separate lightweight `ci.yml` can run `cargo test` on the bindings crate and
a headless smoke test of the built wasm (optional, phase 3).

---

## 8. Risks & mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `ed448-goldilocks` (pre-release) won't compile to WASM | High | **Spike first.** If it blocks, the demo uses ed25519/Falcon only; ed448 is a reserved-family expansion, not core. |
| `ring 0.17` WASM breakage | Medium | ring supports WASM now; if it fights, gate the specific ring-backed path behind the native build. |
| `getrandom` without `js` feature panics in browser | Medium | `wasm` feature enables `getrandom/js`. Verified in spike. |
| `mlock`/`munlock` absent in browser | Low | Feature-gate off under `wasm`; native keeps them. |
| Large `.wasm` bundle (Falcon-1024 keys are big) | Low | Acceptable for a demo; lazy-load scenarios; report size in CI. |
| Browser CSP / module loading issues on Pages | Low | `--target web` emits ES modules; serve with correct MIME. Verified in deploy. |

**The gating risk is ed448.** Everything else is bounded. This is why the spike
(§9, Phase 0) comes before any UI work.

---

## 9. Phased plan

### Phase 0 — Feasibility spike ✅ DONE (2026-07-28)
Goal: prove the SDK's primitives compile to `wasm32-unknown-unknown` and are
callable from JS.
- **Result: every primitive compiles.** See §12 capability matrix.
- The two flagged risks (ring, ed448-goldilocks) both build. ring was a
  non-issue; ed448 just needs getrandom 0.4's `wasm_js` feature.
- 890KB release artifact with the full classical + PQ stack.
- **Exit criterion met.** No algorithm excluded. Proceed to Phase 1.
- Spike crate lives at `origin-web/spike/` (throwaway, not shipped).

### Phase 1 — Repo scaffold + bindings ✅ DONE (2026-07-28)
- Created `origin-web` repo, layout per §3, LICENSE (Apache-2.0), README.
- Added `wasm` feature to origin-crypto-sdk (commit `8afc785`): getrandom 0.2
  `js` + getrandom 0.4 `wasm_js`, wasm32 branch in internal/getrandom.rs.
- Implemented full bindings surface (§2.2): 12 exported functions covering
  all four scenarios. `wasm-pack build --target web --release` → 256KB wasm.
- Verified end-to-end via Node.js: all crypto ops produce correct output.

### Phase 2 — Frontend (the four scenarios) ✅ DONE (2026-07-28)
- Built `www/` with four demo cards (§5), dark technical aesthetic.
- Network-request counter (hooks fetch + XHR, starts after wasm loads).
- Hex-dump renderers, shard chip visualization, entropy bar charts.
- `build.sh` stages `crate/pkg/` → `www/pkg/`; `.gitignore` excludes artifacts.

### Phase 3 — Deploy + polish ✅ DONE (2026-07-28)
- `deploy.yml`: checkout origin-web + SDK sibling, wasm-pack build, deploy
  `www/` to GitHub Pages on push to main.
- Responsive CSS, "what this proves" captions on each card.
- Node.js smoke test validates all 12 bindings produce correct output.

### Phase 4 — Announce ✅ DONE (2026-07-29)
- Linked demo from origin-tools README (`f6853db`) and SDK README (`31c8c7f`).
- Demo URL: https://kidikaros.github.io/origin-web — the "try it" button for the project.

---

## 10. Open questions

1. ~~**Repo home:** under the `KidIkaros` user or an org?~~ **Resolved:**
   `KidIkaros` user. Pages URL: `kidikaros.github.io/origin-web`.
2. ~~**Demo tone:** polished marketing narrative vs. raw developer playground?~~
   **Resolved:** polished marketing **teaser** with playground flavor. The full
   developer playground is origin-tools; this page teases it.
3. ~~**Domain:** stay on `*.github.io`, or custom domain?~~ **Resolved:** start
   on `kidikaros.github.io/origin-web`; custom domain (e.g. `demo.origin.tools`)
   later.
4. **Which crypto can run in WASM?** — *This must be answered empirically
   (Phase 0 spike), not assumed. No algorithm is excluded or defaulted until
   the compiler tells us what actually builds.* See §12.

---

## 12. WASM capability matrix (filled by Phase 0 spike, 2026-07-28)

Empirical results from compiling each primitive directly to
`wasm32-unknown-unknown` in a throwaway spike crate. **Nothing was
pre-excluded; the compiler decided.**

| Primitive | Compiles? | Notes |
|-----------|:---------:|-------|
| blake3 (hashing) | ✅ | clean |
| sha2 (SHA-256) | ✅ | clean |
| sha3 (SHA3-256) | ✅ | clean |
| ChaCha20-Poly1305 (AEAD) | ✅ | needs `getrandom` feature (already on) |
| Argon2id (KDF) | ✅ | clean; runtime speed TBD in browser |
| ed25519-dalek (signing) | ✅ | clean |
| falcon-rust (PQ signing) | ✅ | clean |
| ring (crypto) | ✅ | clean — the feared blocker was a non-issue |
| ed448-goldilocks (signing) | ✅ | needs getrandom 0.4 `wasm_js` feature (transitive dep) |
| getrandom (entropy) | ✅ | needs `js` feature (0.2) / `wasm_js` (0.4) |
| Reed-Solomon (shards) | ✅* | pure math; not in SDK, trivial |
| Shannon/chi² entropy | ✅* | pure math; not in SDK, trivial |
| mlock/munlock (mem protection) | n/a | no libc in browser — gate off under `wasm` feature |

**Artifact size:** 890KB (release, opt-level=s, lto) with 12 exported functions
covering the full classical + PQ stack. Very reasonable for a demo.

**Key finding:** the SDK has THREE getrandom versions in its tree (0.2, 0.3,
0.4). The `wasm` feature must enable `js` on 0.2 AND `wasm_js` on 0.4 (pulled
by ed448-goldilocks → elliptic-curve 0.14-rc → crypto-bigint 0.7). getrandom
0.3 is dev-only (proptest) and irrelevant to the wasm build.

**Conclusion:** every primitive the teaser needs compiles to WASM. No algorithm
needs to be excluded or defaulted. The Phase 0 exit criterion is met.

---

## 11. Decision log

- **2026-07-28:** Chose standalone `origin-web` repo over a subtree of
  origin-tools. Rationale: different tooling/lifecycle, trivial Pages config,
  keeps CLI + SDK repos focused.
- **2026-07-28:** SDK gets only a `wasm` feature flag; bindings + frontend live
  in origin-web. Rationale: keep the SDK a sober library.
- **2026-07-28:** "No service" is a permanent non-goal, not deferred. Rationale:
  a key-holding server contradicts the product's reason to exist.
- **2026-07-28:** Vanilla JS over a framework. Rationale: tiny bundle, honest
  view-source, no build-tool sprawl for a demo.
- **2026-07-28:** Repo lives under the `KidIkaros` user; start on
  `kidikaros.github.io/origin-web`, custom domain later.
- **2026-07-28:** Positioned as a polished marketing **teaser**, not the
  developer playground (that's origin-tools). Every scenario CTAs to the CLI.
- **2026-07-28:** No algorithm is pre-excluded or pre-defaulted for WASM. The
  Phase 0 spike fills the §12 capability matrix empirically; scoping decisions
  follow the data.
