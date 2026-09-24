# origin-web — Agent Notes

## What this repository is

A standalone project: browser/WebAssembly bindings over `origin-crypto-sdk`,
plus the static demo site. It is **not** a member of the `origin-tools`
workspace and owns its own `wasm-pack` build and GitHub Pages lifecycle.

Expected sibling layout (the crate's SDK patch assumes this):

```text
Gold/
├── origin-crypto-sdk/
├── origin-tools/
└── origin-web/         ← this repo
    └── crate/          ← the Rust crate (own Cargo workspace root)
```

## Build and test

```bash
cd crate
cargo fmt -- --check
cargo check                                   # host target
wasm-pack build --target web --dev            # real wasm32 verification
```

Or the full site build from the repo root:

```bash
./build.sh
```

There are no native unit tests in `crate/`; `cargo check` plus a successful
`wasm-pack build` is the meaningful verification. `wasm-pack` and the
`wasm32-unknown-unknown` target are required.

## Local SDK overlay

`crate/Cargo.toml` depends on `origin-crypto-sdk = "0.7.1-rc.10"` with the
`wasm` feature (browser entropy via Web Crypto). For local SDK iteration the
`[patch.crates-io]` section at the bottom points at `../../origin-crypto-sdk`.
Comment it out to resolve against crates.io.

## Hard rules

1. **No crypto outside the SDK.** Use `origin_crypto_sdk` re-exports
   (`blake3`, `Ed25519SigningKey`, `Ed25519VerifyingKey`,
   `Ed25519Signature`, `Signer`, `Verifier`, `fill_random`, `aead::try_generate_*`).
   No `ed25519-dalek`, `rand`, `getrandom`, or `origin_crypto_sdk::internal`
   in `crate/`.
2. **Prefer fallible bindings.** RNG-dependent exports return
   `Result<_, JsError>` so an RNG failure surfaces as a JS exception rather
   than a wasm panic/abort.
3. **`spike/` is a throwaway experiment.** It deliberately depends on raw
   primitive crates to probe what compiles to `wasm32-unknown-unknown`. It is
   not shipped and must not be treated as a pattern to copy.
