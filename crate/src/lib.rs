// SPDX-License-Identifier: Apache-2.0
//! origin-web bindings — Layer 2 of the origin-web architecture.
//!
//! Thin `wasm-bindgen` wrappers over `origin-crypto-sdk`. Every function is
//! pure: bytes/hex in, bytes/hex/JSON out. No filesystem, no network, no
//! global mutable state. The whole point is that this runs 100% in the
//! visitor's browser — see ../DESIGN.md §1.1 ("the one rule").
//!
//! The four teaser scenarios (DESIGN.md §5):
//!   1. Identity in your browser  -> keygen / sign / verify
//!   2. The envelope              -> envelope_encrypt / envelope_decrypt
//!   3. Shard a secret            -> shard_split / shard_recover
//!   4. Entropy audit             -> entropy_analyze

use wasm_bindgen::prelude::*;

/// Install a panic hook that routes Rust panics to the browser console,
/// so failures are debuggable instead of opaque aborts.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 0 — hashing (the simplest "look, it runs locally" proof)
// ─────────────────────────────────────────────────────────────────────────

/// BLAKE3 hash of the input, returned as hex.
#[wasm_bindgen]
pub fn blake3_hash(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 1 — Identity in your browser
// ─────────────────────────────────────────────────────────────────────────

/// Generate an Ed25519 keypair from browser entropy.
/// Returns JSON: { "public_key": hex, "secret_key": hex }.
///
/// The secret key is born in this tab. It is returned to JS only so the demo
/// can sign with it; it never leaves the page.
#[wasm_bindgen]
pub fn keygen() -> String {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    serde_json::json!({
        "public_key": hex::encode(pk.as_bytes()),
        "secret_key": hex::encode(sk.to_bytes()),
    })
    .to_string()
}

/// Sign `message` with a hex-encoded Ed25519 secret key. Returns signature hex.
#[wasm_bindgen]
pub fn sign(secret_key_hex: &str, message: &[u8]) -> Result<String, JsError> {
    use ed25519_dalek::{Signer, SigningKey};
    let sk_bytes = hex::decode(secret_key_hex).map_err(err)?;
    let sk_arr: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes (64 hex chars)"))?;
    let sk = SigningKey::from_bytes(&sk_arr);
    Ok(hex::encode(sk.sign(message).to_bytes()))
}

/// Verify a hex-encoded Ed25519 signature. Returns true/false.
#[wasm_bindgen]
pub fn verify(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    pk.verify(message, &sig).is_ok()
}

/// Derive a 32-byte identity fingerprint from a secret key via BLAKE3.
/// Demonstrates deterministic identity derivation, client-side.
///
/// Note: we use BLAKE3 directly rather than the SDK's `SeedHandle::fingerprint()`
/// because `SeedHandle::new()` internally calls `std::time::SystemTime`, which
/// panics on `wasm32-unknown-unknown` (no OS clock). BLAKE3 gives us the same
/// deterministic-fingerprint property without the time dependency.
#[wasm_bindgen]
pub fn identity_fingerprint(secret_key_hex: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(secret_key_hex).map_err(err)?;
    let hash = blake3::hash(&sk_bytes);
    Ok(hex::encode(hash.as_bytes()))
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 2 — The envelope (AEAD encryption)
// ─────────────────────────────────────────────────────────────────────────

/// Encrypt `plaintext` to a passphrase using XChaCha20-Poly1305 with an
/// Argon2id-derived key. Returns JSON: { "nonce": hex, "ciphertext": hex }.
///
/// This is the real SDK envelope path: passphrase -> Argon2id -> 32-byte key
/// -> XChaCha20-Poly1305. No key material ever leaves the tab.
#[wasm_bindgen]
pub fn envelope_encrypt(passphrase: &str, salt_hex: &str, plaintext: &[u8]) -> Result<String, JsError> {
    use origin_crypto_sdk::{Argon2id, XChaCha20Poly1305};
    let salt_bytes = hex::decode(salt_hex).map_err(err)?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| JsError::new("salt must be 16 bytes (32 hex chars)"))?;

    let key = Argon2id::derive_key(passphrase.as_bytes(), &salt, false).map_err(err)?;
    let nonce = origin_crypto_sdk::aead::generate_nonce();
    let ct = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).map_err(err)?;

    Ok(serde_json::json!({
        "nonce": hex::encode(nonce),
        "ciphertext": hex::encode(ct),
    })
    .to_string())
}

/// Decrypt an envelope produced by `envelope_encrypt`. Returns the plaintext
/// bytes (as a UTF-8 lossy string for display).
#[wasm_bindgen]
pub fn envelope_decrypt(
    passphrase: &str,
    salt_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, JsError> {
    use origin_crypto_sdk::{Argon2id, XChaCha20Poly1305};
    let salt_bytes = hex::decode(salt_hex).map_err(err)?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| JsError::new("salt must be 16 bytes (32 hex chars)"))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(err)?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| JsError::new("nonce must be 24 bytes (48 hex chars)"))?;
    let ct = hex::decode(ciphertext_hex).map_err(err)?;

    let key = Argon2id::derive_key(passphrase.as_bytes(), &salt, false).map_err(err)?;
    let pt = XChaCha20Poly1305::decrypt(&key, &nonce, &ct).map_err(err)?;
    Ok(String::from_utf8_lossy(&pt).into_owned())
}

/// Generate a fresh random salt (16 bytes) as hex, from browser entropy.
#[wasm_bindgen]
pub fn random_salt() -> String {
    let salt = origin_crypto_sdk::aead::generate_key(); // 32 bytes; take 16
    hex::encode(&salt[..16])
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 3 — Shard a secret (Reed-Solomon)
// ─────────────────────────────────────────────────────────────────────────

/// Split `secret` into `data_shards + parity_shards` shards.
/// Returns JSON: { "shards": [hex, ...], "original_len": n }.
#[wasm_bindgen]
pub fn shard_split(secret: &[u8], data_shards: usize, parity_shards: usize) -> Result<String, JsError> {
    use origin_crypto_sdk::error_correction::ReedSolomonCodec;
    let codec = ReedSolomonCodec::new(data_shards, parity_shards);
    let shards = codec.encode_shards(secret).map_err(err)?;
    let hex_shards: Vec<String> = shards.iter().map(|s| hex::encode(s)).collect();
    Ok(serde_json::json!({
        "shards": hex_shards,
        "original_len": secret.len(),
    })
    .to_string())
}

/// Recover a secret from a subset of shards.
/// `present_hex` is a JSON array where each entry is either a hex shard string
/// or null (for a lost shard), in shard order. `original_len` is required.
#[wasm_bindgen]
pub fn shard_recover(present_json: &str, original_len: usize, data_shards: usize, parity_shards: usize) -> Result<String, JsError> {
    use origin_crypto_sdk::error_correction::ReedSolomonCodec;
    let parsed: Vec<Option<String>> = serde_json::from_str(present_json).map_err(err)?;
    let shards: Vec<Option<Vec<u8>>> = parsed
        .iter()
        .map(|s| match s {
            Some(h) => hex::decode(h).ok(),
            None => None,
        })
        .collect();
    let codec = ReedSolomonCodec::new(data_shards, parity_shards);
    let recovered = codec.decode_shards(&shards, original_len).map_err(err)?;
    Ok(String::from_utf8_lossy(&recovered).into_owned())
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 4 — Entropy audit
// ─────────────────────────────────────────────────────────────────────────

/// Analyze the entropy of `data` using the SDK's real analysis.
/// Returns JSON with Shannon/min/collision entropy, chi-squared, serial
/// correlation, bit bias, longest run, and unique byte count.
#[wasm_bindgen]
pub fn entropy_analyze(data: &[u8]) -> String {
    use origin_crypto_sdk::entropy::analyze;
    let m = analyze(data);
    serde_json::json!({
        "shannon_entropy": m.shannon_entropy,
        "min_entropy": m.min_entropy,
        "collision_entropy": m.collision_entropy,
        "chi_squared": m.chi_squared,
        "chi_squared_p": m.chi_squared_p,
        "serial_correlation": m.serial_correlation,
        "longest_run": m.longest_run,
        "bit_bias": m.bit_bias,
        "unique_bytes": m.unique_bytes,
        "length": data.len(),
    })
    .to_string()
}

// ─────────────────────────────────────────────────────────────────────────
// Tool: File encrypt / decrypt (binary I/O for the File API)
// ─────────────────────────────────────────────────────────────────────────

/// Encrypt arbitrary bytes to a passphrase. Returns a binary blob:
///   nonce (24 bytes) || ciphertext
/// Designed for the browser File API — pass a Uint8Array, get one back.
#[wasm_bindgen]
pub fn file_encrypt(passphrase: &str, salt_hex: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    use origin_crypto_sdk::{Argon2id, XChaCha20Poly1305};
    let salt_bytes = hex::decode(salt_hex).map_err(err)?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| JsError::new("salt must be 16 bytes (32 hex chars)"))?;
    let key = Argon2id::derive_key(passphrase.as_bytes(), &salt, false).map_err(err)?;
    let nonce = origin_crypto_sdk::aead::generate_nonce();
    let ct = XChaCha20Poly1305::encrypt(&key, &nonce, data).map_err(err)?;
    let mut blob = Vec::with_capacity(24 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Decrypt a blob produced by `file_encrypt`. Returns the plaintext bytes.
#[wasm_bindgen]
pub fn file_decrypt(passphrase: &str, salt_hex: &str, blob: &[u8]) -> Result<Vec<u8>, JsError> {
    use origin_crypto_sdk::{Argon2id, XChaCha20Poly1305};
    if blob.len() < 25 {
        return Err(JsError::new("blob too short — need at least nonce + 1 byte"));
    }
    let salt_bytes = hex::decode(salt_hex).map_err(err)?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| JsError::new("salt must be 16 bytes (32 hex chars)"))?;
    let nonce: [u8; 24] = blob[..24].try_into().unwrap();
    let ct = &blob[24..];
    let key = Argon2id::derive_key(passphrase.as_bytes(), &salt, false).map_err(err)?;
    XChaCha20Poly1305::decrypt(&key, &nonce, ct).map_err(err)
}

// ─────────────────────────────────────────────────────────────────────────
// Tool: Password strength + generation
// ─────────────────────────────────────────────────────────────────────────

/// Score a password's strength. Returns JSON:
///   { "score": 0-6, "label": "Very Weak"|"Weak"|"Moderate"|"Strong"|"Very Strong",
///     "length": n, "variety": n, "hints": [...] }
#[wasm_bindgen]
pub fn password_strength(password: &str) -> String {
    let len = password.len();
    let mut variety = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) { variety += 1; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { variety += 1; }
    if password.chars().any(|c| c.is_ascii_digit()) { variety += 1; }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) { variety += 1; }

    let len_score = if len >= 16 { 3 } else if len >= 12 { 2 } else if len >= 8 { 1 } else { 0 };
    let score = variety + len_score;

    let label = match score {
        0..=1 => "Very Weak",
        2 => "Weak",
        3..=4 => "Moderate",
        5 => "Strong",
        _ => "Very Strong",
    };

    let mut hints = Vec::new();
    if len < 8 { hints.push("use at least 8 characters"); }
    if len < 12 { hints.push("12+ characters recommended"); }
    if variety < 3 { hints.push("mix upper, lower, digits, symbols"); }
    if password.chars().any(|c| c.is_whitespace()) { hints.push("avoid whitespace"); }

    serde_json::json!({
        "score": score,
        "label": label,
        "length": len,
        "variety": variety,
        "hints": hints,
    })
    .to_string()
}

/// Generate a cryptographically random password.
/// `length` is clamped to [8, 128]. `use_symbols` includes !@#$%^&* etc.
#[wasm_bindgen]
pub fn generate_password(length: u32, use_symbols: bool) -> String {
    use rand::RngCore;
    let len = length.clamp(8, 128) as usize;
    let lower = b"abcdefghijklmnopqrstuvwxyz";
    let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let digits = b"0123456789";
    let symbols = b"!@#$%^&*()-_=+[]{};:,.<>?";

    let mut charset = Vec::from(lower);
    charset.extend_from_slice(upper);
    charset.extend_from_slice(digits);
    if use_symbols {
        charset.extend_from_slice(symbols);
    }

    let mut rng = rand::rngs::OsRng;
    let mut buf = [0u8; 1];
    let mut password = String::with_capacity(len);

    // Guarantee at least one of each required class
    let mut required: Vec<u8> = Vec::new();
    required.push(lower[rng.next_u32() as usize % lower.len()]);
    required.push(upper[rng.next_u32() as usize % upper.len()]);
    required.push(digits[rng.next_u32() as usize % digits.len()]);
    if use_symbols {
        required.push(symbols[rng.next_u32() as usize % symbols.len()]);
    }

    for _ in 0..len {
        rng.fill_bytes(&mut buf);
        password.push(charset[buf[0] as usize % charset.len()] as char);
    }

    // Splice in the required chars at random positions
    let mut chars: Vec<char> = password.chars().collect();
    for (i, &rc) in required.iter().enumerate() {
        let pos = (rng.next_u32() as usize) % chars.len();
        chars[pos] = rc as char;
        let _ = i;
    }

    chars.into_iter().collect()
}
