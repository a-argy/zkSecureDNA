// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public outputs of the zkSecureDNA circuits, and the digests that bind them
//! together. See `docs/ZK-DESIGN.md` for the statement these encode.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];

/// Public output of the hash circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput {
    /// `SHA-256(salt ‖ len₀ ‖ window₀ ‖ len₁ ‖ window₁ ‖ …)`, see [`order_commitment`].
    pub order_commitment: Digest32,
    /// Digest of the per-window blinded queries, see [`queries_digest`].
    pub window_queries_digest: Digest32,
    pub window_count: u32,
}

/// Public output of the checksum circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumOutput {
    /// The blinded active-security checksum query (compressed Ristretto).
    pub checksum_query: Digest32,
    /// `SHA-256(random_modifier)`. Binds the secret modifier without revealing it.
    pub random_modifier_digest: Digest32,
    pub active_security_key_digest: Digest32,
}

/// Public output of the aggregation circuit: the statement a verifier checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreeningStatement {
    /// SP1 verifying-key digests of the hash and checksum circuits that were
    /// recursively verified. A verifier must compare these to pinned values.
    pub hash_vkey: [u32; 8],
    pub checksum_vkey: [u32; 8],
    pub order_commitment: Digest32,
    /// Digest of every query sent to keyservers, checksum query included.
    pub queries_digest: Digest32,
    pub responses_digest: Digest32,
    pub keyserver_ids: Vec<u32>,
    pub active_security_key_digest: Digest32,
    /// Digest of the encoded hashes sent to the HDB, see [`hdb_hashes_digest`].
    pub hdb_hashes_digest: Digest32,
}

/// Hiding commitment to the screened windows. Each window is length-prefixed
/// so different window splits cannot collide.
pub fn order_commitment<'a>(salt: &Digest32, windows: impl IntoIterator<Item = &'a [u8]>) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/order/v1");
    h.update(salt);
    for w in windows {
        h.update((w.len() as u64).to_le_bytes());
        h.update(w);
    }
    h.finalize().into()
}

/// Digest of a list of compressed Ristretto points (queries, hash parts, etc.).
pub fn queries_digest<'a>(points: impl IntoIterator<Item = &'a Digest32>) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/queries/v1");
    for p in points {
        h.update(p);
    }
    h.finalize().into()
}

/// Digest of the active-security key's public commitments.
pub fn active_security_key_digest<'a>(commitments: impl IntoIterator<Item = &'a Digest32>) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/ask/v1");
    for c in commitments {
        h.update(c);
    }
    h.finalize().into()
}

/// Digest of the keyserver responses, in the order they were incorporated.
pub fn responses_digest<'a>(responses: impl IntoIterator<Item = (u32, &'a [Digest32])>) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/responses/v1");
    for (id, parts) in responses {
        h.update(id.to_le_bytes());
        h.update((parts.len() as u64).to_le_bytes());
        for p in parts {
            h.update(p);
        }
    }
    h.finalize().into()
}

/// Digest of the exact bytes the client posts to the HDB (concatenated encoded
/// `TaggedHash` items), so the HDB can recompute it from the request body.
pub fn hdb_hashes_digest(encoded: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/hdb-hashes/v1");
    h.update(encoded);
    h.finalize().into()
}

pub fn random_modifier_digest(random_modifier: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/random-modifier/v1");
    h.update(random_modifier);
    h.finalize().into()
}

/// Concatenates an iterator of byte arrays (helper for `hdb_hashes_digest`).
pub fn concat<'a, const N: usize>(items: impl IntoIterator<Item = &'a [u8; N]>) -> Vec<u8> {
    let mut out = Vec::new();
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// Content type of a `/scep/screen-and-verify` request body.
pub const SCREEN_AND_VERIFY_CONTENT_TYPE: &str = "application/x-zksecuredna-screen-v1";

/// Request body: `len(hashes) as u32 LE ‖ hashes ‖ proof`, where `hashes` is
/// exactly the body `/scep/screen` would receive.
pub fn encode_screen_and_verify(hashes: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + hashes.len() + proof.len());
    out.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    out.extend_from_slice(hashes);
    out.extend_from_slice(proof);
    out
}

/// Inverse of [`encode_screen_and_verify`]: returns `(hashes, proof)`.
pub fn decode_screen_and_verify(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
    let rest = &body[4..];
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}
