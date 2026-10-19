// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lookup proofs against a Merkle trie of the hazard database.
//!
//! The HDB's entries (32-byte hashes, each with 8 bytes of metadata) are
//! placed in a binary trie by the bits of their hash, most significant bit
//! first: bit 0 picks the root's child, bit 1 the next, and so on. A subtree
//! holding a single entry is stored as that entry's leaf (no chains of
//! one-child nodes), and an empty subtree hashes to [`EMPTY`]. The same set of
//! entries always gives the same root, whatever order they were added in, so
//! anyone holding the database can rebuild and check a published root.
//!
//! A [`LookupProof`] for a hash walks the path its bits spell out. It ends at
//! an empty subtree or a leaf: the hash is in the database exactly when that
//! leaf holds it. Building tries and producing proofs is in `crates/hdb_trie`;
//! this module only verifies, and also compiles for the zkVM.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Digest32;

/// Bytes of metadata stored with each hash (`hdb::Entry::META_LENGTH`).
pub const VALUE_LEN: usize = 8;

pub type Key = Digest32;
pub type Value = [u8; VALUE_LEN];

/// Hash of an empty subtree.
pub const EMPTY: Digest32 = [0; 32];

const LEAF_TAG: u8 = 0;
const NODE_TAG: u8 = 1;

pub fn leaf_hash(key: &Key, value: &Value) -> Digest32 {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(key);
    h.update(value);
    h.finalize().into()
}

pub fn node_hash(left: &Digest32, right: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Bit `i` of `key`, most significant bit of byte 0 first (so that byte-wise
/// sorted keys are also sorted by trie path).
pub fn bit(key: &Key, i: usize) -> bool {
    key[i / 8] >> (7 - i % 8) & 1 == 1
}

/// Where a lookup path ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Terminal {
    /// No entry below this point.
    Empty,
    /// The only entry below this point.
    Leaf { key: Key, value: Value },
}

/// Proof of what the database holds for one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupProof {
    /// Sibling hashes along the key's path, root level first.
    pub siblings: Vec<Digest32>,
    pub terminal: Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrieError {
    /// The path does not hash to the root.
    RootMismatch,
    /// The terminal leaf is not on the queried key's path.
    OffPath,
    /// A path cannot be longer than a key has bits.
    TooDeep,
}

impl LookupProof {
    /// Checks the proof against `root`, and returns the entry's metadata if
    /// `key` is in the database, `None` if it is not.
    pub fn verify(&self, root: &Digest32, key: &Key) -> Result<Option<Value>, TrieError> {
        let depth = self.siblings.len();
        if depth >= 256 {
            return Err(TrieError::TooDeep);
        }
        let (mut acc, found) = match &self.terminal {
            Terminal::Empty => (EMPTY, None),
            Terminal::Leaf { key: k, value } => {
                // A leaf at depth d shares its first d bits with every key
                // routed to it. Checking this keeps a malformed proof from
                // borrowing a leaf from elsewhere in the trie.
                if (0..depth).any(|i| bit(k, i) != bit(key, i)) {
                    return Err(TrieError::OffPath);
                }
                (leaf_hash(k, value), (k == key).then_some(*value))
            }
        };
        for (i, sibling) in self.siblings.iter().enumerate().rev() {
            acc = if bit(key, i) {
                node_hash(sibling, &acc)
            } else {
                node_hash(&acc, sibling)
            };
        }
        if acc != *root {
            return Err(TrieError::RootMismatch);
        }
        Ok(found)
    }
}

/// The HDB's lookups for one screening: one proof per hash posted, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrieLookups {
    pub root: Digest32,
    pub proofs: Vec<LookupProof>,
}

/// Size of one encoded `TaggedHash` in the HDB request body: a 4-byte tag,
/// then the 32-byte hash that is looked up.
pub const TAGGED_HASH_LEN: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupsError {
    /// The body is not a whole number of tagged hashes.
    MalformedHashes,
    /// Different number of proofs and hashes.
    CountMismatch,
    /// Proof `i` does not verify.
    BadProof(usize, TrieError),
}

impl TrieLookups {
    /// Verifies a proof for every hash in `encoded_hashes` (the exact HDB
    /// request body bound by `hdb_hashes_digest`), and returns how many of
    /// them are in the database.
    pub fn verify(&self, encoded_hashes: &[u8]) -> Result<u32, LookupsError> {
        if encoded_hashes.len() % TAGGED_HASH_LEN != 0 {
            return Err(LookupsError::MalformedHashes);
        }
        let keys = encoded_hashes.chunks_exact(TAGGED_HASH_LEN);
        if keys.len() != self.proofs.len() {
            return Err(LookupsError::CountMismatch);
        }
        let mut hits = 0;
        for (i, (item, proof)) in keys.zip(&self.proofs).enumerate() {
            let key: &Key = item[4..].try_into().unwrap();
            if proof.verify(&self.root, key).map_err(|e| LookupsError::BadProof(i, e))?.is_some() {
                hits += 1;
            }
        }
        Ok(hits)
    }
}
