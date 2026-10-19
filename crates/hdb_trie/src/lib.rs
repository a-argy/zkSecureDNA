// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Merkle trie over the hazard database, and its lookup proofs.
//!
//! The trie's shape and hashing are defined in [`zk_types::trie`]. Here it is
//! built from a sorted entry list: every subtree is a contiguous range of
//! sorted keys, so no node structure is stored. Hashes of the top
//! `cache_depth` levels are kept (a few bytes per entry); the small subtrees
//! below them are rehashed when a proof needs one of their nodes.

use std::fs;
use std::io;
use std::path::Path;

use rayon::prelude::*;
use zk_types::trie::{
    bit, leaf_hash, node_hash, Key, LookupProof, Terminal, TrieLookups, Value, EMPTY,
    TAGGED_HASH_LEN, VALUE_LEN,
};
use zk_types::Digest32;

/// Size of one HDB entry on disk: hash, then metadata.
pub const ENTRY_LEN: usize = 32 + VALUE_LEN;

/// Average entries per subtree below the cached levels.
const LEAF_BUCKET: usize = 64;

pub struct Trie {
    keys: Vec<Key>,
    values: Vec<Value>,
    cache_depth: usize,
    /// `cache[d][p]`: hash of the subtree whose keys start with the `d`-bit
    /// prefix `p`.
    cache: Vec<Vec<Digest32>>,
}

/// The first `d` bits of `key` as an integer (`d <= 64`).
fn prefix(key: &Key, d: usize) -> u64 {
    if d == 0 {
        return 0;
    }
    u64::from_be_bytes(key[..8].try_into().unwrap()) >> (64 - d)
}

impl Trie {
    /// Builds the trie. Entries may be in any order; a key that appears more
    /// than once keeps its first value.
    pub fn new(mut entries: Vec<(Key, Value)>) -> Self {
        entries.par_sort_by(|a, b| a.0.cmp(&b.0));
        entries.dedup_by(|a, b| a.0 == b.0);
        let (keys, values): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let cache_depth = (keys.len() / LEAF_BUCKET).max(1).ilog2().min(26) as usize;
        let mut trie = Trie { keys, values, cache_depth, cache: Vec::new() };
        trie.build_cache();
        trie
    }

    /// Loads every shard of an HDB directory (files named by their prefix
    /// byte, `00` … `fe`, each a list of 40-byte entries).
    pub fn load_hdb(dir: &Path) -> io::Result<Self> {
        let mut shards: Vec<_> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        n.len() == 2 && n.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
            .collect();
        shards.sort();
        let mut entries = Vec::new();
        for shard in shards {
            let bytes = fs::read(&shard)?;
            if bytes.len() % ENTRY_LEN != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: size is not a multiple of {ENTRY_LEN}", shard.display()),
                ));
            }
            entries.extend(bytes.chunks_exact(ENTRY_LEN).map(|e| {
                (e[..32].try_into().unwrap(), e[32..].try_into().unwrap())
            }));
        }
        Ok(Self::new(entries))
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn root(&self) -> Digest32 {
        self.cache[0][0]
    }

    pub fn get(&self, key: &Key) -> Option<Value> {
        self.keys.binary_search(key).ok().map(|i| self.values[i])
    }

    /// Range of keys starting with the `d`-bit prefix `p` (`d <= 64`).
    fn prefix_range(&self, d: usize, p: u64) -> (usize, usize) {
        let lo = self.keys.partition_point(|k| prefix(k, d) < p);
        let hi = lo + self.keys[lo..].partition_point(|k| prefix(k, d) == p);
        (lo, hi)
    }

    fn build_cache(&mut self) {
        let l = self.cache_depth;
        let bottom: Vec<Digest32> = (0..1u64 << l)
            .into_par_iter()
            .map(|p| {
                let (lo, hi) = self.prefix_range(l, p);
                self.hash_range(lo, hi, l)
            })
            .collect();
        let mut levels = vec![bottom];
        for d in (0..l).rev() {
            let below = levels.last().unwrap();
            let level = (0..1u64 << d)
                .into_par_iter()
                .map(|p| {
                    let (lo, hi) = self.prefix_range(d, p);
                    match hi - lo {
                        0 => EMPTY,
                        1 => leaf_hash(&self.keys[lo], &self.values[lo]),
                        _ => node_hash(&below[2 * p as usize], &below[2 * p as usize + 1]),
                    }
                })
                .collect();
            levels.push(level);
        }
        levels.reverse();
        self.cache = levels;
    }

    /// Index of the first key in `lo..hi` with bit `d` set. All keys in the
    /// range share their first `d` bits.
    fn split(&self, lo: usize, hi: usize, d: usize) -> usize {
        lo + self.keys[lo..hi].partition_point(|k| !bit(k, d))
    }

    /// Hash of the subtree holding `keys[lo..hi]`, rooted at depth `d`.
    fn hash_range(&self, lo: usize, hi: usize, d: usize) -> Digest32 {
        match hi - lo {
            0 => EMPTY,
            1 => leaf_hash(&self.keys[lo], &self.values[lo]),
            _ if d <= self.cache_depth && !self.cache.is_empty() => {
                self.cache[d][prefix(&self.keys[lo], d) as usize]
            }
            _ => {
                let mid = self.split(lo, hi, d);
                node_hash(&self.hash_range(lo, mid, d + 1), &self.hash_range(mid, hi, d + 1))
            }
        }
    }

    pub fn prove(&self, key: &Key) -> LookupProof {
        let (mut lo, mut hi, mut d) = (0, self.keys.len(), 0);
        let mut siblings = Vec::new();
        while hi - lo > 1 {
            let mid = self.split(lo, hi, d);
            if bit(key, d) {
                siblings.push(self.hash_range(lo, mid, d + 1));
                lo = mid;
            } else {
                siblings.push(self.hash_range(mid, hi, d + 1));
                hi = mid;
            }
            d += 1;
        }
        let terminal = if hi == lo {
            Terminal::Empty
        } else {
            Terminal::Leaf { key: self.keys[lo], value: self.values[lo] }
        };
        LookupProof { siblings, terminal }
    }

    /// A proof for every hash in an HDB request body (`TaggedHash` items).
    pub fn lookups(&self, encoded_hashes: &[u8]) -> Option<TrieLookups> {
        if encoded_hashes.len() % TAGGED_HASH_LEN != 0 {
            return None;
        }
        let proofs = encoded_hashes
            .par_chunks_exact(TAGGED_HASH_LEN)
            .map(|item| self.prove(item[4..].try_into().unwrap()))
            .collect();
        Some(TrieLookups { root: self.root(), proofs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn random_entries(n: usize, seed: u64) -> Vec<(Key, Value)> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        (0..n).map(|_| (rng.gen(), rng.gen())).collect()
    }

    /// Reference root, straight from the definition in zk_types::trie.
    fn reference_root(entries: &[(Key, Value)], d: usize) -> Digest32 {
        match entries {
            [] => EMPTY,
            [(k, v)] => leaf_hash(k, v),
            _ => {
                let (l, r): (Vec<_>, Vec<_>) = entries.iter().partition(|(k, _)| !bit(k, d));
                node_hash(&reference_root(&l, d + 1), &reference_root(&r, d + 1))
            }
        }
    }

    #[test]
    fn root_matches_definition_and_ignores_order() {
        for n in [0, 1, 2, 3, 100, 5000] {
            let mut entries = random_entries(n, n as u64);
            let trie = Trie::new(entries.clone());
            assert_eq!(trie.root(), reference_root(&entries, 0), "n = {n}");
            entries.reverse();
            assert_eq!(Trie::new(entries).root(), trie.root());
        }
    }

    #[test]
    fn proofs_verify_for_members_and_non_members() {
        let entries = random_entries(20_000, 7);
        let trie = Trie::new(entries.clone());
        let root = trie.root();
        for (k, v) in entries.iter().take(500) {
            assert_eq!(trie.prove(k).verify(&root, k), Ok(Some(*v)));
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        for _ in 0..500 {
            let k: Key = rng.gen();
            assert_eq!(trie.prove(&k).verify(&root, &k), Ok(None));
        }
        // Keys that share a long prefix with a member end at its leaf.
        let mut near = entries[0].0;
        near[31] ^= 1;
        assert_eq!(trie.prove(&near).verify(&root, &near), Ok(None));
    }

    #[test]
    fn forged_proofs_fail() {
        let entries = random_entries(1000, 3);
        let trie = Trie::new(entries.clone());
        let root = trie.root();
        let (k, _) = entries[10];

        // Claiming a member is absent by swapping in an empty terminal.
        let mut p = trie.prove(&k);
        p.terminal = Terminal::Empty;
        assert!(p.verify(&root, &k).is_err());

        // Reusing another key's leaf.
        let other = trie.prove(&entries[11].0);
        assert!(other.verify(&root, &k).is_err());

        // Tampering with a sibling, or truncating the path.
        let mut p = trie.prove(&k);
        p.siblings[0][0] ^= 1;
        assert!(p.verify(&root, &k).is_err());
        let mut p = trie.prove(&k);
        p.siblings.pop();
        assert!(p.verify(&root, &k).is_err());

        // A proof for one root does not verify against another.
        let other_root = Trie::new(random_entries(1000, 4)).root();
        assert!(trie.prove(&k).verify(&other_root, &k).is_err());
    }

    #[test]
    fn lookups_count_hits() {
        let entries = random_entries(5000, 11);
        let trie = Trie::new(entries.clone());
        let mut body = Vec::new();
        for (i, key) in [entries[0].0, [7; 32], entries[1].0, [9; 32]].iter().enumerate() {
            body.extend_from_slice(&(i as u32).to_be_bytes());
            body.extend_from_slice(key);
        }
        let lookups = trie.lookups(&body).unwrap();
        assert_eq!(lookups.verify(&body), Ok(2));
        assert!(lookups.verify(&body[..72]).is_err());
    }

    #[test]
    fn loads_hdb_shards() {
        let dir = tempfile::tempdir().unwrap();
        let entries = random_entries(300, 5);
        let mut sorted = entries.clone();
        sorted.sort();
        for chunk in sorted.chunks(100) {
            let name = format!("{:02x}", chunk[0].0[0] & 0xfe);
            let mut bytes = fs::read(dir.path().join(&name)).unwrap_or_default();
            for (k, v) in chunk {
                bytes.extend_from_slice(k);
                bytes.extend_from_slice(v);
            }
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        fs::write(dir.path().join("hlt.json"), "{}").unwrap();
        let trie = Trie::load_hdb(dir.path()).unwrap();
        assert_eq!(trie.len(), 300);
        assert_eq!(trie.root(), Trie::new(entries).root());
    }
}
