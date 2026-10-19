// SPDX-License-Identifier: MIT OR Apache-2.0

//! `hdbtrie root --hdb DIR`: the trie root to publish for a database.
//! `hdbtrie bench --entries N`: build time, proof size and verify time on a
//! random database of `N` entries.

use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand};
use hdb_trie::Trie;
use rand::{Rng, SeedableRng};
use zk_types::trie::{Key, Value};

#[derive(Parser)]
struct Opts {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Root {
        #[arg(long)]
        hdb: PathBuf,
    },
    Bench {
        #[arg(long)]
        entries: usize,
        #[arg(long, default_value_t = 10_000)]
        queries: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
}

fn main() -> anyhow::Result<()> {
    match Opts::parse().cmd {
        Cmd::Root { hdb } => {
            let t = Instant::now();
            let trie = Trie::load_hdb(&hdb)?;
            println!(
                "{}",
                serde_json::json!({
                    "root": hex(&trie.root()),
                    "entries": trie.len(),
                    "build_s": t.elapsed().as_secs_f64(),
                })
            );
        }
        Cmd::Bench { entries, queries, seed } => {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let data: Vec<(Key, Value)> = (0..entries).map(|_| (rng.gen(), rng.gen())).collect();
            let members: Vec<Key> = data.iter().take(queries / 2).map(|e| e.0).collect();
            let t = Instant::now();
            let trie = Trie::new(data);
            let build_s = t.elapsed().as_secs_f64();
            let root = trie.root();

            let keys: Vec<Key> = members
                .into_iter()
                .chain((0..queries - queries / 2).map(|_| rng.gen()))
                .collect();
            let t = Instant::now();
            let proofs: Vec<_> = keys.iter().map(|k| trie.prove(k)).collect();
            let prove_us = t.elapsed().as_secs_f64() * 1e6 / queries as f64;
            let t = Instant::now();
            let mut hits = 0;
            for (k, p) in keys.iter().zip(&proofs) {
                hits += p.verify(&root, k).expect("proof verifies").is_some() as usize;
            }
            let verify_us = t.elapsed().as_secs_f64() * 1e6 / queries as f64;
            let depths: Vec<usize> = proofs.iter().map(|p| p.siblings.len()).collect();
            let bytes: usize = proofs.iter().map(|p| bincode::serialized_size(p).unwrap() as usize).sum();
            println!(
                "{}",
                serde_json::json!({
                    "entries": trie.len(),
                    "build_s": build_s,
                    "queries": queries,
                    "hits": hits,
                    "mean_depth": depths.iter().sum::<usize>() as f64 / queries as f64,
                    "max_depth": depths.iter().max(),
                    "mean_proof_bytes": bytes as f64 / queries as f64,
                    "prove_us": prove_us,
                    "verify_us": verify_us,
                })
            );
        }
    }
    Ok(())
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
