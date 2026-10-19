// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cost of the HDB lookup proofs in the record circuit. For each order size,
//! proves one screening, then runs the record circuit with lookup proofs
//! against random databases of several sizes (an empty database is the
//! baseline: zero-length proofs). The largest database is also proved.
//! Prints one JSON line per (order, database) pair.
//!
//!   SP1_PROVER=cuda cargo run --release -p zk_prover --features cuda --example lookup_bench -- 1 10 100
//!   TRIE_SIZES=0,1000000,100000000 (default)

use std::num::NonZeroU32;
use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use doprf::active_security::{commitments_from_secret_and_keyshares, ActiveSecurityKey};
use doprf::dleq::{keyserve_domain, DleqProof};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{generate_keyshares, HashPart, KeyShare, QueryStateSet};
use doprf::tagged::{HashTag, TaggedHash};
use ed25519_dalek::{Signer, SigningKey};
use hdb_trie::Trie;
use packed_ristretto::PackedRistrettos;
use rand::{rngs::OsRng, Rng};
use zk_escrow::deal_committee;
use zk_prover::{ClientProver, ProofMode, RecordProofKind};
use zk_types::{concat, HdbAttestation, SignedHdbAttestation, ZkReceipt};

const REQUIRED: u32 = 2;

fn random_windows(n: usize) -> Vec<String> {
    (0..n)
        .map(|_| (0..42).map(|_| b"ACGT"[OsRng.gen_range(0..4)] as char).collect())
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sizes: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let trie_sizes: Vec<usize> = std::env::var("TRIE_SIZES")
        .unwrap_or_else(|_| "0,1000000,100000000".into())
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    let backend = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into());
    let prover = ClientProver::new().await?;

    let tries: Vec<Trie> = trie_sizes
        .iter()
        .map(|&n| {
            let t = Instant::now();
            let trie = Trie::new((0..n).map(|_| (OsRng.gen(), OsRng.gen())).collect());
            eprintln!("trie of {n} entries built in {:.1?}", t.elapsed());
            trie
        })
        .collect();

    let secret = KeyShare::from(Scalar::random(&mut OsRng));
    let required = NonZeroU32::new(REQUIRED).unwrap();
    let shares = generate_keyshares(&secret, required, NonZeroU32::new(3).unwrap(), &mut OsRng)?;
    let ask = ActiveSecurityKey::from_commitments(commitments_from_secret_and_keyshares(
        &secret, &shares, required,
    )?);
    let chosen: Vec<(KeyserverId, KeyShare)> = shares
        .into_iter()
        .take(REQUIRED as usize)
        .enumerate()
        .map(|(i, s)| (KeyserverId::try_from(i as u32 + 1).unwrap(), s))
        .collect();
    let ids: KeyserverIdSet = chosen.iter().map(|(id, _)| *id).collect();
    let id_list: Vec<u32> = ids.iter().map(u32::from).collect();
    let hdb_key = SigningKey::generate(&mut OsRng);
    let (committee_key, _) = deal_committee(2, 3);
    let committee_bytes = committee_key.compress().to_bytes();
    let metadata = vec![b"benchmark".to_vec(), b"lab:bench".to_vec()];

    for n in sizes {
        let windows = random_windows(n);
        let (qs, witness) = QueryStateSet::from_iter_with_witness(
            windows.iter().enumerate().map(|(i, w)| (HashTag::new(i == 0, 0, i), w.as_bytes())),
            REQUIRED as usize,
            ask.clone(),
        );
        let queries: Vec<[u8; 32]> = qs.queries().map(|q| *q.as_bytes()).collect();
        let responses: Vec<(KeyserverId, PackedRistrettos<HashPart>, DleqProof)> = chosen
            .iter()
            .map(|(id, share)| {
                let coeff = ids.langrange_coefficient_for_id(id);
                let parts: Vec<HashPart> =
                    qs.queries().map(|q| share.apply_query_and_lagrange_coefficient(*q, &coeff)).collect();
                let bytes: Vec<[u8; 32]> = parts.iter().map(|p| *p.as_bytes()).collect();
                let proof = share
                    .prove_responses(&coeff, &keyserve_domain(u32::from(id), &id_list), &queries, &bytes)
                    .unwrap();
                (*id, parts.into_iter().collect(), proof)
            })
            .collect();
        let query_proofs = prover.prove_queries(ProofMode::Prove, &witness, &ask).await?;
        let screening = prover
            .prove_screening(ProofMode::Prove, query_proofs, &qs.to_serializable_set(), &responses)
            .await?;

        let mut done = qs.clone();
        for (id, packed, _) in &responses {
            let parts: Vec<HashPart> = packed.iter_decoded().collect::<Result<_, _>>()?;
            done.incorporate_response(*id, &parts)?;
        }
        let packed: PackedRistrettos<TaggedHash> = done.get_hash_values()?.into_iter().collect();
        let hdb_hashes = concat(packed.iter_encoded());

        for (i, trie) in tries.iter().enumerate() {
            let t = Instant::now();
            let lookups = trie.lookups(&hdb_hashes).unwrap();
            let lookup_ms = t.elapsed().as_secs_f64() * 1e3;
            let lookup_bytes = bincode::serialize(&lookups)?.len();
            let mean_depth = lookups.proofs.iter().map(|p| p.siblings.len()).sum::<usize>() as f64
                / lookups.proofs.len() as f64;
            let attestation = HdbAttestation {
                statement_digest: zk_types::statement_digest(&screening.statement),
                hdb_hashes_digest: screening.statement.hdb_hashes_digest,
                hazard_count: 0,
                timestamp: 1_790_000_000,
                hdb_public_key: hdb_key.verifying_key().to_bytes(),
                hdb_root: trie.root(),
            };
            let signature = hdb_key.sign(&attestation.message()).to_bytes().to_vec();
            let receipt = ZkReceipt {
                statement: screening.statement.clone(),
                proof: screening.proof.clone().expect("prove mode"),
                salt: screening.salt,
                attestation: SignedHdbAttestation { attestation, signature },
                windows: witness.windows.clone(),
                hdb_hashes: hdb_hashes.clone(),
                lookups,
            };
            let kind = if i + 1 == tries.len() { RecordProofKind::Compressed } else { RecordProofKind::Execute };
            let record = prover.prove_record(kind, &receipt, &metadata, &committee_bytes).await?;
            println!(
                "{}",
                serde_json::json!({
                    "backend": backend,
                    "windows": n,
                    "hashes": hdb_hashes.len() / zk_types::trie::TAGGED_HASH_LEN,
                    "db_entries": trie.len(),
                    "mean_depth": mean_depth,
                    "lookup_proofs_ms": lookup_ms,
                    "lookup_bytes": lookup_bytes,
                    "record_cycles": record.cycles,
                    "record_prove_s": (kind == RecordProofKind::Compressed).then(|| record.prove_time.as_secs_f64()),
                })
            );
        }
    }
    Ok(())
}
