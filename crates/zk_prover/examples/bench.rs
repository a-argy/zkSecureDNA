// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end proving benchmark on synthetic orders, with keyservers
//! simulated in-process. Prints one JSON line per order size.
//!
//!   SP1_PROVER=cpu  cargo run --release -p zk_prover --example bench -- 1 10 100
//!   SP1_PROVER=cuda cargo run --release -p zk_prover --features cuda --example bench -- 1 10 100

use std::num::NonZeroU32;
use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use doprf::active_security::{commitments_from_secret_and_keyshares, ActiveSecurityKey};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{generate_keyshares, HashPart, KeyShare, QueryStateSet};
use doprf::tagged::{HashTag, TaggedHash};
use packed_ristretto::PackedRistrettos;
use rand::{rngs::OsRng, Rng};
use zk_prover::{ClientProver, ProofMode, ScreeningVerifier};
use zk_types::concat;

const REQUIRED: u32 = 2;

/// Random 42-mers: synthetic, not real sequences.
fn random_windows(n: usize) -> Vec<String> {
    (0..n)
        .map(|_| (0..42).map(|_| b"ACGT"[OsRng.gen_range(0..4)] as char).collect())
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sizes: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let backend = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into());

    let setup = Instant::now();
    let prover = ClientProver::new().await?;
    let verifier = ScreeningVerifier::new().await?;
    eprintln!("setup: {:.1?}", setup.elapsed());

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

    for n in sizes {
        let windows = random_windows(n);
        let (qs, witness) = QueryStateSet::from_iter_with_witness(
            windows.iter().enumerate().map(|(i, w)| (HashTag::new(i == 0, 0, i), w.as_bytes())),
            REQUIRED as usize,
            ask.clone(),
        );
        let responses: Vec<(KeyserverId, PackedRistrettos<HashPart>)> = chosen
            .iter()
            .map(|(id, share)| {
                let coeff = ids.langrange_coefficient_for_id(id);
                let parts: Vec<HashPart> = qs
                    .queries()
                    .map(|q| share.apply_query_and_lagrange_coefficient(*q, &coeff))
                    .collect();
                (*id, parts.into_iter().collect())
            })
            .collect();

        let total = Instant::now();
        let query_proofs = prover.prove_queries(ProofMode::Prove, &witness, &ask).await?;
        let proof = prover
            .prove_screening(ProofMode::Prove, query_proofs, &qs.to_serializable_set(), &responses)
            .await?;
        let total = total.elapsed();
        let proof_bytes = proof.proof.expect("prove mode yields a proof");

        let mut done = qs.clone();
        for (id, packed) in &responses {
            let parts: Vec<HashPart> = packed.iter_decoded().collect::<Result<_, _>>()?;
            done.incorporate_response(*id, &parts)?;
        }
        let packed: PackedRistrettos<TaggedHash> = done.get_hash_values()?.into_iter().collect();
        let hashes = concat(packed.iter_encoded());

        let verify = Instant::now();
        verifier.verify(&proof_bytes, &hashes, None)?;
        let verify = verify.elapsed();

        let t = &proof.timings;
        println!(
            "{}",
            serde_json::json!({
                "backend": backend,
                "windows": n,
                "hash_cycles": t.hash_cycles,
                "checksum_cycles": t.checksum_cycles,
                "aggregate_cycles": t.aggregate_cycles,
                "query_proofs_s": t.query_proofs.as_secs_f64(),
                "aggregate_proof_s": t.aggregate_proof.as_secs_f64(),
                "total_s": total.as_secs_f64(),
                "verify_ms": verify.as_secs_f64() * 1e3,
                "proof_bytes": proof_bytes.len(),
            })
        );
    }
    Ok(())
}
