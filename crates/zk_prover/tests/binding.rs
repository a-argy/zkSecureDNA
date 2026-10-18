// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding tests: the aggregation circuit must reject every way of
//! mismatching its inputs, and the HDB verifier must reject proofs that are
//! not about the request. Keyservers are simulated in-process with real
//! keyshares. Execute-mode tests are fast; prove-mode tests are `#[ignore]`d
//! (run with `cargo test --release -p zk_prover -- --ignored`).

use std::num::NonZeroU32;

use curve25519_dalek::scalar::Scalar;
use doprf::active_security::{commitments_from_secret_and_keyshares, ActiveSecurityKey};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{generate_keyshares, HashPart, KeyShare, QueryStateSet, QueryWitness};
use doprf::tagged::{HashTag, TaggedHash};
use packed_ristretto::PackedRistrettos;
use rand::rngs::OsRng;
use zk_prover::{ClientProver, ProofMode, ScreeningVerifier, VerifyError};
use zk_types::{concat, hdb_hashes_digest};

const REQUIRED: u32 = 2;

struct Keyservers {
    ask: ActiveSecurityKey,
    chosen: Vec<(KeyserverId, KeyShare)>,
}

impl Keyservers {
    fn new() -> Self {
        let secret = KeyShare::from(Scalar::random(&mut OsRng));
        let required = NonZeroU32::new(REQUIRED).unwrap();
        let shares = generate_keyshares(&secret, required, NonZeroU32::new(3).unwrap(), &mut OsRng).unwrap();
        let ask = ActiveSecurityKey::from_commitments(
            commitments_from_secret_and_keyshares(&secret, &shares, required).unwrap(),
        );
        let chosen = shares
            .into_iter()
            .take(REQUIRED as usize)
            .enumerate()
            .map(|(i, s)| (KeyserverId::try_from(i as u32 + 1).unwrap(), s))
            .collect();
        Self { ask, chosen }
    }

    /// Honest responses from each chosen keyserver.
    fn respond(&self, qs: &QueryStateSet) -> Vec<(KeyserverId, PackedRistrettos<HashPart>)> {
        let ids: KeyserverIdSet = self.chosen.iter().map(|(id, _)| *id).collect();
        self.chosen
            .iter()
            .map(|(id, share)| {
                let coeff = ids.langrange_coefficient_for_id(id);
                let parts: Vec<HashPart> = qs
                    .queries()
                    .map(|q| share.apply_query_and_lagrange_coefficient(*q, &coeff))
                    .collect();
                (*id, parts.into_iter().collect())
            })
            .collect()
    }

    fn queries(&self, windows: &[&str]) -> (QueryStateSet, QueryWitness) {
        QueryStateSet::from_iter_with_witness(
            windows
                .iter()
                .enumerate()
                .map(|(i, w)| (HashTag::new(i == 0, 0, i), w.as_bytes())),
            REQUIRED as usize,
            self.ask.clone(),
        )
    }
}

/// Placeholder 42-mers; not real sequences.
const WINDOWS: [&str; 3] = [
    "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTAC",
    "CGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACG",
    "GTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT",
];

fn local_hashes_digest(qs: &QueryStateSet, ks: &Keyservers) -> [u8; 32] {
    let mut qs = qs.clone();
    for (id, packed) in ks.respond(&qs) {
        let parts: Vec<HashPart> = packed.iter_decoded().map(Result::unwrap).collect();
        qs.incorporate_response(id, &parts).unwrap();
    }
    let packed: PackedRistrettos<TaggedHash> = qs.get_hash_values().unwrap().into_iter().collect();
    hdb_hashes_digest(&concat(packed.iter_encoded()))
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_screening_produces_matching_statement() {
    let prover = ClientProver::new().await.unwrap();
    let ks = Keyservers::new();
    let (qs, witness) = ks.queries(&WINDOWS);

    let query_proofs = prover.prove_queries(ProofMode::Execute, &witness, &ks.ask).await.unwrap();
    let proof = prover
        .prove_screening(ProofMode::Execute, query_proofs, &qs.to_serializable_set(), &ks.respond(&qs))
        .await
        .unwrap();

    assert_eq!(proof.statement.hdb_hashes_digest, local_hashes_digest(&qs, &ks));
    assert_eq!(proof.statement.keyserver_ids, vec![1, 2]);
    assert_eq!(
        proof.statement.order_commitment,
        zk_types::order_commitment(&proof.salt, WINDOWS.iter().map(|w| w.as_bytes()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_query_state_not_matching_hash_proof() {
    let prover = ClientProver::new().await.unwrap();
    let ks = Keyservers::new();
    let (_, witness_a) = ks.queries(&WINDOWS);
    let (qs_b, _) = ks.queries(&WINDOWS); // same windows, fresh blinding

    let query_proofs = prover.prove_queries(ProofMode::Execute, &witness_a, &ks.ask).await.unwrap();
    let result = prover
        .prove_screening(ProofMode::Execute, query_proofs, &qs_b.to_serializable_set(), &ks.respond(&qs_b))
        .await;
    assert!(result.is_err(), "proofs for one query set must not cover another");
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_substituted_random_modifier() {
    let prover = ClientProver::new().await.unwrap();
    let ks = Keyservers::new();
    let (qs, witness) = ks.queries(&WINDOWS);

    let query_proofs = prover.prove_queries(ProofMode::Execute, &witness, &ks.ask).await.unwrap();
    let mut serialized = qs.to_serializable_set();
    serialized.randomized_target.random_modifier = Scalar::random(&mut OsRng).to_bytes();
    let result = prover
        .prove_screening(ProofMode::Execute, query_proofs, &serialized, &ks.respond(&qs))
        .await;
    assert!(result.is_err(), "random modifier must match the checksum proof");
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_cheating_keyserver() {
    let prover = ClientProver::new().await.unwrap();
    let ks = Keyservers::new();
    let (qs, witness) = ks.queries(&WINDOWS);

    let mut responses = ks.respond(&qs);
    // Keyserver 2 answers the first query with a wrong (but valid) point.
    let mut parts: Vec<HashPart> = responses[1].1.iter_decoded().map(Result::unwrap).collect();
    parts[0] = parts[1];
    responses[1].1 = parts.into_iter().collect();

    let query_proofs = prover.prove_queries(ProofMode::Execute, &witness, &ks.ask).await.unwrap();
    let result = prover
        .prove_screening(ProofMode::Execute, query_proofs, &qs.to_serializable_set(), &responses)
        .await;
    assert!(result.is_err(), "active security must catch a wrong keyserver response");
}

/// Real proofs: the HDB verifier accepts an honest proof and rejects proofs
/// attached to other hashes or tampered with.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "generates real proofs; slow"]
async fn verifier_accepts_honest_and_rejects_mismatched_proofs() {
    let prover = ClientProver::new().await.unwrap();
    let verifier = ScreeningVerifier::new().await.unwrap();
    let ks = Keyservers::new();
    let (qs, witness) = ks.queries(&WINDOWS[..1]);

    let query_proofs = prover.prove_queries(ProofMode::Prove, &witness, &ks.ask).await.unwrap();
    let proof = prover
        .prove_screening(ProofMode::Prove, query_proofs, &qs.to_serializable_set(), &ks.respond(&qs))
        .await
        .unwrap();
    let proof_bytes = proof.proof.expect("prove mode yields a proof");

    // Rebuild exactly the bytes the client would post to the HDB.
    let mut qs_done = qs.clone();
    for (id, packed) in ks.respond(&qs) {
        let parts: Vec<HashPart> = packed.iter_decoded().map(Result::unwrap).collect();
        qs_done.incorporate_response(id, &parts).unwrap();
    }
    let packed: PackedRistrettos<TaggedHash> = qs_done.get_hash_values().unwrap().into_iter().collect();
    let hashes = concat(packed.iter_encoded());

    let ask_digest = zk_types::active_security_key_digest(&ks.ask.commitment_bytes());
    let statement = verifier.verify(&proof_bytes, &hashes, Some(&ask_digest)).unwrap();
    assert_eq!(statement, proof.statement);

    // Same proof, different hashes (e.g. reusing an old proof for a new order).
    let mut other = hashes.clone();
    other[10] ^= 1;
    assert!(matches!(verifier.verify(&proof_bytes, &other, None), Err(VerifyError::HashesMismatch)));

    // Untrusted active-security key.
    assert!(matches!(
        verifier.verify(&proof_bytes, &hashes, Some(&[0u8; 32])),
        Err(VerifyError::WrongActiveSecurityKey)
    ));

    // Tampered proof bytes.
    let mut tampered = proof_bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    assert!(matches!(
        verifier.verify(&tampered, &hashes, None),
        Err(VerifyError::Invalid(_) | VerifyError::Malformed(_))
    ));

    println!(
        "proof size: {} bytes; timings: {:?}",
        proof_bytes.len(),
        proof.timings
    );
}
