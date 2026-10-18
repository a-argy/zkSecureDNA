//! Aggregation circuit: recursively verifies the hash and checksum proofs,
//! checks that their outputs match the query state the client actually used,
//! completes the DOPRF (including the active-security check), and commits the
//! `ScreeningStatement`. See docs/ZK-DESIGN.md.

#![no_main]
sp1_zkvm::entrypoint!(main);

use doprf::party::KeyserverId;
use doprf::prf::{HashPart, SerializableQueryStateSet};
use doprf::tagged::TaggedHash;
use packed_ristretto::PackedRistrettos;
use sha2::{Digest, Sha256};
use zk_types::{
    active_security_key_digest, concat, hdb_hashes_digest, queries_digest, random_modifier_digest,
    responses_digest, ChecksumOutput, HashOutput, ScreeningStatement,
};

/// Verifies an SP1 sub-proof and decodes its public values.
fn verify_and_decode<T: serde::de::DeserializeOwned>(vkey: &[u32; 8], public_values: &[u8]) -> T {
    sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &Sha256::digest(public_values).into());
    bincode::deserialize(public_values).expect("malformed sub-proof public values")
}

pub fn main() {
    // Sub-proof verifying keys are prover-supplied here; they are committed in
    // the statement and the verifier compares them to its pinned values.
    let hash_vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let hash_public_values = sp1_zkvm::io::read::<Vec<u8>>();
    let checksum_vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let checksum_public_values = sp1_zkvm::io::read::<Vec<u8>>();

    let hash_out: HashOutput = verify_and_decode(&hash_vkey, &hash_public_values);
    let checksum_out: ChecksumOutput = verify_and_decode(&checksum_vkey, &checksum_public_values);

    let mut querystate = sp1_zkvm::io::read::<SerializableQueryStateSet>()
        .to_query_state_set()
        .expect("malformed query state");
    let keyserver_responses = sp1_zkvm::io::read::<Vec<(KeyserverId, PackedRistrettos<HashPart>)>>();

    // Bind the query state to the sub-proofs.
    let queries: Vec<[u8; 32]> = querystate.queries().map(|q| *q.as_bytes()).collect();
    let window_count = hash_out.window_count as usize;
    assert_eq!(queries.len(), window_count + 1, "query count does not match hash proof");
    let (window_queries, checksum_query) = queries.split_at(window_count);
    assert_eq!(
        queries_digest(window_queries),
        hash_out.window_queries_digest,
        "queries do not match hash proof"
    );
    assert_eq!(checksum_query[0], checksum_out.checksum_query, "checksum query does not match checksum proof");

    let target = &querystate.randomized_target;
    assert_eq!(
        random_modifier_digest(&target.random_modifier.to_bytes()),
        checksum_out.random_modifier_digest,
        "random modifier does not match checksum proof"
    );
    let ask_digest = active_security_key_digest(&target.commitment_bytes());
    assert_eq!(ask_digest, checksum_out.active_security_key_digest, "active security key does not match checksum proof");

    // Complete the DOPRF, mirroring incorporate_responses_and_hash in
    // crates/doprf_client/src/operations.rs (without thread spawning).
    let mut decoded_responses = Vec::with_capacity(keyserver_responses.len());
    for (id, packed) in &keyserver_responses {
        let parts = packed
            .iter_decoded()
            .collect::<Result<Vec<HashPart>, _>>()
            .expect("malformed keyserver response");
        querystate
            .incorporate_response(*id, &parts)
            .expect("keyserver response has wrong size");
        decoded_responses.push((id.as_u32(), parts.iter().map(|p| *p.as_bytes()).collect::<Vec<_>>()));
    }

    // Also runs the active-security validation; fails if any keyserver cheated.
    let hashes = querystate
        .get_hash_values()
        .expect("keyserver responses failed active-security validation");
    let packed_hashes: PackedRistrettos<TaggedHash> = hashes.into_iter().collect();

    sp1_zkvm::io::commit(&ScreeningStatement {
        hash_vkey,
        checksum_vkey,
        order_commitment: hash_out.order_commitment,
        queries_digest: queries_digest(&queries),
        responses_digest: responses_digest(
            decoded_responses.iter().map(|(id, parts)| (*id, parts.as_slice())),
        ),
        keyserver_ids: decoded_responses.iter().map(|(id, _)| *id).collect(),
        active_security_key_digest: ask_digest,
        hdb_hashes_digest: hdb_hashes_digest(&concat(packed_hashes.iter_encoded())),
    });
}
