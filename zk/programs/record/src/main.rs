//! Record circuit: the on-chain artifact (Neil's "zkp_all"). It
//!   1. recursively verifies the aggregation proof (the screening statement),
//!   2. verifies the HDB's Ed25519 attestation of that statement,
//!   3. opens the order commitment against the actual windows, and
//!   4. encrypts each record field (field 0 = the windows) to the authority
//!      committee key, committing a digest per ciphertext.
//! Public values are ABI-encoded for the Solidity registry.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zk_escrow::{decompress, encode_windows, encrypt_field};
use zk_types::{
    circuits_digest, order_commitment, statement_digest, HdbAttestation, ScreeningStatement,
};

sol! {
    /// Must match `RecordPublicValues` in contracts/src/ZkSecureDNARegistry.sol.
    struct RecordPublicValues {
        bytes32 circuitsDigest;
        bytes32 statementDigest;
        bytes32 orderCommitment;
        bytes32 activeSecurityKeyDigest;
        bytes32 hdbPublicKey;
        uint32 hazardCount;
        uint64 screenedAt;
        bytes32 committeeKey;
        bytes32[] fieldDigests;
    }
}

pub fn main() {
    let aggregate_vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let aggregate_public_values = sp1_zkvm::io::read::<Vec<u8>>();
    let attestation = sp1_zkvm::io::read::<HdbAttestation>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();
    let salt = sp1_zkvm::io::read::<[u8; 32]>();
    let windows = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    // Fields 1.. (purpose, lab id, ...); field 0 is built from the windows.
    let metadata = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let committee_key_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let ephemeral_scalars = sp1_zkvm::io::read::<Vec<[u8; 32]>>();

    // 1. The screening statement, proven by the aggregation circuit.
    sp1_zkvm::lib::verify::verify_sp1_proof(
        &aggregate_vkey,
        &Sha256::digest(&aggregate_public_values).into(),
    );
    let statement: ScreeningStatement =
        bincode::deserialize(&aggregate_public_values).expect("malformed aggregation public values");

    // 2. The HDB attested to exactly this statement.
    let stmt_digest = statement_digest(&statement);
    assert_eq!(attestation.statement_digest, stmt_digest, "attestation is for another statement");
    assert_eq!(attestation.hdb_hashes_digest, statement.hdb_hashes_digest);
    let hdb_key = VerifyingKey::from_bytes(&attestation.hdb_public_key).expect("invalid HDB key");
    let signature = Signature::from_slice(&signature).expect("malformed signature");
    hdb_key
        .verify(&attestation.message(), &signature)
        .expect("HDB attestation signature does not verify");

    // 3. The windows are the ones that were screened.
    assert_eq!(
        order_commitment(&salt, windows.iter().map(Vec::as_slice)),
        statement.order_commitment,
        "windows do not open the order commitment"
    );

    // 4. Encrypt every field to the committee key.
    let committee_key = decompress(&committee_key_bytes).expect("invalid committee key");
    let mut fields = vec![encode_windows(&windows)];
    fields.extend(metadata);
    assert_eq!(fields.len(), ephemeral_scalars.len(), "one ephemeral scalar per field");
    let field_digests: Vec<[u8; 32]> = fields
        .iter()
        .zip(&ephemeral_scalars)
        .enumerate()
        .map(|(i, (plaintext, r))| {
            let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(*r)).expect("bad scalar");
            encrypt_field(&committee_key, i as u32, &r, plaintext).digest()
        })
        .collect();

    let public_values = RecordPublicValues {
        circuitsDigest: circuits_digest(&aggregate_vkey, &statement.hash_vkey, &statement.checksum_vkey).into(),
        statementDigest: stmt_digest.into(),
        orderCommitment: statement.order_commitment.into(),
        activeSecurityKeyDigest: statement.active_security_key_digest.into(),
        hdbPublicKey: attestation.hdb_public_key.into(),
        hazardCount: attestation.hazard_count,
        screenedAt: attestation.timestamp,
        committeeKey: committee_key_bytes.into(),
        fieldDigests: field_digests.into_iter().map(Into::into).collect(),
    };
    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
