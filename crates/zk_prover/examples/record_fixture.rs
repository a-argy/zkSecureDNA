// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end record test and Solidity fixture generator.
//!
//! Screens a synthetic order with real proofs (keyservers simulated with real
//! keyshares, HDB attestation signed with a test Ed25519 key), builds the
//! Groth16-wrapped record proof, checks every public value, opens one field
//! with 2 of 3 authority shares, and writes contracts/test/fixtures/record.json.
//! Also checks (execute only) that the record circuit counts a database hit
//! and rejects lookup proofs against another root.
//!
//!   SP1_PROVER=cpu cargo run --release -p zk_prover --example record_fixture

use std::num::NonZeroU32;

use alloy_sol_types::{sol, SolType};
use curve25519_dalek::scalar::Scalar;
use doprf::active_security::{commitments_from_secret_and_keyshares, ActiveSecurityKey};
use doprf::dleq::{keyserve_domain, DleqProof};
use doprf::party::{KeyserverId, KeyserverIdSet};
use doprf::prf::{generate_keyshares, HashPart, KeyShare, QueryStateSet};
use doprf::tagged::{HashTag, TaggedHash};
use ed25519_dalek::{Signer, SigningKey};
use packed_ristretto::PackedRistrettos;
use hdb_trie::Trie;
use rand::rngs::OsRng;
use rand::Rng;
use zk_escrow::{combine_shares, deal_committee, decode_windows, decryption_share, EncryptedField};
use zk_prover::{ClientProver, ProofMode, RecordProofKind};
use zk_types::{concat, HdbAttestation, SignedHdbAttestation, ZkReceipt};

sol! {
    struct RecordPublicValues {
        bytes32 circuitsDigest;
        bytes32 statementDigest;
        bytes32 orderCommitment;
        bytes32 activeSecurityKeyDigest;
        bytes32 hdbPublicKey;
        bytes32 hdbRoot;
        uint32 hazardCount;
        uint32 lookupHits;
        uint64 screenedAt;
        bytes32 committeeKey;
        bytes32[] fieldDigests;
    }
}

const WINDOWS: [&str; 2] = [
    "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTAC",
    "CGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACG",
];

/// Entries in the synthetic hazard database.
const TEST_DB_ENTRIES: usize = 100_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let kind = match std::env::var("RECORD_PROOF").as_deref() {
        Ok("execute") => RecordProofKind::Execute,
        Ok("compressed") => RecordProofKind::Compressed,
        _ => RecordProofKind::Groth16,
    };
    let prover = ClientProver::new().await?;

    // Keyservers (2-of-3) with real keyshares.
    let secret = KeyShare::from(Scalar::random(&mut OsRng));
    let two = NonZeroU32::new(2).unwrap();
    let shares = generate_keyshares(&secret, two, NonZeroU32::new(3).unwrap(), &mut OsRng)?;
    let ask = ActiveSecurityKey::from_commitments(commitments_from_secret_and_keyshares(&secret, &shares, two)?);
    let chosen: Vec<(KeyserverId, KeyShare)> = shares
        .into_iter()
        .take(2)
        .enumerate()
        .map(|(i, s)| (KeyserverId::try_from(i as u32 + 1).unwrap(), s))
        .collect();
    let ids: KeyserverIdSet = chosen.iter().map(|(id, _)| *id).collect();
    let id_list: Vec<u32> = ids.iter().map(u32::from).collect();

    // Screening with real compressed proofs.
    let (qs, witness) = QueryStateSet::from_iter_with_witness(
        WINDOWS.iter().enumerate().map(|(i, w)| (HashTag::new(i == 0, 0, i), w.as_bytes())),
        2,
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
    eprintln!("screening proved: {:?}", screening.timings);

    // The HDB's attestation (test key standing in for the HDB's SCEP key).
    let mut done = qs.clone();
    for (id, packed, _) in &responses {
        let parts: Vec<HashPart> = packed.iter_decoded().collect::<Result<_, _>>()?;
        done.incorporate_response(*id, &parts)?;
    }
    let packed: PackedRistrettos<TaggedHash> = done.get_hash_values()?.into_iter().collect();
    assert_eq!(screening.statement.hdb_hashes_digest, zk_types::hdb_hashes_digest(&concat(packed.iter_encoded())));
    let hdb_hashes = concat(packed.iter_encoded());
    // A synthetic hazard database (random entries) that the order misses.
    let db: Vec<([u8; 32], [u8; 8])> = (0..TEST_DB_ENTRIES).map(|_| (OsRng.gen(), OsRng.gen())).collect();
    let trie = Trie::new(db.clone());
    let hdb_key = SigningKey::generate(&mut OsRng);
    let make_receipt = |trie: &Trie, hazard_count: u32| {
        let attestation = HdbAttestation {
            statement_digest: zk_types::statement_digest(&screening.statement),
            hdb_hashes_digest: screening.statement.hdb_hashes_digest,
            hazard_count,
            timestamp: 1_790_000_000,
            hdb_public_key: hdb_key.verifying_key().to_bytes(),
            hdb_root: trie.root(),
        };
        let signature = hdb_key.sign(&attestation.message()).to_bytes().to_vec();
        ZkReceipt {
            statement: screening.statement.clone(),
            proof: screening.proof.clone().expect("prove mode"),
            salt: screening.salt,
            attestation: SignedHdbAttestation { attestation, signature },
            windows: witness.windows.clone(),
            hdb_hashes: hdb_hashes.clone(),
            lookups: trie.lookups(&hdb_hashes).unwrap(),
        }
    };
    let receipt = make_receipt(&trie, 0);
    let attestation = receipt.attestation.attestation.clone();

    if let Ok(path) = std::env::var("RECEIPT_OUT") {
        std::fs::write(&path, serde_json::to_vec(&receipt)?)?;
        eprintln!("wrote receipt to {path}");
    }

    // Committee (3 authorities, any 2 can open) and the record proof.
    let (committee_key, authority_shares) = deal_committee(2, 3);
    let committee_bytes = committee_key.compress().to_bytes();
    let metadata = vec![b"plasmid backbone test".to_vec(), b"lab:test-001".to_vec()];

    // The record circuit counts database hits from the lookup proofs: add the
    // order's first hash to the database and it reports one hit.
    let mut with_hit = db.clone();
    with_hit.push((hdb_hashes[4..36].try_into().unwrap(), [0; 8]));
    let hit_receipt = make_receipt(&Trie::new(with_hit), 1);
    let hit = prover.prove_record(RecordProofKind::Execute, &hit_receipt, &metadata, &committee_bytes).await?;
    assert_eq!(RecordPublicValues::abi_decode(&hit.public_values)?.lookupHits, 1);
    // Lookup proofs against a different root than the one attested are rejected.
    let mut forged = receipt.clone();
    forged.lookups = hit_receipt.lookups.clone();
    assert!(prover.prove_record(RecordProofKind::Execute, &forged, &metadata, &committee_bytes).await.is_err());
    eprintln!("lookup checks passed (hit counted, foreign root rejected)");

    let record = prover.prove_record(kind, &receipt, &metadata, &committee_bytes).await?;
    eprintln!("record proved ({kind:?}): {} cycles, {:.1?}", record.cycles, record.prove_time);

    // Every public value is what it should be.
    let pv = RecordPublicValues::abi_decode(&record.public_values)?;
    assert_eq!(pv.circuitsDigest.0, prover.circuits_digest());
    assert_eq!(pv.statementDigest.0, attestation.statement_digest);
    assert_eq!(pv.orderCommitment.0, screening.statement.order_commitment);
    assert_eq!(pv.activeSecurityKeyDigest.0, zk_types::active_security_key_digest(&ask.commitment_bytes()));
    assert_eq!(pv.hdbPublicKey.0, attestation.hdb_public_key);
    assert_eq!(pv.hdbRoot.0, trie.root());
    assert_eq!(pv.hazardCount, 0);
    assert_eq!(pv.lookupHits, 0);
    assert_eq!(pv.screenedAt, attestation.timestamp);
    assert_eq!(pv.committeeKey.0, committee_bytes);
    assert_eq!(pv.fieldDigests.len(), 3);
    let fields: Vec<EncryptedField> =
        record.fields.iter().map(|f| EncryptedField::from_bytes(f).unwrap()).collect();
    for (f, d) in fields.iter().zip(&pv.fieldDigests) {
        assert_eq!(&f.digest(), &d.0);
    }

    // Authorities 1 and 3 open field 0 (the windows) and field 2 only.
    let keys: Vec<_> = authority_shares.iter().map(|a| (a.index, a.public_key())).collect();
    let record_id = pv.statementDigest.0;
    for field in [0u32, 2] {
        let opened: Vec<_> = [0usize, 2]
            .iter()
            .map(|&k| decryption_share(&authority_shares[k], &record_id, field, &fields[field as usize]).unwrap())
            .collect();
        let s = combine_shares(&keys, 2, &record_id, field, &fields[field as usize], &opened)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let plaintext = zk_escrow::decrypt_field(&s, field, &fields[field as usize]);
        if field == 0 {
            assert_eq!(decode_windows(&plaintext).unwrap(), witness.windows);
        } else {
            assert_eq!(plaintext, metadata[1]);
        }
    }
    eprintln!("record checks and 2-of-3 field opening passed");

    let fixture = serde_json::json!({
        "recordVkey": record.record_vkey,
        "publicValues": format!("0x{}", hex::encode(&record.public_values)),
        "proof": format!("0x{}", hex::encode(&record.proof)),
        "fields": record.fields.iter().map(|f| format!("0x{}", hex::encode(f))).collect::<Vec<_>>(),
        "circuitsDigest": format!("0x{}", hex::encode(pv.circuitsDigest.0)),
        "statementDigest": format!("0x{}", hex::encode(pv.statementDigest.0)),
        "activeSecurityKeyDigest": format!("0x{}", hex::encode(pv.activeSecurityKeyDigest.0)),
        "hdbPublicKey": format!("0x{}", hex::encode(pv.hdbPublicKey.0)),
        "hdbRoot": format!("0x{}", hex::encode(pv.hdbRoot.0)),
        "committeeKey": format!("0x{}", hex::encode(committee_bytes)),
        "screenedAt": pv.screenedAt,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/fixtures/record.json");
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, serde_json::to_string_pretty(&fixture)?)?;
    eprintln!("wrote {}", path.display());
    Ok(())
}
