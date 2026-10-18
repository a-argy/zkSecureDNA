// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host side of the zkSecureDNA circuits. See docs/ZK-DESIGN.md.
//!
//! * [`ClientProver`] runs on the synthesis client: it executes or proves the
//!   hash and checksum circuits from a [`QueryWitness`], then the aggregation
//!   circuit once keyserver responses arrive.
//! * [`ScreeningVerifier`] runs on the HDB: it verifies the final proof against
//!   verifying keys it derives itself, and checks the proof is about the
//!   hashes actually being screened.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use doprf::active_security::ActiveSecurityKey;
use doprf::party::KeyserverId;
use doprf::dleq::DleqProof;
use doprf::prf::{HashPart, QueryWitness, SerializableQueryStateSet};
use packed_ristretto::PackedRistrettos;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::{
    include_elf, Elf, HashableKey, LightProver, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1Proof, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use tokio::sync::OnceCell;
use tracing::info;
use zk_types::{Digest32, ScreeningStatement};

pub use zk_types;

pub const HASH_ELF: Elf = include_elf!("zksecuredna-hash");
pub const CHECKSUM_ELF: Elf = include_elf!("zksecuredna-checksum");
pub const AGGREGATE_ELF: Elf = include_elf!("zksecuredna-aggregate");

/// How the client handles the circuits, from `ZK_PROOF_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// Upstream SecureDNA behaviour: no circuits, plain `/scep/screen`.
    Off,
    /// Run the circuits in the zkVM without proving (fast; development only).
    /// Produces a statement but no proof, so the HDB cannot verify it.
    Execute,
    /// Generate real compressed proofs and use `/scep/screen-and-verify`.
    Prove,
}

impl ProofMode {
    pub fn from_env() -> Self {
        match std::env::var("ZK_PROOF_MODE").as_deref() {
            Ok("prove") => Self::Prove,
            Ok("execute") => Self::Execute,
            _ => Self::Off,
        }
    }
}

/// Output of one circuit run.
#[derive(Clone)]
struct SubProof {
    public_values: SP1PublicValues,
    proof: Option<SP1ProofWithPublicValues>,
    vkey: [u32; 8],
    vk: SP1VerifyingKey,
}

/// Cycle counts and wall-clock times, for benchmarking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CircuitTimings {
    pub hash_cycles: u64,
    pub checksum_cycles: u64,
    pub aggregate_cycles: u64,
    pub query_proofs: Duration,
    pub aggregate_proof: Duration,
}

/// Hash and checksum proofs, produced before contacting keyservers.
pub struct QueryProofs {
    hash: SubProof,
    checksum: SubProof,
    salt: Digest32,
    timings: CircuitTimings,
}

/// The final result handed to the HDB.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScreeningProof {
    pub statement: ScreeningStatement,
    /// Opening salt for `statement.order_commitment`. The lab keeps this; it
    /// is never sent to the HDB.
    #[serde(skip)]
    pub salt: Digest32,
    /// bincode-encoded compressed `SP1ProofWithPublicValues`; `None` in execute mode.
    pub proof: Option<Vec<u8>>,
    #[serde(skip)]
    pub timings: CircuitTimings,
}

pub struct ClientProver {
    client: EnvProver,
    hash_pk: EnvProvingKey,
    checksum_pk: EnvProvingKey,
    aggregate_pk: EnvProvingKey,
}

static CLIENT_PROVER: OnceCell<Arc<ClientProver>> = OnceCell::const_new();

impl ClientProver {
    /// Shared instance; setup takes several seconds, so it is done once.
    pub async fn global() -> anyhow::Result<Arc<Self>> {
        CLIENT_PROVER
            .get_or_try_init(|| async { Self::new().await.map(Arc::new) })
            .await
            .cloned()
    }

    /// Uses `SP1_PROVER` (cpu, cuda, network, mock) to pick a backend.
    pub async fn new() -> anyhow::Result<Self> {
        let client = ProverClient::from_env().await;
        let hash_pk = client.setup(HASH_ELF).await.context("hash circuit setup")?;
        let checksum_pk = client.setup(CHECKSUM_ELF).await.context("checksum circuit setup")?;
        let aggregate_pk = client.setup(AGGREGATE_ELF).await.context("aggregate circuit setup")?;
        Ok(Self { client, hash_pk, checksum_pk, aggregate_pk })
    }

    async fn run(
        &self,
        mode: ProofMode,
        pk: &EnvProvingKey,
        stdin: SP1Stdin,
        deferred_proofs: bool,
    ) -> anyhow::Result<(SubProof, u64)> {
        let vk = pk.verifying_key().clone();
        let vkey = vk.hash_u32();
        // Always execute first: cheap, gives cycle counts, fails fast.
        let (public_values, report) = self
            .client
            .execute(pk.elf().clone(), stdin.clone())
            .deferred_proof_verification(deferred_proofs)
            .await?;
        let cycles = report.total_instruction_count() + report.total_syscall_count();
        let proof = match mode {
            ProofMode::Prove => Some(self.client.prove(pk, stdin).compressed().await?),
            _ => None,
        };
        Ok((SubProof { public_values, proof, vkey, vk }, cycles))
    }

    pub async fn prove_queries(
        &self,
        mode: ProofMode,
        witness: &QueryWitness,
        active_security_key: &ActiveSecurityKey,
    ) -> anyhow::Result<QueryProofs> {
        let start = Instant::now();
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let mut hash_stdin = SP1Stdin::new();
        hash_stdin.write(&salt);
        hash_stdin.write(&witness.windows);
        hash_stdin.write(&witness.blinding_factors);

        let mut checksum_stdin = SP1Stdin::new();
        checksum_stdin.write(active_security_key);
        checksum_stdin.write(&witness.sum);
        checksum_stdin.write(&witness.random_modifier);
        checksum_stdin.write(&witness.checksum_verification_factor);
        checksum_stdin.write(&witness.checksum_blinding_factor);

        let (hash, checksum) = tokio::try_join!(
            self.run(mode, &self.hash_pk, hash_stdin, true),
            self.run(mode, &self.checksum_pk, checksum_stdin, true),
        )?;

        let timings = CircuitTimings {
            hash_cycles: hash.1,
            checksum_cycles: checksum.1,
            query_proofs: start.elapsed(),
            ..Default::default()
        };
        info!(?timings, "zk: query circuits done");
        Ok(QueryProofs { hash: hash.0, checksum: checksum.0, salt, timings })
    }

    pub async fn prove_screening(
        &self,
        mode: ProofMode,
        query_proofs: QueryProofs,
        querystate: &SerializableQueryStateSet,
        keyserver_responses: &[(KeyserverId, PackedRistrettos<HashPart>, DleqProof)],
    ) -> anyhow::Result<ScreeningProof> {
        let start = Instant::now();
        let QueryProofs { hash, checksum, salt, mut timings } = query_proofs;

        let mut stdin = SP1Stdin::new();
        for sub in [&hash, &checksum] {
            stdin.write(&sub.vkey);
            stdin.write(&sub.public_values.to_vec());
        }
        stdin.write(querystate);
        stdin.write(&keyserver_responses.to_vec());
        // The proofs themselves are witnessed by SP1's recursion, not read by the guest.
        for sub in [&hash, &checksum] {
            if let Some(proof) = &sub.proof {
                let SP1Proof::Compressed(p) = &proof.proof else {
                    anyhow::bail!("sub-proof is not compressed");
                };
                stdin.write_proof((**p).clone(), sub.vk.vk.clone());
            }
        }

        // In execute mode there are no sub-proofs to check.
        let deferred = mode == ProofMode::Prove;
        let (aggregate, cycles) = self.run(mode, &self.aggregate_pk, stdin, deferred).await?;
        let statement = aggregate.public_values.clone().read::<ScreeningStatement>();

        timings.aggregate_cycles = cycles;
        timings.aggregate_proof = start.elapsed();
        info!(?timings, "zk: aggregate circuit done");

        let proof = aggregate
            .proof
            .map(|p| bincode::serialize(&p))
            .transpose()
            .context("serializing proof")?;
        Ok(ScreeningProof { statement, salt, proof, timings })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed proof: {0}")]
    Malformed(String),
    #[error("proof did not verify: {0}")]
    Invalid(String),
    #[error("proof is for a different {0} circuit than this server trusts")]
    WrongCircuit(&'static str),
    #[error("proof is not about the hashes in this request")]
    HashesMismatch,
    #[error("proof used an active-security key this server does not trust")]
    WrongActiveSecurityKey,
}

/// Verifies screening proofs. Verifying keys are derived from this build's
/// own copies of the circuits, never taken from the client.
pub struct ScreeningVerifier {
    prover: LightProver,
    aggregate_vk: SP1VerifyingKey,
    hash_vkey: [u32; 8],
    checksum_vkey: [u32; 8],
}

impl ScreeningVerifier {
    pub async fn new() -> anyhow::Result<Self> {
        let prover = ProverClient::builder().light().build().await;
        let vk = |pk: sp1_sdk::SP1ProvingKey| pk.verifying_key().clone();
        let aggregate_vk = vk(prover.setup(AGGREGATE_ELF).await?);
        let hash_vkey = vk(prover.setup(HASH_ELF).await?).hash_u32();
        let checksum_vkey = vk(prover.setup(CHECKSUM_ELF).await?).hash_u32();
        info!(
            aggregate = aggregate_vk.bytes32(),
            "zk: screening verifier ready"
        );
        Ok(Self { prover, aggregate_vk, hash_vkey, checksum_vkey })
    }

    /// `hdb_request_bytes` must be exactly the encoded hashes being screened.
    /// CPU-heavy: call from `spawn_blocking`.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        hdb_request_bytes: &[u8],
        trusted_active_security_key: Option<&Digest32>,
    ) -> Result<ScreeningStatement, VerifyError> {
        let proof: SP1ProofWithPublicValues =
            bincode::deserialize(proof_bytes).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        self.prover
            .verify(&proof, &self.aggregate_vk, None)
            .map_err(|e| VerifyError::Invalid(e.to_string()))?;

        let statement = proof.public_values.clone().read::<ScreeningStatement>();
        if statement.hash_vkey != self.hash_vkey {
            return Err(VerifyError::WrongCircuit("hash"));
        }
        if statement.checksum_vkey != self.checksum_vkey {
            return Err(VerifyError::WrongCircuit("checksum"));
        }
        if statement.hdb_hashes_digest != zk_types::hdb_hashes_digest(hdb_request_bytes) {
            return Err(VerifyError::HashesMismatch);
        }
        if let Some(ask) = trusted_active_security_key {
            if &statement.active_security_key_digest != ask {
                return Err(VerifyError::WrongActiveSecurityKey);
            }
        }
        Ok(statement)
    }
}
