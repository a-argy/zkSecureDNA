// SPDX-License-Identifier: MIT OR Apache-2.0

//! `zksecuredna`: off-chain tooling around the on-chain registry
//! (contracts/src/ZkSecureDNARegistry.sol).
//!
//! * labs:        `record` turns a screening receipt into a submission
//! * authorities: `share` produces a sealed decryption share for a case
//! * recipients:  `recipient-keygen`, `open` verifies, combines, decrypts
//! * dev only:    `committee-deal` creates a committee with a trusted dealer

use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use zk_escrow::{EncryptedField, FIELD_NAMES};

#[derive(Parser)]
#[command(name = "zksecuredna", about = "zkSecureDNA record and investigation tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an authority committee with a trusted dealer (development only;
    /// a deployment should use a distributed key generation).
    CommitteeDeal {
        #[arg(long)]
        threshold: u32,
        #[arg(long)]
        members: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a registry submission from a screening receipt.
    Record {
        #[arg(long)]
        receipt: PathBuf,
        /// Committee key (hex), as stored in the registry.
        #[arg(long)]
        committee_key: String,
        /// Metadata fields `name=value` for purpose, lab_id, printer_id,
        /// location, timestamp (all required; see zk_escrow::FIELD_NAMES).
        #[arg(long = "field", value_parser = parse_kv)]
        fields: Vec<(String, String)>,
        /// groth16 (on-chain), compressed, or execute (no proof).
        #[arg(long, default_value = "groth16")]
        proof: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a case recipient keypair.
    RecipientKeygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// As an authority, produce a sealed decryption share for one field of a
    /// record in an authorized case (post it with submitDecryptionShare).
    Share {
        /// This authority's share file from committee setup.
        #[arg(long)]
        share: PathBuf,
        /// The record's statementDigest (hex).
        #[arg(long)]
        record_id: String,
        #[arg(long)]
        field: u32,
        /// The field's on-chain ciphertext `R ‖ ct` (hex), from RecordSubmitted.
        #[arg(long)]
        encrypted_field: String,
        /// The case's recipientKey (hex).
        #[arg(long)]
        recipient: String,
    },
    /// As the case recipient, unseal and verify shares, combine them and
    /// decrypt one field.
    Open {
        #[arg(long)]
        recipient_key: PathBuf,
        #[arg(long)]
        committee: PathBuf,
        #[arg(long)]
        record_id: String,
        #[arg(long)]
        field: u32,
        #[arg(long)]
        encrypted_field: String,
        /// Sealed shares (hex) from DecryptionShareSubmitted events.
        #[arg(long = "sealed", required = true)]
        sealed: Vec<String>,
    },
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected name=value, got {s:?}"))
}

#[derive(Serialize, Deserialize)]
struct CommitteeFile {
    threshold: u32,
    committee_key: String,
    members: Vec<CommitteeMember>,
}

#[derive(Serialize, Deserialize)]
struct CommitteeMember {
    index: u32,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct ShareFile {
    index: u32,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    public_key: String,
    secret: String,
}

fn hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes of hex"))
}

fn scalar(s: &str) -> anyhow::Result<Scalar> {
    Option::from(Scalar::from_canonical_bytes(hex32(s)?)).context("not a canonical scalar")
}

fn point(s: &str) -> anyhow::Result<curve25519_dalek::ristretto::RistrettoPoint> {
    zk_escrow::decompress(&hex32(s)?).context("not a valid Ristretto point")
}

fn encrypted_field(s: &str) -> anyhow::Result<EncryptedField> {
    EncryptedField::from_bytes(&hex::decode(s.trim_start_matches("0x"))?).context("malformed encrypted field")
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?).with_context(|| format!("writing {}", path.display()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::CommitteeDeal { threshold, members, out } => {
            if threshold == 0 || threshold > members {
                bail!("need 0 < threshold <= members");
            }
            std::fs::create_dir_all(&out)?;
            let (key, shares) = zk_escrow::deal_committee(threshold, members);
            let committee = CommitteeFile {
                threshold,
                committee_key: hex::encode(key.compress().as_bytes()),
                members: shares
                    .iter()
                    .map(|s| CommitteeMember { index: s.index, public_key: hex::encode(s.public_key().compress().as_bytes()) })
                    .collect(),
            };
            write_json(&out.join("committee.json"), &committee)?;
            for s in &shares {
                write_json(
                    &out.join(format!("share-{}.json", s.index)),
                    &ShareFile { index: s.index, secret: hex::encode(s.secret.to_bytes()) },
                )?;
            }
            println!("committee key 0x{}; give share-<i>.json to authority i only", committee.committee_key);
        }
        Command::Record { receipt, committee_key, fields, proof, out } => {
            let receipt: zk_types::ZkReceipt = serde_json::from_slice(&std::fs::read(&receipt)?)?;
            let metadata = FIELD_NAMES[1..]
                .iter()
                .map(|name| {
                    fields
                        .iter()
                        .find(|(k, _)| k == name)
                        .map(|(_, v)| v.as_bytes().to_vec())
                        .with_context(|| format!("missing --field {name}=..."))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let kind = match proof.as_str() {
                "groth16" => zk_prover::RecordProofKind::Groth16,
                "compressed" => zk_prover::RecordProofKind::Compressed,
                "execute" => zk_prover::RecordProofKind::Execute,
                other => bail!("unknown proof kind {other}"),
            };
            let prover = zk_prover::ClientProver::new().await?;
            let submission = prover.prove_record(kind, &receipt, &metadata, &hex32(&committee_key)?).await?;
            write_json(&out, &submission)?;
            println!("wrote {} ({} fields, {:.1?})", out.display(), submission.fields.len(), submission.prove_time);
        }
        Command::RecipientKeygen { out } => {
            let secret = Scalar::random(&mut rand::rngs::OsRng);
            let public_key = hex::encode((RISTRETTO_BASEPOINT_POINT * secret).compress().as_bytes());
            write_json(&out, &KeyFile { public_key: public_key.clone(), secret: hex::encode(secret.to_bytes()) })?;
            println!("recipient key 0x{public_key}");
        }
        Command::Share { share, record_id, field, encrypted_field: ef, recipient } => {
            let share: ShareFile = serde_json::from_slice(&std::fs::read(&share)?)?;
            let authority = zk_escrow::AuthorityShare { index: share.index, secret: scalar(&share.secret)? };
            let ds = zk_escrow::decryption_share(&authority, &hex32(&record_id)?, field, &encrypted_field(&ef)?)
                .context("could not compute share")?;
            println!("0x{}", hex::encode(zk_escrow::seal_share(&point(&recipient)?, &ds)));
        }
        Command::Open { recipient_key, committee, record_id, field, encrypted_field: ef, sealed } => {
            let key: KeyFile = serde_json::from_slice(&std::fs::read(&recipient_key)?)?;
            let committee: CommitteeFile = serde_json::from_slice(&std::fs::read(&committee)?)?;
            let secret = scalar(&key.secret)?;
            let shares = sealed
                .iter()
                .map(|s| {
                    zk_escrow::unseal_share(&secret, &hex::decode(s.trim_start_matches("0x"))?)
                        .context("share is not sealed to this recipient")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let keys = committee
                .members
                .iter()
                .map(|m| Ok((m.index, point(&m.public_key)?)))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let field_ct = encrypted_field(&ef)?;
            let shared = zk_escrow::combine_shares(
                &keys,
                committee.threshold as usize,
                &hex32(&record_id)?,
                field,
                &field_ct,
                &shares,
            )
            .map_err(|e| anyhow::anyhow!("cannot open: {e:?}"))?;
            let plaintext = zk_escrow::decrypt_field(&shared, field, &field_ct);
            if field == 0 {
                let windows = zk_escrow::decode_windows(&plaintext).context("field 0 is not window data")?;
                for w in windows {
                    println!("{}", String::from_utf8_lossy(&w));
                }
            } else {
                println!("{}", String::from_utf8_lossy(&plaintext));
            }
        }
    }
    Ok(())
}
