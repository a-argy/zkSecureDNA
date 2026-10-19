// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batched Chaum–Pedersen proofs of discrete-log equality (zkSecureDNA).
//!
//! A keyserver with secret `x` (its keyshare times its Lagrange coefficient)
//! proves that every response `P_j` equals `x * Q_j` for the queries `Q_j`,
//! and that the same `x` satisfies `Y = x * G` for its public key `Y`. This is
//! the standard verifiable-PRF construction: it shows the keyserver evaluated
//! the DOPRF correctly, and since only the holder of `x` can produce it, it
//! also authenticates the response.
//!
//! Batching: the per-query statements are folded into one with Fiat–Shamir
//! weights `rho_j` derived from the whole transcript, so one 64-byte proof
//! covers any number of queries.
//!
//! The same proof is used for threshold-decryption shares (`D = sk_i * R`
//! against `PK_i = sk_i * G`).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

/// A batched DLEQ proof: challenge `e` and response `s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DleqProof {
    pub e: [u8; 32],
    pub s: [u8; 32],
}

impl DleqProof {
    pub const SIZE: usize = 64;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.e);
        out[32..].copy_from_slice(&self.s);
        out
    }

    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut e = [0u8; 32];
        let mut s = [0u8; 32];
        e.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Self { e, s }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DleqError {
    LengthMismatch,
    InvalidPoint,
    InvalidScalar,
    Invalid,
}

impl std::fmt::Display for DleqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LengthMismatch => "inputs and outputs have different lengths",
            Self::InvalidPoint => "invalid Ristretto point",
            Self::InvalidScalar => "non-canonical scalar",
            Self::Invalid => "proof does not verify",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DleqError {}

fn decompress(bytes: &[u8; 32]) -> Result<RistrettoPoint, DleqError> {
    CompressedRistretto(*bytes).decompress().ok_or(DleqError::InvalidPoint)
}

/// Folds `inputs`/`outputs` into single points with transcript-bound weights.
fn fold(
    domain: &[u8],
    public_key: &[u8; 32],
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
) -> Result<(RistrettoPoint, RistrettoPoint), DleqError> {
    if inputs.len() != outputs.len() {
        return Err(DleqError::LengthMismatch);
    }
    let mut seed = Sha3_512::new();
    seed.update(b"zksecuredna/dleq-batch/v1");
    seed.update((domain.len() as u64).to_le_bytes());
    seed.update(domain);
    seed.update(public_key);
    seed.update((inputs.len() as u64).to_le_bytes());
    for (q, p) in inputs.iter().zip(outputs) {
        seed.update(q);
        seed.update(p);
    }
    let seed = seed.finalize();

    let weights: Vec<Scalar> = (0..inputs.len() as u64)
        .map(|j| {
            let mut h = Sha3_512::new();
            h.update(seed);
            h.update(j.to_le_bytes());
            Scalar::from_hash(h)
        })
        .collect();
    let qs = inputs.iter().map(decompress).collect::<Result<Vec<_>, _>>()?;
    let ps = outputs.iter().map(decompress).collect::<Result<Vec<_>, _>>()?;
    Ok((
        RistrettoPoint::vartime_multiscalar_mul(&weights, &qs),
        RistrettoPoint::vartime_multiscalar_mul(&weights, &ps),
    ))
}

fn challenge(
    domain: &[u8],
    public_key: &RistrettoPoint,
    q: &RistrettoPoint,
    p: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"zksecuredna/dleq-challenge/v1");
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    for point in [public_key, q, p, a1, a2] {
        h.update(point.compress().as_bytes());
    }
    Scalar::from_hash(h)
}

/// Proves `outputs[j] = secret * inputs[j]` for all `j`, and
/// `secret * G = public key`. `domain` binds the proof to a context.
pub fn prove(
    domain: &[u8],
    secret: &Scalar,
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
) -> Result<DleqProof, DleqError> {
    let public_key = RISTRETTO_BASEPOINT_POINT * secret;
    let (q, p) = fold(domain, public_key.compress().as_bytes(), inputs, outputs)?;
    let r = Scalar::random(&mut OsRng);
    let a1 = RISTRETTO_BASEPOINT_POINT * r;
    let a2 = q * r;
    let e = challenge(domain, &public_key, &q, &p, &a1, &a2);
    let s = r - e * secret;
    Ok(DleqProof { e: e.to_bytes(), s: s.to_bytes() })
}

/// Verifies a proof produced by [`prove`].
pub fn verify(
    domain: &[u8],
    public_key: &RistrettoPoint,
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    proof: &DleqProof,
) -> Result<(), DleqError> {
    let e = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.e)).ok_or(DleqError::InvalidScalar)?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.s)).ok_or(DleqError::InvalidScalar)?;
    let (q, p) = fold(domain, public_key.compress().as_bytes(), inputs, outputs)?;
    // An empty batch folds to the identity, which proves nothing about `secret`.
    if q == RistrettoPoint::identity() {
        return Err(DleqError::Invalid);
    }
    let a1 = RistrettoPoint::vartime_multiscalar_mul([s, e], [RISTRETTO_BASEPOINT_POINT, *public_key]);
    let a2 = RistrettoPoint::vartime_multiscalar_mul([s, e], [q, p]);
    if challenge(domain, public_key, &q, &p, &a1, &a2) == e {
        Ok(())
    } else {
        Err(DleqError::Invalid)
    }
}

/// Domain for keyserver response proofs: binds keyserver id and quorum.
pub fn keyserve_domain(keyserver_id: u32, keyserver_ids: &[u32]) -> Vec<u8> {
    let mut d = b"zksecuredna/keyserve/v1".to_vec();
    d.extend_from_slice(&keyserver_id.to_le_bytes());
    d.extend_from_slice(&(keyserver_ids.len() as u32).to_le_bytes());
    for id in keyserver_ids {
        d.extend_from_slice(&id.to_le_bytes());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn points(n: usize) -> Vec<RistrettoPoint> {
        (0..n).map(|_| RistrettoPoint::random(&mut OsRng)).collect()
    }

    fn compress(ps: &[RistrettoPoint]) -> Vec<[u8; 32]> {
        ps.iter().map(|p| p.compress().to_bytes()).collect()
    }

    #[test]
    fn honest_proof_verifies() {
        let x = Scalar::random(&mut OsRng);
        let qs = points(5);
        let ps: Vec<_> = qs.iter().map(|q| q * x).collect();
        let proof = prove(b"d", &x, &compress(&qs), &compress(&ps)).unwrap();
        verify(b"d", &(RISTRETTO_BASEPOINT_POINT * x), &compress(&qs), &compress(&ps), &proof).unwrap();
    }

    #[test]
    fn rejects_one_wrong_output() {
        let x = Scalar::random(&mut OsRng);
        let qs = points(5);
        let mut ps: Vec<_> = qs.iter().map(|q| q * x).collect();
        ps[3] = RistrettoPoint::random(&mut OsRng);
        // A cheater cannot produce a proof for wrong outputs; even the honest
        // prover's algorithm yields one that fails.
        let proof = prove(b"d", &x, &compress(&qs), &compress(&ps)).unwrap();
        assert_eq!(
            verify(b"d", &(RISTRETTO_BASEPOINT_POINT * x), &compress(&qs), &compress(&ps), &proof),
            Err(DleqError::Invalid)
        );
    }

    #[test]
    fn rejects_wrong_key_or_domain() {
        let x = Scalar::random(&mut OsRng);
        let qs = points(3);
        let ps: Vec<_> = qs.iter().map(|q| q * x).collect();
        let proof = prove(b"d", &x, &compress(&qs), &compress(&ps)).unwrap();
        let other = RistrettoPoint::random(&mut OsRng);
        assert!(verify(b"d", &other, &compress(&qs), &compress(&ps), &proof).is_err());
        assert!(verify(b"other", &(RISTRETTO_BASEPOINT_POINT * x), &compress(&qs), &compress(&ps), &proof).is_err());
    }

    #[test]
    fn rejects_empty_batch() {
        let x = Scalar::random(&mut OsRng);
        let proof = prove(b"d", &x, &[], &[]).unwrap();
        assert!(verify(b"d", &(RISTRETTO_BASEPOINT_POINT * x), &[], &[], &proof).is_err());
    }
}
