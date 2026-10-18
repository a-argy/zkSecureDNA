// SPDX-License-Identifier: MIT OR Apache-2.0

//! zkSecureDNA record escrow: each record field is encrypted to an
//! authority committee whose secret key is Shamir-shared t-of-N, so no single
//! authority can open a record, any t together can, and each field opens
//! independently. See docs/ZK-DESIGN.md ("On-chain records").
//!
//! Per field `f` (hashed-ElGamal / ECIES over Ristretto):
//!   R_f = r_f·G,  S_f = r_f·PK,  key_f = H(S_f, f),
//!   ct_f = plaintext ⊕ keystream(key_f),
//!   digest_f = SHA-256(R_f ‖ ct_f)   (committed by the record circuit,
//!                                     checked by the contract).
//! Opening: authority i publishes D_i = sk_i·R_f with a DLEQ proof against
//! PK_i = sk_i·G; any t shares interpolate to S_f.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use doprf::dleq::{self, DleqProof};
use doprf::party::{KeyserverId, KeyserverIdSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Bytes32 = [u8; 32];

/// One encrypted field as stored on chain: `R_f ‖ ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedField {
    pub ephemeral: Bytes32,
    pub ciphertext: Vec<u8>,
}

impl EncryptedField {
    /// The on-chain encoding (`R_f ‖ ciphertext`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (r, ct) = (bytes.get(..32)?, &bytes[32..]);
        Some(Self { ephemeral: r.try_into().ok()?, ciphertext: ct.to_vec() })
    }

    /// `SHA-256(R_f ‖ ct_f)`; the Solidity side computes `sha256(bytes)`.
    pub fn digest(&self) -> Bytes32 {
        Sha256::digest(self.to_bytes()).into()
    }
}

fn field_key(shared: &RistrettoPoint, field_index: u32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"zksecuredna/field-key/v1");
    h.update(shared.compress().as_bytes());
    h.update(field_index.to_le_bytes());
    h.finalize().into()
}

fn apply_keystream(key: &Bytes32, data: &mut [u8]) {
    for (block, chunk) in data.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(key);
        h.update((block as u64).to_le_bytes());
        let pad: Bytes32 = h.finalize().into();
        for (b, p) in chunk.iter_mut().zip(pad) {
            *b ^= p;
        }
    }
}

pub fn decompress(bytes: &Bytes32) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

/// Encrypts `plaintext` as field `field_index` to `committee_key` using the
/// ephemeral scalar `r` (which must be fresh and uniformly random).
pub fn encrypt_field(
    committee_key: &RistrettoPoint,
    field_index: u32,
    r: &Scalar,
    plaintext: &[u8],
) -> EncryptedField {
    let ephemeral = (RISTRETTO_BASEPOINT_POINT * r).compress().to_bytes();
    let key = field_key(&(committee_key * r), field_index);
    let mut ciphertext = plaintext.to_vec();
    apply_keystream(&key, &mut ciphertext);
    EncryptedField { ephemeral, ciphertext }
}

/// Decrypts with the reconstructed shared point `S_f = sk·R_f`.
pub fn decrypt_field(shared: &RistrettoPoint, field_index: u32, field: &EncryptedField) -> Vec<u8> {
    let key = field_key(shared, field_index);
    let mut plaintext = field.ciphertext.clone();
    apply_keystream(&key, &mut plaintext);
    plaintext
}

/// Standard record fields, in order. Field 0 is always the screened windows.
pub const FIELD_NAMES: [&str; 6] =
    ["sequence", "purpose", "lab_id", "printer_id", "location", "timestamp"];

/// Encodes screened windows as field 0 (length-prefixed, like the order commitment).
pub fn encode_windows(windows: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for w in windows {
        out.extend_from_slice(&(w.len() as u64).to_le_bytes());
        out.extend_from_slice(w);
    }
    out
}

pub fn decode_windows(mut bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?) as usize;
        out.push(bytes.get(8..8 + len)?.to_vec());
        bytes = &bytes[8 + len..];
    }
    Some(out)
}

// ---- Committee (threshold) side -------------------------------------------

/// One authority's key share. `index` is its Shamir x-coordinate (1..=N).
#[derive(Debug, Clone, Copy)]
pub struct AuthorityShare {
    pub index: u32,
    pub secret: Scalar,
}

impl AuthorityShare {
    pub fn public_key(&self) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT * self.secret
    }
}

/// Committee setup by a trusted dealer (development only; a deployment
/// would run a DKG). Returns the committee key and the N shares.
pub fn deal_committee(threshold: u32, members: u32) -> (RistrettoPoint, Vec<AuthorityShare>) {
    use rand::rngs::OsRng;
    let mut coeffs = vec![Scalar::random(&mut OsRng)];
    coeffs.extend((1..threshold).map(|_| Scalar::random(&mut OsRng)));
    let shares = (1..=members)
        .map(|x| {
            let xs = Scalar::from(x);
            let mut acc = Scalar::ZERO;
            for c in coeffs.iter().rev() {
                acc = acc * xs + c;
            }
            AuthorityShare { index: x, secret: acc }
        })
        .collect();
    (RISTRETTO_BASEPOINT_POINT * coeffs[0], shares)
}

/// A decryption share for one field: `D = sk_i·R_f`, with a DLEQ proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    pub index: u32,
    pub share: Bytes32,
    pub proof: DleqProof,
}

fn share_domain(record_id: &Bytes32, field_index: u32, index: u32) -> Vec<u8> {
    let mut d = b"zksecuredna/decryption-share/v1".to_vec();
    d.extend_from_slice(record_id);
    d.extend_from_slice(&field_index.to_le_bytes());
    d.extend_from_slice(&index.to_le_bytes());
    d
}

pub fn decryption_share(
    authority: &AuthorityShare,
    record_id: &Bytes32,
    field_index: u32,
    field: &EncryptedField,
) -> Option<DecryptionShare> {
    let r = decompress(&field.ephemeral)?;
    let share = (r * authority.secret).compress().to_bytes();
    let proof = dleq::prove(
        &share_domain(record_id, field_index, authority.index),
        &authority.secret,
        &[field.ephemeral],
        &[share],
    )
    .ok()?;
    Some(DecryptionShare { index: authority.index, share, proof })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    NotEnoughShares,
    DuplicateShare,
    UnknownAuthority(u32),
    BadShareProof(u32),
    InvalidPoint,
}

/// Checks each share's proof against the authorities' public keys
/// (`index → PK_i`) and interpolates the shared point `S_f`.
pub fn combine_shares(
    authority_keys: &[(u32, RistrettoPoint)],
    threshold: usize,
    record_id: &Bytes32,
    field_index: u32,
    field: &EncryptedField,
    shares: &[DecryptionShare],
) -> Result<RistrettoPoint, OpenError> {
    if shares.len() < threshold {
        return Err(OpenError::NotEnoughShares);
    }
    let shares = &shares[..threshold];
    let mut seen: Vec<u32> = shares.iter().map(|s| s.index).collect();
    seen.sort_unstable();
    if seen.windows(2).any(|w| w[0] == w[1]) {
        return Err(OpenError::DuplicateShare);
    }
    let mut points = Vec::with_capacity(shares.len());
    for s in shares {
        let pk = authority_keys
            .iter()
            .find(|(i, _)| *i == s.index)
            .map(|(_, pk)| pk)
            .ok_or(OpenError::UnknownAuthority(s.index))?;
        dleq::verify(
            &share_domain(record_id, field_index, s.index),
            pk,
            &[field.ephemeral],
            &[s.share],
            &s.proof,
        )
        .map_err(|_| OpenError::BadShareProof(s.index))?;
        points.push(decompress(&s.share).ok_or(OpenError::InvalidPoint)?);
    }
    // Lagrange interpolation at 0, reusing doprf's coefficient code.
    let ids: KeyserverIdSet = shares
        .iter()
        .map(|s| KeyserverId::try_from(s.index).map_err(|_| OpenError::UnknownAuthority(s.index)))
        .collect::<Result<_, _>>()?;
    Ok(shares
        .iter()
        .zip(points)
        .map(|(s, p)| ids.langrange_coefficient_for_id(&KeyserverId::try_from(s.index).unwrap()) * p)
        .sum())
}

impl DecryptionShare {
    pub const SIZE: usize = 4 + 32 + DleqProof::SIZE;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..36].copy_from_slice(&self.share);
        out[36..].copy_from_slice(&self.proof.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            index: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            share: bytes[4..36].try_into().ok()?,
            proof: DleqProof::from_bytes(bytes[36..].try_into().ok()?),
        })
    }
}

/// Field index used when sealing decryption shares to a case recipient, so
/// share ciphertexts can never be confused with record fields.
const SHARE_SEAL_FIELD: u32 = u32::MAX;

/// Seals a decryption share to the case recipient's key (what an authority
/// posts on chain with `submitDecryptionShare`).
pub fn seal_share(recipient: &RistrettoPoint, share: &DecryptionShare) -> Vec<u8> {
    use rand::rngs::OsRng;
    encrypt_field(recipient, SHARE_SEAL_FIELD, &Scalar::random(&mut OsRng), &share.to_bytes()).to_bytes()
}

/// Opens a sealed share with the recipient's secret key.
pub fn unseal_share(recipient_secret: &Scalar, sealed: &[u8]) -> Option<DecryptionShare> {
    let field = EncryptedField::from_bytes(sealed)?;
    let shared = decompress(&field.ephemeral)? * recipient_secret;
    DecryptionShare::from_bytes(&decrypt_field(&shared, SHARE_SEAL_FIELD, &field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn t_of_n_opens_each_field_independently() {
        let (pk, shares) = deal_committee(3, 5);
        let keys: Vec<_> = shares.iter().map(|s| (s.index, s.public_key())).collect();
        let record_id = [7u8; 32];
        let fields: Vec<&[u8]> = vec![b"window data", b"purpose text", b"lab-42"];
        let enc: Vec<_> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| encrypt_field(&pk, i as u32, &Scalar::random(&mut OsRng), f))
            .collect();

        // Authorities 2, 4, 5 open field 1 only.
        let opened: Vec<_> = [1usize, 3, 4]
            .iter()
            .map(|&k| decryption_share(&shares[k], &record_id, 1, &enc[1]).unwrap())
            .collect();
        let s = combine_shares(&keys, 3, &record_id, 1, &enc[1], &opened).unwrap();
        assert_eq!(decrypt_field(&s, 1, &enc[1]), fields[1]);
        // The same shares do not open another field.
        assert_ne!(decrypt_field(&s, 2, &enc[2]), fields[2]);
    }

    #[test]
    fn fewer_than_t_or_forged_shares_fail() {
        let (pk, shares) = deal_committee(3, 5);
        let keys: Vec<_> = shares.iter().map(|s| (s.index, s.public_key())).collect();
        let record_id = [1u8; 32];
        let enc = encrypt_field(&pk, 0, &Scalar::random(&mut OsRng), b"secret");
        let two: Vec<_> = shares[..2].iter().map(|a| decryption_share(a, &record_id, 0, &enc).unwrap()).collect();
        assert_eq!(combine_shares(&keys, 3, &record_id, 0, &enc, &two), Err(OpenError::NotEnoughShares));

        let mut three: Vec<_> = shares[..3].iter().map(|a| decryption_share(a, &record_id, 0, &enc).unwrap()).collect();
        three[2].share = RistrettoPoint::random(&mut OsRng).compress().to_bytes();
        assert_eq!(combine_shares(&keys, 3, &record_id, 0, &enc, &three), Err(OpenError::BadShareProof(3)));
    }

    #[test]
    fn sealed_shares_open_only_for_the_recipient() {
        let (pk, shares) = deal_committee(2, 3);
        let enc = encrypt_field(&pk, 1, &Scalar::random(&mut OsRng), b"purpose");
        let share = decryption_share(&shares[0], &[9u8; 32], 1, &enc).unwrap();
        let recipient = Scalar::random(&mut OsRng);
        let sealed = seal_share(&(RISTRETTO_BASEPOINT_POINT * recipient), &share);
        let opened = unseal_share(&recipient, &sealed).unwrap();
        assert_eq!(opened.to_bytes(), share.to_bytes());
        let other = Scalar::random(&mut OsRng);
        assert!(unseal_share(&other, &sealed).map(|s| s.to_bytes() != share.to_bytes()).unwrap_or(true));
    }

    #[test]
    fn windows_roundtrip_and_ciphertext_digest() {
        let windows = vec![b"ACGT".to_vec(), b"TTGCA".to_vec()];
        assert_eq!(decode_windows(&encode_windows(&windows)).unwrap(), windows);
        let (pk, _) = deal_committee(2, 3);
        let enc = encrypt_field(&pk, 0, &Scalar::random(&mut OsRng), b"x");
        assert_eq!(EncryptedField::from_bytes(&enc.to_bytes()).unwrap(), enc);
        assert_eq!(enc.digest(), <[u8; 32]>::from(Sha256::digest(enc.to_bytes())));
    }
}
