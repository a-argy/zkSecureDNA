//! Hash circuit: proves the blinded queries were derived from real DNA windows.
//!
//! For each window `x_i` with blinding factor `b_i`, computes the query
//! `b_i * H(x_i)` exactly as `QueryState::from_rp` does, and commits a digest
//! of the queries plus a hiding commitment to the windows.

#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha3::Sha3_512;
use zk_types::{order_commitment, queries_digest, HashOutput};

pub fn main() {
    let salt = sp1_zkvm::io::read::<[u8; 32]>();
    let windows = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let blinding_factors = sp1_zkvm::io::read::<Vec<[u8; 32]>>();
    assert_eq!(windows.len(), blinding_factors.len(), "one blinding factor per window");

    let queries: Vec<[u8; 32]> = windows
        .iter()
        .zip(&blinding_factors)
        .map(|(window, b)| {
            let point = RistrettoPoint::hash_from_bytes::<Sha3_512>(window);
            let b = Option::<Scalar>::from(Scalar::from_canonical_bytes(*b))
                .expect("non-canonical blinding factor");
            (point * b).compress().to_bytes()
        })
        .collect();

    sp1_zkvm::io::commit(&HashOutput {
        order_commitment: order_commitment(&salt, windows.iter().map(Vec::as_slice)),
        window_queries_digest: queries_digest(&queries),
        window_count: windows.len() as u32,
    });
}
