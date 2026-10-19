//! Checksum circuit: proves the active-security checksum query was built
//! correctly from the published active-security key and a fresh secret
//! modifier, exactly as `QueryStateSet::from_iter_with_witness` does.

#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use doprf::active_security::ActiveSecurityKey;
use zk_types::{active_security_key_digest, random_modifier_digest, ChecksumOutput};

fn scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("non-canonical scalar")
}

pub fn main() {
    let active_security_key = sp1_zkvm::io::read::<ActiveSecurityKey>();
    let sum = CompressedRistretto(sp1_zkvm::io::read::<[u8; 32]>())
        .decompress()
        .expect("invalid sum point");
    let random_modifier_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let verification_factor_0 = scalar(sp1_zkvm::io::read::<[u8; 32]>());
    let blinding_factor_0 = scalar(sp1_zkvm::io::read::<[u8; 32]>());

    let randomized_target =
        active_security_key.randomized_target_with_modifier(scalar(random_modifier_bytes));
    let checksum = randomized_target.get_checksum_point_for_validation(&sum);
    let x_0 = checksum * verification_factor_0.invert();

    sp1_zkvm::io::commit(&ChecksumOutput {
        checksum_query: (x_0 * blinding_factor_0).compress().to_bytes(),
        random_modifier_digest: random_modifier_digest(&random_modifier_bytes),
        active_security_key_digest: active_security_key_digest(
            &active_security_key.commitment_bytes(),
        ),
    });
}
