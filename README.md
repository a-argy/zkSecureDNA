<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Last updated: Dec 29, 2025 -->

# zkSecureDNA

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-informational?style=flat-square)](COPYRIGHT.md)

A fork of [SecureDNA](https://securedna.org) with **zero-knowledge proof extensions** for verifiable DNA synthesis screening.

## Background: The SecureDNA Protocol

SecureDNA is a cryptographic screening protocol designed to prevent the synthesis of hazardous biological agents from synthetic DNA—without disclosing information about potential bioweapons. The system was developed by researchers from MIT, Aarhus University, Shanghai Jiao Tong University, Tsinghua University, and Northeastern University.

### The Problem

DNA synthesis technology has revolutionized molecular biology, but also presents serious biosecurity risks. Malicious or accidental synthesis of self-replicating pathogens could lead to global pandemics. An effective screening system must:

1. **Screen DNA orders** against a database of known hazardous sequences
2. **Protect the hazard database** from disclosure (to prevent reverse-engineering bioweapons)
3. **Preserve client privacy** by keeping synthesizer queries confidential

### How SecureDNA Works

The protocol uses a **Distributed Oblivious Pseudo-Random Function (DOPRF)** to achieve these goals:

1. **Window-based exact matching**: DNA sequences are broken into short windows (e.g., 42 base pairs). If any window matches a hazardous sequence in the database, the order is flagged.

2. **Threshold cryptography**: The PRF key is split among multiple keyholders using Shamir secret sharing. A quorum of `t` out of `n` keyholders must cooperate to evaluate the PRF—no single party can learn the secret key.

3. **Oblivious evaluation**: The client (synthesizer) submits blinded queries to keyholders, who return partial evaluations. The client combines these to compute a hash that can be checked against the encrypted hazard database, without revealing the query to keyholders.

4. **Active security**: Randomized checksums verify that keyholders correctly evaluated the PRF, allowing detection (and identification) of malicious keyholders.

For complete technical details, see the [SecureDNA Cryptographic Technical Note](https://securedna.org).

---

## zkSecureDNA: Zero-Knowledge Proof Extensions

This repository extends the original SecureDNA implementation with **zero-knowledge proofs** that allow DNA synthesis labs to cryptographically prove they correctly executed the screening protocol.

### Motivation

The original SecureDNA protocol ensures that screening is performed *correctly* through cryptographic guarantees—but only to the participants in the protocol. There is no mechanism for **third-party verification** that a lab actually performed screening on a given order.

zkSecureDNA addresses this gap by wrapping critical cryptographic computations in **zkVM proofs** (using [SP1](https://github.com/succinctlabs/sp1)). These proofs can be:

- **Verified on-chain** via Ethereum smart contracts
- **Publicly audited** without revealing the DNA sequences being screened
- **Stored as immutable records** of compliance

This creates a verifiable audit trail proving that DNA synthesis orders were screened against the hazard database—enabling regulatory compliance, insurance verification, and public accountability.

### Architecture

The extension adds three zero-knowledge proof circuits:

#### 1. Hash Proof (`hash_proof/`)
Proves the correct computation of DOPRF queries:
- Takes raw DNA window bytes as input
- Hashes them to RistrettoPoints using SHA3-512
- Applies blinding factors to create oblivious queries
- Commits the resulting `Query` objects as public outputs

```rust
// Inside the zkVM
let hashed_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&bytes);
let query = Query::from_rp(hashed_point * blinding_factor);
sp1_zkvm::io::commit::<Query>(&query);
```

#### 2. Checksum Proof (`checksum_proof/`)
Proves the active security checksum computation:
- Verifies the `RandomizedTarget` checksum for a batch of queries
- Confirms keyholders correctly evaluated the PRF
- Outputs the validated query for database lookup

```rust
// Inside the zkVM
let randomized_target = active_security_key.randomized_target(hashed_concat_queries);
let checksum = randomized_target.get_checksum_point_for_validation(&sum);
let x_0 = checksum * verification_factor_0.invert();
let query = Query::from_rp(x_0 * blinding_factor);
sp1_zkvm::io::commit::<Query>(&query);
```

#### 3. Verification Proof (`verification_proof/`)
Recursively verifies hash and checksum proofs, then completes the protocol:
- Aggregates multiple sub-proofs into a single proof
- Incorporates keyserver responses
- Computes final hash values for database membership testing
- Validates the complete DOPRF evaluation

```rust
// Recursive verification of sub-proofs
for i in 0..vkeys.len() {
    sp1_zkvm::lib::verify::verify_sp1_proof(&vkeys[i], &public_values_digest.into());
}

// Complete the DOPRF protocol
let hash_values = querystate.get_hash_values()?;
sp1_zkvm::io::commit::<PackedRistrettos<TaggedHash>>(&packed_hashes);
```

### New Crates

| Crate | Description |
|-------|-------------|
| `hash_proof/` | SP1 circuit for proving correct query hashing |
| `checksum_proof/` | SP1 circuit for proving checksum validation |
| `verification_proof/` | SP1 circuit for recursive proof aggregation and final verification |
| `hdb_acc/` | Accumulator support for HDB hashes using BLS12-381 scalar fields |

### Key Modifications to Upstream

The following modifications were made to the original SecureDNA crates:

- **`doprf/`**: Added serialization support (`SerializableQueryStateSet`, `SerializableRandomizedTarget`) to pass cryptographic structures into zkVM programs. Added `VerificationInput` for proof aggregation. Modified `QueryStateSet::from_iter` to generate ZK proofs when the `sp1` feature is enabled.

- **`active_security.rs`**: Added `SerializableRandomizedTarget` for passing randomized targets into zkVM. Added `get_checksum_point_for_validation()` for use in checksum proofs.

### On-Chain Verification

Each proof module includes Solidity contracts (in `contracts/src/`) that can verify proofs on Ethereum:

```solidity
contract SecureDNAVerifier {
    address public verifier;
    bytes32 public programVKey;

    function verifyScreeningProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public view returns (bool) {
        ISP1Verifier(verifier).verifyProof(programVKey, _publicValues, _proofBytes);
        return true;
    }
}
```

---

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (see `rust-toolchain.toml` for version)
- [SP1](https://docs.succinct.xyz/getting-started/install.html) for ZK proof generation
- [Foundry](https://getfoundry.sh/) for Solidity contract testing (optional)

### Building the ZK Circuits

```sh
# Build the hash proof circuit
cd hash_proof/program
cargo prove build

# Build the checksum proof circuit
cd checksum_proof/program
cargo prove build

# Build the verification proof circuit
cd verification_proof/program
cargo prove build
```

### Generating Proofs

```sh
# Execute without proving (for testing)
cd hash_proof/script
cargo run --release -- --execute

# Generate a core proof
cargo run --release -- --prove

# Generate an EVM-compatible Groth16 proof
cargo run --release --bin evm -- --system groth16
```

> **Note**: EVM-compatible proofs require at least 128GB RAM. Consider using the [Succinct Prover Network](https://docs.succinct.xyz/generating-proofs/prover-network.html) for production.

### Running the Full System

Follow the original SecureDNA setup:

```sh
# Using Docker (recommended)
earthly +dev && docker compose up

# Or without containerization
./bin/local_test_environment.sh
```

---

## Original SecureDNA Documentation

### Structure

- `crates/` contains all the crates in the monorepo workspace.
   - `awesome_hazard_analyzer/`: A Rust crate combining `hdb` and `synthclient` into one fast local hazard analyzer which bypasses crypto and networking
   - `certificate_client/`: a command line interface for managing SecureDNA certificates.
   - `certificates/`: a library for managing SecureDNA certificates, used to request exemptions from DNA synthesis restrictions.
   - `doprf/`: a Rust implementation of DOPRF ("distributed oblivious pseudo-random function"), the distributed hashing technique we use.
   - `doprf_client/`: a Rust server that actually talks to keyservers using DOPRF and sends the result to the HDB.
   - `hdb/`: the HDB (hash database) implementation.
   - `hdbserver/`: HDB server holding hazard information.
   - `keyserver/`: one of the keyservers used in DOPRF.
   - `synthclient/`: a Rust server that runs within the client's premises. It generates windows from a FASTA string, then communicates with other components to hash the windows and check them for hazards.
- `frontend/`: React and TypeScript code for the various web interfaces to SecureDNA.
- `test/`: test data used for local development. You can `ln -s test/data data` to run the system with a small "test HDB".

### Example Usage

Once you have synthclient running:

```bash
echo -e ">Influenza_segment_1\nggcacatctggggtggagtctgctgtcctgagaggatttctcattttcgacaaagaagacaagagatatgacctagcattaagcatcaatgaactgagcaatcttgcaaaaggagagaaggctaatgtgctaattgggcaaggggacgtagtgttggtaatgaaacgaaaacgggactctagcatacttactgacagccagacagcgaccaaaagaattcggatggccatcaattag\n" | jq -sR '{fasta: ., region: "all"}' | curl localhost/v1/screen -d@-
```

---

## References

- [SecureDNA Technical Note: Cryptographic Aspects of DNA Screening](https://securedna.org) — Baum, Cui, Damgård, Esvelt, Gao, Gretton, Paneth, Rivest, Vaikuntanathan, Wichs, Yao, Yu (2020)
- [SP1 zkVM](https://github.com/succinctlabs/sp1) — The RISC-V zkVM used for proof generation
- [Original SecureDNA Repository](https://github.com/SecureDNA/SecureDNA)

## License

This project is dual-licensed under MIT OR Apache-2.0, following the original SecureDNA licensing.
