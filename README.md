<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# zkSecureDNA

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-informational?style=flat-square)](COPYRIGHT.md)

**Making biosecurity screening auditable.** zkSecureDNA extends the [SecureDNA](https://securedna.org) DNA synthesis screening protocol with zero-knowledge proofs, so a synthesis lab can prove to a third party that it correctly screened an order against the hazard database — without revealing the DNA sequence it screened, and without the verifier needing to trust the lab or the keyservers.

Three [SP1](https://github.com/succinctlabs/sp1) zkVM circuits over SecureDNA's real distributed-OPRF cryptography, composed by a recursive aggregation circuit, with a verification endpoint added to the hazard database server.

> **Status: research prototype.** The circuits are implemented and validated against the native implementation; end-to-end proof *generation* is currently disabled in favor of zkVM execute-mode. See [Current state](#current-state) for exactly what runs today and what doesn't. Forked from [`SecureDNA/SecureDNA`](https://github.com/SecureDNA/SecureDNA).

---

## The problem

DNA synthesis is cheap and getting cheaper. That's mostly good, and occasionally catastrophic: the same technology that accelerates vaccine development also lowers the barrier to synthesizing a known pathogen. Screening synthesis orders against a hazard database is the obvious control, and it runs into an obvious problem — **the hazard database is itself a blueprint**. You cannot hand every synthesis lab a list of dangerous sequences.

SecureDNA solves this with cryptography. Its screening protocol satisfies three constraints simultaneously:

1. **Screen orders** against known hazardous sequences.
2. **Never disclose the hazard database**, even to participating labs.
3. **Never disclose the customer's order** to the screening infrastructure.

It works through a **Distributed Oblivious Pseudo-Random Function (DOPRF)**. DNA is cut into short windows (~42 bp). The client blinds each window and sends it to a set of keyservers holding Shamir shares of a PRF key; a threshold `t` of `n` must cooperate, and no single keyserver can evaluate the PRF alone or learn the query. The client unblinds the combined result into a hash and checks it against an encrypted database. Randomized checksums let the client detect — and identify — a keyserver that computed its share incorrectly.

The protocol was developed by researchers at MIT, Aarhus, Shanghai Jiao Tong, Tsinghua, and Northeastern.

## The gap zkSecureDNA fills

SecureDNA's guarantees are strong but **local to the participants**. The client knows it screened correctly. A regulator, an insurer, or the public has no way to check that a given order was screened at all. The protocol produces conviction, not evidence.

That gap matters because screening compliance is exactly the thing you'd want auditable. Today the only options are trusting the lab's word or auditing it in a way that exposes either the orders or the hazard database.

zkSecureDNA wraps the protocol's critical computations in zkVM proofs. The resulting artifact is a compact, publicly checkable object attesting that the screening protocol was executed correctly on some order — while revealing nothing about the DNA sequence. It's the difference between "we screen everything, trust us" and a verifiable record.

---

## Architecture

Three circuits, mirroring the three cryptographic steps a client performs. Each is a standalone SP1 program compiled to RISC-V.

### 1. Hash proof — [`hash_proof/`](hash_proof/)

Proves the client correctly derived its blinded queries from real DNA windows. Reads window bytes and blinding factors in a loop (terminated by an empty-vector sentinel), hashes each window to a Ristretto point, applies the blinding factor, and commits the resulting `Query`.

```rust
// hash_proof/program/src/main.rs
let hashed_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&bytes);
let blinding_factor = Scalar::from_canonical_bytes(blinding_bytes).unwrap();
let query = Query::from_rp(hashed_point * blinding_factor);
sp1_zkvm::io::commit::<Query>(&query);
```

This binds the public queries to an actual hash-to-curve of real input, closing the hole where a lab submits arbitrary group elements it knows the preimages of.

### 2. Checksum proof — [`checksum_proof/`](checksum_proof/)

Proves the active-security checksum. Reconstructs the `RandomizedTarget` from the active security key, derives the checksum point for the batch, inverts out the verification factor, and re-blinds:

```rust
// checksum_proof/program/src/main.rs
let randomized_target = active_security_key.randomized_target(hashed_concat_quries);
let checksum = randomized_target.get_checksum_point_for_validation(&sum);
let x_0 = checksum * verification_factor_0.invert();
sp1_zkvm::io::commit::<Query>(&Query::from_rp(x_0 * blinding_factor));
```

This is the step that catches a cheating keyserver, so proving it is what lets a verifier conclude the keyserver responses were actually validated rather than accepted.

### 3. Verification proof — [`verification_proof/`](verification_proof/)

The aggregation circuit. It **recursively verifies the other two proofs inside the zkVM**, then finishes the protocol in the same execution:

```rust
// verification_proof/program/src/main.rs
for i in 0..vkeys.len() {
    sp1_zkvm::lib::verify::verify_sp1_proof(&vkeys[i], &Sha256::digest(&public_values[i]).into());
}
// ... then incorporate keyserver responses and complete the DOPRF
let hash_values = querystate.get_hash_values()?;   // triggers checksum validation
sp1_zkvm::io::commit::<PackedRistrettos<TaggedHash>>(&packed_hashes);
```

The two sub-proof verifying keys come from `client.setup()` on the hash and checksum ELFs and are supplied as witnesses ([`crates/doprf/src/prf.rs:474`](crates/doprf/src/prf.rs)).

Recursion is what makes this practical. Without it, a verifier would need all three proofs plus the logic to relate them. With it, **one proof attests to the entire screening pipeline**, and its size doesn't grow with the number of steps folded in.

### Verification endpoint

The hazard database server gained a `/scep/screen-and-verify` endpoint ([`crates/hdbserver/src/screening.rs:81`](crates/hdbserver/src/screening.rs)) that accepts the proof and verifying key alongside the Ristretto query data, verifies the proof, and only then runs the normal screening path. This moves the check to the party that actually cares — the HDB will not answer a query it can't verify was legitimately derived.

### Accumulator groundwork — [`crates/hdb_acc/`](crates/hdb_acc/)

Walks the HDB shard files and converts the 32-byte hash prefixes into BLS12-381 scalar field elements, as preparation for a [`vb_accumulator`](https://crates.io/crates/vb_accumulator)-based membership scheme. **This is unfinished** — the conversion and its tests work, but no accumulator is constructed and nothing references the crate yet. It's the direction the work was headed, not a completed component.

---

## Changes to upstream SecureDNA

| Crate | Change |
|---|---|
| [`doprf/`](crates/doprf/) | New `sp1` feature. Added `SerializableQueryStateSet` and `VerificationInput`; rewrote `QueryStateSet::from_iter` to drive the hash and checksum circuits and return their verification inputs alongside the query state. |
| [`doprf/src/active_security.rs`](crates/doprf/src/active_security.rs) | Added `SerializableRandomizedTarget` and `get_checksum_point_for_validation()` — the checksum computation had to be reachable in isolation to be provable. |
| [`doprf_client/`](crates/doprf_client/) | `hash()` now returns a `VerificationInput` with the query data; added the recursive verification-proof driver. |
| [`hdbserver/`](crates/hdbserver/) | New `scep_endpoint_screen_and_verify` that verifies a proof before screening. |
| [`scep/`](crates/scep/), [`scep_client_helpers/`](crates/scep_client_helpers/) | New `SCREEN_AND_VERIFY_ENDPOINT` and the client-side `screen_and_verify()` call. |
| Root `Cargo.toml` | `[patch.crates-io]` redirecting `sha3` and `curve25519-dalek` to SP1 precompile forks. |

That last row is small and load-bearing. SHA3-512 and Ristretto scalar multiplication dominate the circuits' cycle counts; routing them through SP1's accelerated precompiles rather than executing the pure-Rust implementations inside the zkVM is the difference between a tractable circuit and an intractable one.

A serialization theme runs through all of this. Cryptographic state that lived comfortably as in-memory Rust structs had to cross the host/guest boundary, which meant giving `QueryStateSet`, `RandomizedTarget`, and `RequestContext` explicit serializable forms. Most of the integration work was this, not the circuit logic.

---

## Current state

Being precise about what runs, since "has ZK proofs" can mean several things:

**Working:**
- All three circuits compile and execute correctly in the SP1 zkVM.
- Circuit outputs are validated against the native implementation on every run — the host recomputes each result and asserts equality (`"Hash proof: Hashes match."`, `"Checksum proof: Checksums match."`, `"Verification Proof: Incorporated responses match."`).
- Recursive aggregation of the two sub-proofs was demonstrated working (commit `f6bafd6`).
- The HDB verification endpoint verifies a supplied proof and gates screening on it.

**Not working / not built:**
- **Proof generation is commented out** throughout ([`crates/doprf/src/prf.rs:337`](crates/doprf/src/prf.rs), [`crates/doprf_client/src/doprf_client.rs:346`](crates/doprf_client/src/doprf_client.rs)). The code paths run `client.execute()` and load previously generated proofs from disk. Restoring `client.prove()` is a matter of uncommenting the adjacent blocks; it was disabled because proving on every iteration made the development loop impractical, and EVM-compatible wrapping needs ≥128 GB RAM.
- **There is no on-chain verifier.** The `contracts/` directories are unmodified SP1 project templates (`Fibonacci.sol`) and verify nothing about DNA screening. On-chain verification is a plausible extension, not something this repo implements. *(An earlier version of this README described a `SecureDNAVerifier` contract; no such contract exists here, and the claim has been removed.)*
- **No performance numbers were recorded.** Cycle-count instrumentation is in place but no output was captured, so this README quotes no proving times, cycle counts, or proof sizes.
- The accumulator crate is groundwork only (above).
- SP1 template residue remains in places — the guest packages are still named `fibonacci-program`.

---

## Getting started

**Prerequisites:** [Rust](https://rustup.rs/) (see `rust-toolchain.toml`), [SP1](https://docs.succinct.xyz/getting-started/install.html), and optionally [Foundry](https://getfoundry.sh/).

```sh
# Build a circuit
cd hash_proof/program && cargo prove build

# Execute without proving (fast; validates circuit output against native)
cd ../script && cargo run --release -- --execute

# Generate a core proof
cargo run --release -- --prove
```

> EVM-compatible Groth16 proofs require ≥128 GB RAM. Use the [Succinct Prover Network](https://docs.succinct.xyz/generating-proofs/prover-network.html) instead.

Run the full SecureDNA system per upstream instructions:

```sh
earthly +dev && docker compose up     # or: ./bin/local_test_environment.sh
```

Once `synthclient` is up:

```bash
echo -e ">Influenza_segment_1\nggcacatctggggtggagtctgctgtcctgagaggatttctcattttcgacaaagaagacaagagatatgacctagcattaagcatcaatgaactgagcaatcttgcaaaaggagagaaggctaatgtgctaattgggcaaggggacgtagtgttggtaatgaaacgaaaacgggactctagcatacttactgacagccagacagcgaccaaaagaattcggatggccatcaattag\n" \
  | jq -sR '{fasta: ., region: "all"}' | curl localhost/v1/screen -d@-
```

---

## Repository structure

Added by this fork:

```
hash_proof/           SP1 circuit — query hashing and blinding
checksum_proof/       SP1 circuit — active-security checksum validation
verification_proof/   SP1 circuit — recursive aggregation + protocol completion
crates/hdb_acc/       BLS12-381 scalar conversion for HDB hashes (groundwork)
```

Upstream SecureDNA:

```
crates/
├── doprf/               distributed oblivious PRF  (modified: sp1 feature)
├── doprf_client/        keyserver client            (modified: proof driver)
├── hdb/, hdbserver/     hash database + server      (modified: verify endpoint)
├── keyserver/           DOPRF keyserver
├── synthclient/         client-side screening service
├── certificates/, certificate_client/
└── awesome_hazard_analyzer/
frontend/                React/TypeScript web interfaces
test/                    test data (`ln -s test/data data` for a small test HDB)
```

## References

- [SecureDNA: Cryptographic Aspects of DNA Screening](https://securedna.org) — Baum, Cui, Damgård, Esvelt, Gao, Gretton, Paneth, Rivest, Vaikuntanathan, Wichs, Yao, Yu
- [SP1 zkVM](https://github.com/succinctlabs/sp1) — Succinct Labs
- [Original SecureDNA repository](https://github.com/SecureDNA/SecureDNA)

## License

Dual-licensed under MIT OR Apache-2.0, following upstream SecureDNA.
