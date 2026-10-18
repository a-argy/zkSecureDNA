<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# zkSecureDNA

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-informational?style=flat-square)](COPYRIGHT.md)

**Verifiable DNA synthesis screening.** zkSecureDNA extends the
[SecureDNA](https://securedna.org) screening protocol with zero-knowledge
proofs. A synthesis lab gets a compact, publicly checkable record showing it
screened an order with a registered screening service, following the
protocol, without revealing anything about the order. Records go to an
on-chain registry where any field can be opened only by a threshold of
authorities, and every opening is publicly announced.

Forked from [`SecureDNA/SecureDNA`](https://github.com/SecureDNA/SecureDNA).
Project concept by Neil Perry. Built on [SP1](https://github.com/succinctlabs/sp1) 6.9.

- **Design and security argument:** [docs/ZK-DESIGN.md](docs/ZK-DESIGN.md)
- **Write-up:** [docs/WRITEUP.md](docs/WRITEUP.md)

> Research prototype. Not audited. The authority committee uses a trusted
> dealer, and the registry has not been deployed to a public network.

## What it proves

```
windows ─► hash proof ─────┐
            checksum proof ┼─► aggregation proof ─► HDB verifies, screens, signs
keyservers ─► DLEQ proofs ─┘                                │
                                                            ▼
                     record proof (Groth16) ─► ZkSecureDNARegistry (on chain)
```

| Component | Proves |
|---|---|
| `zk/programs/hash` | Blinded queries were derived from the committed windows. |
| `zk/programs/checksum` | The active-security checksum was built from the published key and a fresh secret modifier. |
| `zk/programs/aggregate` | Both sub-proofs verify and match the query state. Each keyserver's batched Chaum–Pedersen proof verifies against its key interpolated from the active-security commitments. The responses pass active security. The final hashes are correct. |
| HDB `/scep/screen-and-verify` | Verifies with its own pinned keys, requires the proof to be about the exact request and the pinned keyservers, screens, and signs an attestation. |
| `zk/programs/record` | Verifies the aggregation proof and the HDB's Ed25519 attestation, opens the order commitment, and encrypts every record field to the authority committee (threshold hashed-ElGamal, `crates/zk_escrow`). |
| `contracts/src/ZkSecureDNARegistry.sol` | Verifies the record proof. Pins each screener's HDB key, keyservers and circuits. Rejects replays, stale records and mismatched ciphertexts. Runs threshold-approved investigations with public notice, and threshold governance. |

## Results

Synthetic orders, keyservers simulated in process with real keyshares,
compressed proofs, SP1 6.9 (`crates/zk_prover/examples/bench.rs`):

| Order (windows) | CPU: 32 vCPU (n2) | GPU: 1× NVIDIA L4 | Proof | HDB verify |
|---|---|---|---|---|
| 1 | 377 s | 16.4 s | 1.27 MB | 47–60 ms |
| 10 | 491 s | 25.0 s | 1.27 MB | 47–60 ms |
| 100 | 1,774 s | 110 s | 1.27 MB | 47–60 ms |
| 500 | — | 446 s | 1.27 MB | 60 ms |

On-chain record: the record circuit (1.78M cycles) wrapped in Groth16 gives a
356-byte proof; `submitRecord` with SP1's v6.1.0 verifier costs 674,609 gas
for a 3-field record.

The full SecureDNA integration test (real keyservers and HDB in process, six
screenings, every proof verified by the HDB) passes in 5.4 minutes on the
L4. The same test with the pre-keyserver-proof circuits took 51 minutes on a
32-core CPU.

Tests:

- `cargo test -p zk_prover --test binding`: tampered query state,
  substituted modifier, cheating keyserver, impostor keyserver, self-run
  keyservers. Each must be rejected.
- `cargo test -p doprf dleq` and `cargo test -p zk_escrow`.
- `forge test` in `contracts/`: registry rules, plus a real Groth16 record
  verified by SP1's on-chain verifier.
- `crates/zk_prover/examples/record_fixture.rs`: end to end from screening to
  record, including a 2-of-3 field opening.

Upstream unit tests for every modified crate pass. The exception is
`certificates/tests/check_test_certs.rs`: its 8 failures also occur on
unmodified upstream, because the bundled test certificates no longer
validate as of October 2026.

## Running

Prerequisites: Rust (see `rust-toolchain.toml`), [SP1](https://docs.succinct.xyz)
(`sp1up`), and [Foundry](https://getfoundry.sh) for the contracts. GPU
proving needs an NVIDIA GPU with compute capability ≥ 8.0, plus the `cuda`
feature.

```sh
# Proofs on/off for the screening client: off | execute | prove
export ZK_PROOF_MODE=prove SP1_PROVER=cpu   # or cuda (with --features zk_prover/cuda)

# End-to-end test with real keyservers + HDB (HDB verifies every proof)
cargo test --release -p doprf_client --features zk --test test_integration

# Benchmarks and record fixture
cargo run --release -p zk_prover --example bench -- 1 10 100
cargo run --release -p zk_prover --example record_fixture

# Contracts
cd contracts && forge install foundry-rs/forge-std succinctlabs/sp1-contracts@v6.1.1 && forge test
```

Full SecureDNA stack with proofs (locally built binaries in the upstream
images; this compose path has not been exercised end to end, the
integration test above covers the same flow in process):

```sh
cargo build --release -p synthclient -p hdbserver
docker compose -f docker-compose.yml -f docker-compose.zk.yml up
```

The HDB needs `SECUREDNA_HDBSERVER_ZK_VERIFY=true` and
`SECUREDNA_HDBSERVER_ZK_ACTIVE_SECURITY_KEY_DIGEST=<hex>`. The synthclient
writes receipts to `ZK_RECEIPT_DIR`.

Records and investigations (`crates/zk_cli`):

```sh
zksecuredna committee-deal --threshold 3 --members 5 --out committee/   # dev only
zksecuredna record --receipt r.json --committee-key 0x… \
  --field purpose=… --field lab_id=… --field printer_id=… --field location=… --field timestamp=… \
  --out submission.json                                                # → submitRecord
zksecuredna recipient-keygen --out recipient.json
zksecuredna share --share committee/share-2.json --record-id 0x… --field 1 \
  --encrypted-field 0x… --recipient 0x…                                # → submitDecryptionShare
zksecuredna open --recipient-key recipient.json --committee committee/committee.json \
  --record-id 0x… --field 1 --encrypted-field 0x… --sealed 0x… --sealed 0x… --sealed 0x…
```

## What changed from upstream SecureDNA

| Area | Change |
|---|---|
| `crates/doprf` | `QueryStateSet::from_iter_with_witness`; `dleq` module; keyserver public keys from the active-security key; the randomized target is recomputed, never deserialized. No SP1 dependency. |
| `crates/keyserver` | `/scep/keyserve-proved`: responses plus a batched DLEQ proof. |
| `crates/doprf_client` | `zk` feature: proves while keyservers work, attaches proofs to screening (exemption-token path included), verifies the HDB attestation, returns a receipt. |
| `crates/hdbserver` | `--zk-verify` / `--zk-active-security-key-digest`; `/scep/screen-and-verify` verifies, screens via the unmodified path, and signs. |
| New crates | `zk_types` (statements, digests, wire formats), `zk_prover` (prover/verifier, benchmarks), `zk_escrow` (threshold field encryption), `zk_cli`. |
| New | `zk/programs/*` (four SP1 circuits), `contracts/` (registry, tests, deploy script). |

v1 of this fork (SP1 3.0, 2024–25) is in the git history. Its circuits were
not bound to each other or to the request; see the "Lessons from v1" section
of the write-up.

## License

Dual-licensed under MIT OR Apache-2.0, following upstream SecureDNA.
