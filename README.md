<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# zkSecureDNA

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-informational?style=flat-square)](COPYRIGHT.md)

**Verifiable DNA synthesis screening: a safeguard against AI-enabled
biological misuse.** zkSecureDNA extends the
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

## Why this matters

As AI models get better at biology, a key worry is that they lower the
expertise needed to misuse it. Model-side safeguards help but are not the
only line of defence. Whatever a model tells someone, turning a digital
design into physical DNA still runs through synthesis providers and,
increasingly, benchtop DNA printers. That makes synthesis screening one of
the few safeguards that holds regardless of which model, open or closed,
was involved. It is widely recommended in AI biosecurity discussions for
exactly that reason.

A safeguard nobody can check is weak. SecureDNA keeps both the customer's
order and the hazard database secret, but it produces no evidence: after
screening, only the lab knows it screened. As desktop printers spread,
regulators, insurers and the public need a way to confirm screening
actually happened at each device, without exposing customers' orders or the
hazard database. zkSecureDNA gives every screened order a record anyone can
verify. It shows the real order was screened by the real, registered
service, and reveals nothing about the order. Authorities can open a
specific record only jointly, and every opening is public.

The same pattern applies to AI governance more broadly: *proving a safety
check was performed, on the real input, by the real checker, without
handing over the sensitive data involved*. A developer might need to show
that a required evaluation ran on the deployed model, by an approved
evaluator, without revealing weights. The recipe is the same:
commit to the private input, prove each step against keys the verifier
pins, have the external checker sign what it saw, and bind it all into one
artifact that authorities can open only jointly and publicly.

What is still trusted: the contents of the screening service's database
(lookups are proven against a published root, so the service cannot
misreport what the database holds, but nothing shows it catches every
hazardous sequence; improving detection is separate work that this
complements), what the service does with a hit (exemptions, regional
rules), the
committee setup (trusted dealer for now), and the permanence of encrypted
records on a public chain. The full argument, including lessons from v1, is
in the [write-up](docs/WRITEUP.md).

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
| HDB `/scep/screen-and-verify` | Verifies with its own pinned keys, requires the proof to be about the exact request and the pinned keyservers, screens, returns a Merkle-trie lookup proof for every hash, and signs an attestation naming the database root. |
| `zk/programs/record` | Verifies the aggregation proof, the HDB's Ed25519 attestation, and every lookup proof against the attested database root (so the number of database hits is proven, not reported), opens the order commitment, and encrypts every record field to the authority committee (threshold hashed-ElGamal, `crates/zk_escrow`). |
| `contracts/src/ZkSecureDNARegistry.sol` | Verifies the record proof. Pins each screener's HDB key, keyservers, circuits and curator-published database roots. Rejects replays, stale records and mismatched ciphertexts. Runs threshold-approved investigations with public notice, and threshold governance. |

## Results

Synthetic orders, keyservers simulated in process with real keyshares,
compressed proofs, SP1 6.9 (`crates/zk_prover/examples/bench.rs`):

| Order (windows) | CPU: 32 vCPU (n2) | GPU: 1× NVIDIA L4 | Proof | HDB verify |
|---|---|---|---|---|
| 1 | 377 s | 16.4 s | 1.27 MB | 47–60 ms |
| 10 | 491 s | 25.0 s | 1.27 MB | 47–60 ms |
| 100 | 1,774 s | 110 s | 1.27 MB | 47–60 ms |
| 500 | — | 446 s | 1.27 MB | 60 ms |

On-chain record: the record circuit (1.87M cycles, lookup proofs included)
wrapped in Groth16 gives a 356-byte proof; `submitRecord` with SP1's v6.1.0
verifier costs 668,856 gas for a 3-field record.

Database lookup proofs (random synthetic databases, L4; `hdbtrie bench` and
`crates/zk_prover/examples/lookup_bench.rs`):

| Database entries | Build trie | Mean path | Proof size | Check one proof (native) |
|---|---|---|---|---|
| 1M | 0.5 s | 20.6 | 705 B | 16 µs |
| 10M | 4.7 s | 23.9 | 810 B | 19 µs |
| 100M | 48 s | 27.2 | 916 B | 22 µs |

| Order (hashes) | Record circuit, no lookups | + lookups, 1M-entry DB | + lookups, 100M-entry DB | Record proof, 100M DB (L4) | Lookup proofs sent |
|---|---|---|---|---|---|
| 1 | 1.78M cycles | 1.83M | 1.84M | 5.1 s | 0.9 KB |
| 10 | 1.83M | 2.36M | 2.51M | 5.7 s | 8.8 KB |
| 100 | 2.28M | 7.55M | 9.24M | 10.0 s | 89 KB |
| 500 | 4.30M | 30.6M | 39.1M | 30.4 s | 444 KB |

About 70,000 cycles per lookup, growing with the log of the database size.

The full SecureDNA integration test (real keyservers and HDB in process, six
screenings, every proof verified by the HDB, every HDB lookup proof verified
by the client) passes in 5.4 minutes on the
L4. The same test with the pre-keyserver-proof circuits took 51 minutes on a
32-core CPU.

Tests:

- `cargo test -p zk_prover --test binding`: tampered query state,
  substituted modifier, cheating keyserver, impostor keyserver, self-run
  keyservers. Each must be rejected.
- `cargo test -p doprf dleq` and `cargo test -p zk_escrow`.
- `cargo test -p hdb_trie`: roots match the definition and ignore insertion
  order; member and non-member proofs verify; forged proofs (swapped
  terminal, borrowed leaf, tampered or truncated path, wrong root) fail.
- `forge test` in `contracts/`: registry rules, plus a real Groth16 record
  verified by SP1's on-chain verifier.
- `crates/zk_prover/examples/record_fixture.rs`: end to end from screening to
  record, including a 2-of-3 field opening; the record circuit counts a
  database hit and rejects lookup proofs against a root the HDB did not attest.

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
cargo run --release -p zk_prover --example lookup_bench -- 1 10 100
cargo run --release -p zk_prover --example record_fixture

# Database trie: the root a curator publishes, and a size benchmark
cargo run --release -p hdb_trie --bin hdbtrie -- root --hdb path/to/hdb
cargo run --release -p hdb_trie --bin hdbtrie -- bench --entries 10000000

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
| `crates/doprf_client` | `zk` feature: proves while keyservers work, attaches proofs to screening (exemption-token path included), verifies the HDB attestation and every lookup proof, returns a receipt. |
| `crates/hdbserver` | `--zk-verify` / `--zk-active-security-key-digest`; builds the database trie on load; `/scep/screen-and-verify` verifies, screens via the unmodified path, proves every lookup, and signs. |
| New crates | `zk_types` (statements, digests, wire formats, trie proof verification), `hdb_trie` (database Merkle trie and lookup proofs), `zk_prover` (prover/verifier, benchmarks), `zk_escrow` (threshold field encryption), `zk_cli`. |
| New | `zk/programs/*` (four SP1 circuits), `contracts/` (registry, tests, deploy script). |

v1 of this fork (SP1 3.0, 2024–25) is in the git history. Its circuits were
not bound to each other or to the request; see the "Lessons from v1" section
of the write-up.

## License

Dual-licensed under MIT OR Apache-2.0, following upstream SecureDNA.
