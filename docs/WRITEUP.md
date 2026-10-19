# Making a safety check verifiable without revealing what was checked

*zkSecureDNA: zero-knowledge proofs for DNA synthesis screening, as a
safeguard against AI-enabled biological misuse*

## Why DNA synthesis, and why now

A central concern about increasingly capable AI is that it could lower the
expertise needed to cause biological harm. Model-side safeguards (refusals,
classifiers, evaluations) are essential, but they only cover the models
that implement them. A complementary defence sits downstream. Whatever
help someone gets, a digital design only becomes a physical threat once it
is turned into DNA. That step runs through synthesis providers and,
increasingly, benchtop DNA printers. Screening at that point works no
matter which model, open or closed, was involved. This is why synthesis
screening keeps appearing in AI biosecurity recommendations.

Benchtop printers make the problem harder. Screening moves from a few large
providers that can be audited to many devices in many labs. Nobody outside
the lab can tell whether a given device actually screened its orders.

## The problem

Screening DNA synthesis orders against a database of sequences of concern is
a widely recommended safeguard. SecureDNA does this with cryptography that
keeps two things secret at once: the customer's order, which the screening
infrastructure never sees, and the database, which the customer never sees.
A distributed oblivious PRF evaluated by a threshold of keyservers hides the
order. An encrypted hash database lets the screener answer without exposing
its contents.

What SecureDNA does not produce is *evidence*. After screening, the lab
knows it screened correctly; nobody else can check. A regulator, insurer or
the public has two options: trust the lab, or audit it in a way that
exposes the orders or the database. The project this repo implements, started
with Neil Perry, asks whether a lab can instead produce a compact, publicly
checkable record that it followed the screening protocol, without revealing
anything about the order. The record would also give authorities a way to
investigate a specific record under strict, transparent conditions.

This is one instance of a general pattern that matters for AI as well:
*proving a safety check was performed, on the real input, by the real
checker, without handing over the sensitive data involved.*

## What the system proves

A record on chain carries a proof of this statement:

> For some DNA windows (committed to, not revealed), the lab derived its
> screening queries from exactly those windows; a quorum of the registered
> service's keyservers answered them, each proving its answers used its
> published keyshare; the answers passed SecureDNA's active-security check;
> the resulting hashes were screened by the registered hazard database, which
> verified all of the above and signed the outcome; each hash's lookup is
> proven against a published root of that database, so how many of them it
> contains is proven, not just reported; and the record's fields
> are encryptions of those windows and the stated metadata to the authority
> committee's key.

The registry contract checks the proof and pins the service's database key,
its keyserver key, its circuits and the published roots of its database. It refuses replays, stale screenings and
ciphertexts that do not match the proof. Opening any field of any record
needs a threshold of authorities. Their approval is a public event naming
the lab, so every opening is visible.

## How the pieces bind

A proof system is only as strong as its weakest link between components.
Most of the work was in those links rather than in any one circuit:

1. **Queries to windows.** The hash circuit computes each blinded query from
   the actual window bytes, and commits to the windows with a salted hash.
2. **Sub-proofs to query state.** The aggregation circuit recursively
   verifies the hash and checksum proofs and requires their outputs to equal
   the query state it then uses. The verifier, not the prover, decides which
   circuits are acceptable.
3. **Keyservers to their keys.** Each keyserver's answer carries a batched
   Chaum–Pedersen proof against a public key interpolated from SecureDNA's
   existing active-security commitments, so no new key infrastructure is
   needed. This is the standard verifiable-PRF construction.
4. **Hashes to the database query.** The database verifies the proof against
   the exact bytes it is asked to screen, then signs its result.
5. **Lookups to the database.** The database keeps its entries in a Merkle
   trie, keyed by the bits of each hash, and its curator publishes the root
   on chain. For every hash screened, the database returns the path its bits
   spell out, which ends either at that hash's entry or somewhere it is
   provably absent. Following a suggestion from Dan Boneh, this replaces
   "trust the database's answer" with a proof against a root anyone holding
   the database can rebuild.
6. **Record to everything above.** The record circuit verifies the screening
   proof, the database's signature and every lookup proof, opens the commitment, and produces
   the encrypted fields, so the on-chain record cannot be detached from any of it.

### Lessons from v1

The first version (SP1 3.0, 2024–25) had three circuits that each ran
correctly, but links 2–4 were missing: verifying keys came from the prover,
sub-proof outputs were never compared to the state used next, and the
database accepted the client's key and did not compare the proof to the
request. Each circuit was right, but the system did not yet establish the
claim. v2 adds a test for every link: each test changes exactly one input
relative to an honest run, and the system must reject it.

## Results

Measured on synthetic orders with keyservers simulated in process using real
keyshares, SP1 6.9.

| Order (windows) | CPU, 32 vCPU | GPU, 1× NVIDIA L4 | Proof size | Verify |
|---|---|---|---|---|
| 1 | 377 s | 16.4 s | 1.27 MB | ~50 ms |
| 10 | 491 s | 25.0 s | 1.27 MB | ~50 ms |
| 100 | 1,774 s | 110 s | 1.27 MB | ~50 ms |
| 500 | — | 446 s | 1.27 MB | ~60 ms |

A mid-range data-centre GPU is 16–23× faster than 32 CPU cores. Proof size
and verification time are constant. The full SecureDNA integration test (six
screenings against real in-process keyservers and HDB, each proof verified)
takes 5.4 minutes on the GPU.

The record circuit, now including the database lookup proofs, is 1.87M
cycles for the fixture order. Wrapped in Groth16 its proof is 356 bytes, and
`submitRecord` with SP1's on-chain verifier costs 668,856 gas for a 3-field
record.

**Database lookup proofs.** Synthetic databases of random entries
(`hdbtrie bench`, `examples/lookup_bench.rs`); one lookup proof per hash
screened, checked inside the record circuit:

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

Each lookup costs about 70,000 cycles in the circuit, and the cost grows
with the logarithm of the database size, so a 100× larger database adds
about a third. A 500-hash order's record proof takes 30 s on the L4, small
next to the 446 s screening proof. The integration test now also checks
the real HDB's lookup proofs (hits included) and still passes in 5.4 minutes.

The keyserver proofs are the largest single cost inside the aggregation
circuit (about 3.7M → 17.6M cycles for a one-window order). Batching
already makes this one proof per keyserver rather than one per query.
Moving the check into accelerated precompiles is the obvious next optimization.

## What is still trusted

- **The database contents.** Lookups are proven against a published root,
  so the service cannot misreport what its database holds. But the curator
  vouches that the root is the real database, and nothing shows the
  database catches every hazardous sequence, including novel AI-designed
  ones. Better detection is separate work. This project makes whatever
  detection exists verifiable, and lets a better screener plug into the
  same registry.
- **What the service does with a hit.** Exemptions, regional rules and
  grouping hits into hazards still rest on the service's signature. The
  record carries both the proven number of database hits and the signed
  hazard count, so a gap between them is visible.
- **Committee setup.** The prototype uses a trusted dealer. A deployment
  needs distributed key generation.
- **Permanence.** Encrypted records on a public chain are permanent, and
  posting patterns are visible even when contents are not.

## Why this matters for AI safety

For biosecurity directly, this makes a key downstream safeguard against
AI-enabled misuse checkable. A regulator or insurer can require proof of
screening from every printer, and verify it, without collecting anyone's
orders.

More broadly, many proposed AI governance mechanisms have the same shape: a developer
should be able to show that a required evaluation was run, on the model
actually deployed, by an approved evaluator, without revealing weights or
proprietary data. The recipe here transfers directly:

- commit to the private input;
- prove each step with keys the verifier pins;
- have the external checker sign what it actually saw;
- bind it all into one artifact that anyone can verify, and that authorities
  can open only jointly and publicly.

## Credits

Project concept and design: Neil Perry (with input from Dan Boneh on
the verifiable-PRF step). Architecture input: Sofiane. Upstream protocol and
code: SecureDNA. Implementation: Anthony Argyropoulos.
