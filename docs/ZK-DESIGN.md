# zkSecureDNA proof design (v2)

This document pins down what each proof claims, how the pieces bind
together, what the on-chain registry enforces, and what is still trusted.
v1 (SP1 3.0, Nov 2024 – Apr 2025) had working circuits that were not bound to
each other or to the order; v2 (SP1 6.9) fixes that and completes the design
from the project's original plan.

```
 lab (synthclient)                 keyservers (t of n)          HDB
 ──────────────────                ───────────────────          ───
 windows x_i ─► hash proof ─┐
 checksum      ─► checksum ─┤      queries ──────────► parts + DLEQ proof
                proof       ├─► aggregation proof ───────────────► verify proof
                            │   (verifies both, checks DLEQs,       screen hashes
                            │    runs active security)              prove lookups (trie)
                            │                                       sign attestation
                            │                                           │
 receipt = proof + attestation + lookup proofs + commitment opening ◄───┘
        │
        └─► record proof (verifies aggregation proof + attestation + every
            lookup proof, opens the commitment, encrypts fields to the
            authority committee)
                 │  Groth16
                 ▼
          ZkSecureDNARegistry (on chain)
```

## 1. Screening statement (aggregation circuit)

Public output, `zk_types::ScreeningStatement`:

| Field | Meaning |
|---|---|
| `hash_vkey`, `checksum_vkey` | Verifying keys of the sub-proofs that were recursively verified. |
| `order_commitment` | `SHA-256(salt ‖ len ‖ window …)`: hiding commitment to the screened windows. |
| `queries_digest` | Digest of every blinded query sent to keyservers (checksum query included). |
| `responses_digest` | Digest of every keyserver response, in order. |
| `keyserver_ids` | The quorum that answered. |
| `active_security_key_digest` | Digest of the active-security commitments used. |
| `hdb_hashes_digest` | Digest of the exact bytes posted to the HDB. |

**hash** (private: windows, blinding factors, salt) computes each query
`b_i·H(x_i)` as `QueryState::from_rp` does and commits the order commitment
and a digest of the queries.

**checksum** (private: weighted point sum, fresh random modifier `r`,
checksum verification and blinding factors; public: active-security key)
recomputes the checksum query, and commits it with `SHA-256(r)` and the key
digest. `r` is drawn fresh per screening and never leaves the lab, as
upstream SecureDNA requires.

**aggregate** verifies both sub-proofs, then requires that

- the query state's per-window queries hash to the hash proof's digest;
- its checksum query and `r` match the checksum proof;
- the randomized target is *recomputed* from the commitments and `r`
  (`SerializableRandomizedTarget` no longer carries a target that could be
  substituted);
- exactly a quorum of distinct keyservers answered, and each keyserver's
  **DLEQ proof** verifies (below);
- the responses pass the active-security check.

### Keyserver proofs (`doprf::dleq`)

Each keyserver `i` with keyshare `k_i` and Lagrange coefficient `λ_i` returns
`P_j = λ_i k_i·Q_j` for every query `Q_j`, plus one batched Chaum–Pedersen
proof that the same exponent satisfies `λ_i·Y_i = λ_i k_i·G`, where
`Y_i = k_i·G` is interpolated from the active-security commitments SecureDNA
already distributes. The per-query statements are folded with Fiat–Shamir
weights derived from the whole transcript, so one 64-byte proof covers a
batch. Served on `/scep/keyserve-proved`.

This is the verifiable-PRF construction from the project plan: it shows each
response was computed correctly, and only the holder of `k_i` can produce it.
Because the keys come from the active-security key, **the HDB pinning that
key** (`--zk-active-security-key-digest`, required with `--zk-verify`)
means only the real keyservers can produce an acceptable statement.

## 2. HDB verification and attestation

`/scep/screen-and-verify`:

1. requires an existing session, and takes a heavy-request permit, before
   doing any expensive work;
2. verifies the proof against the aggregation verifying key it derives from
   its own copy of the circuit (never a client-supplied key);
3. requires the statement's sub-proof keys to be its own, the hashes digest
   to match the request body, and the active-security key to be the pinned one;
4. screens through the unmodified upstream path (plain and exemption-token
   screenings both end here);
5. proves, for every hash in the request, what its database holds for it
   (section 2a);
6. signs `zk_types::HdbAttestation` (statement digest, hashes digest, hazard
   count, timestamp, its public key, and the database root the lookups are
   against) with its Ed25519 SCEP key.

The client checks the attestation signature, that it names its own
statement, and every lookup proof against the attested root. It then keeps a
`ZkReceipt` (proof, statement, attestation, commitment salt, windows, the
exact hashes sent, lookup proofs), written to `ZK_RECEIPT_DIR` by the
synthclient.

## 2a. Database lookup proofs (Merkle trie)

Without these, "this hash is not in the database" is only the HDB's signed
word. With them, it is proven against a root the HDB commits to in advance.

**The trie** (`zk_types::trie`, built by `crates/hdb_trie`). The database's
entries (32-byte hash, 8 bytes of metadata) sit in a binary trie keyed by
the bits of the hash, most significant first. A subtree with one entry is
that entry's leaf, an empty subtree hashes to zero, and

- `leaf = SHA-256(0x00 ‖ hash ‖ metadata)`
- `node = SHA-256(0x01 ‖ left ‖ right)`

The root depends only on the set of entries, not the order they were added
in, so anyone holding the database can rebuild it (`hdbtrie root --hdb DIR`)
and check a published root. The HDB rebuilds the trie whenever it loads its
database.

**A lookup proof** for a hash follows the path its bits spell out and gives
the sibling hash at each level. The path ends at an empty subtree (absent),
at a leaf holding the hash (present, with its metadata), or at a leaf
holding a different hash that shares the path so far (absent). The verifier
rehashes up to the root. Hash entries are pseudorandom, so paths are about
`log₂(entries)` long: 20 levels and roughly 700 bytes at a million entries.

**What it proves.** Against a given root, the HDB cannot report a hash as
absent when it is present, or the other way round, without breaking
SHA-256. It does not prove the root is the real database: that is what the
registry's published roots are for (section 4). Nor does it prove what the
HDB does with a hit afterwards (exemptions, region rules, consolidating hits
into hazards): the attested `hazardCount` stays a signed claim, while
`lookupHits`, the number of screened hashes found in the database, is
proven. A record with `lookupHits = 0` therefore shows the order matched
nothing in the published database, whatever the HDB says.

This follows Dan Boneh's suggestion of a Merkle trie. The project's earlier
plan, a bilinear accumulator (`crates/hdb_acc`, never finished), would have
needed the accumulator's secret key to be kept from the HDB: whoever holds
it can forge non-membership proofs.

## 3. Record circuit and escrow

`zk/programs/record` turns a receipt into the on-chain artifact. It verifies
the aggregation proof recursively, verifies the HDB's Ed25519 signature on
the attestation, checks the screened hashes against the statement's hashes
digest and verifies a lookup proof for each against the attested root,
opens the order commitment against the windows, and encrypts every field to
the authority committee key. Field 0 is the windows;
fields 1–5 are purpose, lab id, printer id, location and timestamp. Public
values, ABI-encoded:

`circuitsDigest, statementDigest, orderCommitment, activeSecurityKeyDigest,
hdbPublicKey, hdbRoot, hazardCount, lookupHits, screenedAt, committeeKey,
fieldDigests[]`

**Escrow** (`crates/zk_escrow`) is hashed ElGamal over Ristretto, per field:
`R = r·G`, key `= H(r·PK, field)`, `ct = plaintext ⊕ keystream(key)`,
`digest = SHA-256(R ‖ ct)`. The committee secret is Shamir-shared t-of-N.
To open field `f` of a record, an authority computes `D_i = sk_i·R_f` with a
DLEQ proof against its public share `PK_i`; any `t` verified shares
interpolate to `r·PK`. A separate `R` per field means each field opens
independently.

## 4. On-chain registry (`contracts/src/ZkSecureDNARegistry.sol`)

- **Screeners** (pluggable protocols): each registered service pins its HDB
  key, its active-security key digest and its circuits digest. A record must
  match all three.
- **Database roots**: each screener names a curator, who publishes the roots
  of its hazard database (`publishHdbRoot`). A record's `hdbRoot` must be a
  published, unrevoked root of its screener. Every root ever published
  stays on chain, so every lab and auditor sees the same database versions;
  governance can revoke a root (`revokeHdbRoot`).
- **Records**: `submitRecord` verifies the Groth16 record proof with SP1's
  verifier. It then checks the screener pins, the current committee key,
  freshness (`maxRecordAge`), the required field count, each ciphertext's
  SHA-256 against the committed digest, and that the statement is not a
  replay. It stores digests only; ciphertexts are emitted in the event.
  Records are indexed by lab.
- **Investigations**: an authority opens a case naming a record, a field
  mask, a recipient key and a legal-basis reference. When `threshold`
  authorities approve, `CaseAuthorized` is emitted, indexed by the lab, as a
  public notice. Only approving authorities may then post decryption shares,
  only for masked fields, once each, sealed to the recipient key. Shares are
  verified and combined off chain (`zksecuredna open`).
- **Governance**: every rule change (screeners, authorities, threshold,
  committee key rotation, record circuit, field count, record age) is a
  proposal that executes only with `threshold` approvals.

## 5. Still trusted / out of scope

- **Committee setup** uses a trusted dealer (`zksecuredna committee-deal`).
  A deployment needs a DKG so no party ever holds the full key.
- **The screening service itself**: the registry trusts registered HDB keys
  and keyserver keys to belong to an honest service. Lookups are proven
  against a published database root, so the HDB can no longer misreport
  what its database holds; what it does with a hit (exemptions, region
  rules, the hazard count) is still its signed word.
- **The database contents**: the curator vouches that a published root is
  the real database. Anyone holding the database can rebuild the root, and
  auditors can screen known hazards and expect proven hits, but nothing
  proves the database is complete, including against novel AI-designed
  sequences.
- **Long-term confidentiality**: ciphertexts on a public chain are permanent;
  a future break of the encryption, or a leak of `t` shares, exposes past
  records. Posting frequency and timing are visible even though content is not.
- **The order commitment hides only as well as the salt**: the lab must keep
  receipts private.

## Proof modes

`ZK_PROOF_MODE` = `off` (upstream behaviour), `execute` (run circuits, no
proof; development), `prove` (compressed proofs + `/scep/screen-and-verify`).
`SP1_PROVER` = `cpu` | `cuda` | `network` selects the backend (`cuda` needs
the `cuda` feature).
