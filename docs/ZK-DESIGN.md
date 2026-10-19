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
                            │    runs active security)              sign attestation
                            │                                           │
 receipt = proof + attestation + commitment opening ◄───────────────────┘
        │
        └─► record proof (verifies aggregation proof + attestation, opens the
            commitment, encrypts fields to the authority committee)
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
5. signs `zk_types::HdbAttestation` (statement digest, hashes digest, hazard
   count, timestamp, its public key) with its Ed25519 SCEP key.

The client checks the attestation signature and that it names its own
statement, then keeps a `ZkReceipt` (proof, statement, attestation,
commitment salt, windows), written to `ZK_RECEIPT_DIR` by the synthclient.

## 3. Record circuit and escrow

`zk/programs/record` turns a receipt into the on-chain artifact. It verifies
the aggregation proof recursively, verifies the HDB's Ed25519 signature on
the attestation, opens the order commitment against the windows, and
encrypts every field to the authority committee key. Field 0 is the windows;
fields 1–5 are purpose, lab id, printer id, location and timestamp. Public
values, ABI-encoded:

`circuitsDigest, statementDigest, orderCommitment, activeSecurityKeyDigest,
hdbPublicKey, hazardCount, screenedAt, committeeKey, fieldDigests[]`

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
  and keyserver keys to belong to an honest service. The proofs show the
  protocol was followed, not that the hazard database is complete.
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
