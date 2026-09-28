# Future directions

A design note, not a commitment. It records how two recurring requests —
post-quantum security and "adaptive privacy" — fit (or clash) with this
coin's priorities, so the discussion does not have to be repeated. The
priorities are unchanged: anonymity first, uniform transactions, and the
rule that anything variable in a transaction is a fingerprint
(`CLAUDE.md` §9).

## Post-quantum

The stack is not post-quantum today, and it should not claim to be. But
"the coin is not PQ" is too coarse: the pieces fail at different times and
for different reasons, and only one failure is retroactive.

| Component | Basis | Quantum risk | Retroactive? |
|---|---|---|---|
| Note encryption KEM (DH over Pallas) | discrete log | recorded ciphertexts decrypted later | **yes** |
| Spend / binding signatures (RedPallas) | discrete log | forgery, theft | no |
| Proof system (Halo2 / IPA over Pallas) | discrete log | forged proofs → invisible inflation | no |
| Hashes (Poseidon, BLAKE2b) | preimage / collision | Grover halves the margin | n/a (fields are wide enough) |

The note-encryption key agreement is the only **harvest-now-decrypt-later**
exposure: a passive observer stores today's ciphertexts and opens them
once a quantum computer exists. Everything else only matters from the day
such a machine is built, so it can be addressed by a scheduled hard fork
rather than pre-emptively.

Staged plan, in priority order:

1. **Hybrid KEM for note encryption — the first concrete step.** Wrap the
   current Diffie-Hellman with a lattice KEM (ML-KEM / Kyber) so the note
   key is `KDF(dh_shared ‖ kyber_shared)`. It is safe as long as *either*
   primitive holds, and it can ship incrementally. Cost: the Kyber
   ciphertext adds roughly 0.8–1.1 KB per output. That enlarges the
   transaction, but uniformity is preserved because *every* output carries
   the same field — the §9 rule is about variability between transactions,
   not absolute size.
2. **Post-quantum signatures** — a medium-term hard fork. Hash-based or
   lattice signatures are larger and change transaction size and the
   sighash; a consensus change, not a drop-in.
3. **Post-quantum proofs** — a long research horizon. Halo2 over Pallas is
   not post-quantum and cannot be patched into it; a PQ system (STARK,
   hash-based, or lattice SNARK) would mean rewriting `crates/circuit` from
   scratch and a hard fork. Until this is done the coin is not truly
   post-quantum, even with the hybrid KEM, and should say so plainly.

The honest summary: plan for it, do the hybrid KEM first because it is the
only retroactive gap, and treat signatures and proofs as later forks — not
as a marketing label applied early.

## "Adaptive privacy" is the wrong axis; selective disclosure is the right one

A recurring request is to let the user *choose a privacy level*. This runs
against the core thesis of the design, and the two reference coins already
taught the lesson:

- **Zcash** made privacy optional. The shielded pool stayed small, and the
  transparent majority made even shielded users linkable. The *choice
  itself* is metadata.
- **Monero** made privacy mandatory and uniform (fixed ring size, later
  enforced). Everyone hides in the same set.

A user-selectable level does exactly the damage this design avoids: it
**fragments the anonymity set**. Whoever picks "high" is distinguishable
from whoever picks "low", and every "low" user shrinks the pool that
everyone else hides in. Here amount, sender and recipient are already
hidden by construction (Pedersen commitments plus a shielded-only pool),
so there is no meaningful *lower* level to offer — only a way to make
everyone's privacy worse. So: no user-facing privacy level.

The useful version of the idea inverts it. Instead of "choose how private
you are," offer **"choose what to reveal, to whom, after the fact"** —
selective disclosure that is opt-in, owner-controlled, and off-chain, so
it never changes the on-chain footprint or the anonymity set:

- **Viewing keys.** Export an incoming/outgoing viewing key so an exchange
  or auditor sees only what the owner grants. The key material already
  exists — `FullViewingKey`, `IncomingViewingKey`, `OutgoingViewingKey` in
  `crates/crypto` — so this is packaging, not new cryptography.
- **Payment proofs.** Done 2026-09-14 as `getpaymentdisclosure` /
  `verifypaymentdisclosure` (`docs/rpc.md`). Prove "I paid this transaction, with this memo"
  without revealing anything else.

This gives compliance and auditability without weakening the base, because
nothing on-chain changes: the owner simply opens a window onto their own
data. It is adaptive *transparency*, not adaptive privacy, and it is the
direction to take if the goal is to let people disclose on their own terms.

## Confidential assets (anonymous tokens)

Letting users issue and transfer their own tokens with the same privacy as
the native coin — amount, sender, recipient, *and* asset type hidden — is
feasible on this design, because it is Orchard-derived and the same
extension already exists in production as Zcash Shielded Assets (ZSA) over
halo2. But it is a large, consensus-critical change and its privacy story
lives or dies on one detail: the asset type must be hidden, not public.

How it fits the mechanics we already have:

- **Per-asset value commitment.** Today the value commitment binds one
  quantity: `cv_net = [v_old − v_new] V + [rcv] R`, with `V` the single
  `ValueCommitValue` generator. For assets, `V` becomes `V_asset`, a
  generator derived from the asset identifier by hash-to-curve, and the
  binding signature balances **per asset type**. A transfer of asset *X*
  balances only in `V_X`.
- **Asset type inside the note.** The asset id is carried as a hidden field
  in the note and proven in-circuit: the spend and output must use the same
  asset base, and the range/balance constraints apply to that asset. This
  is the crucial part — if the asset id were public, it would fragment the
  anonymity set exactly the way a user-selectable privacy level does (one
  small pool per token), which is the mistake the previous section warns
  against. Hidden asset type keeps every transfer indistinguishable from a
  native-coin transfer.
- **Uniform shape.** The asset base is one more field present and identical
  on every note, like the hybrid-KEM ciphertext above, so §9 is satisfied
  for *transfers*: they do not vary between transactions.

The genuinely hard and leaky part is **issuance**. Minting a new asset is
an inherently distinguished event: it creates supply, needs an issuance
authority, and has a different shape from a transfer — so an issuance
transaction is a fingerprint and the issuer is traceable. This cannot be
made as private as a transfer without deep work, and possibly not at all.
The realistic stance is to isolate issuance as the one non-private,
rate-limited, explicitly-authorized operation, and keep *transfers* fully
private and uniform.

Consequences to weigh before committing:

- **Circuit and audit.** The asset base, per-asset balance, and issuance
  rules all live in `crates/circuit`, the consensus-critical part. A
  soundness bug there is invisible inflation of *some asset*, and the
  supply-integrity invariant in `docs/threat-model.md` must generalize from
  one supply to one per asset. Any of this needs a second review and a full
  release-mode run, and realistically a fresh external audit.
- **Proof size and cost.** Hiding and proving the asset base enlarges the
  circuit and the proof; the numbers in `docs/perf.md` would move.
- **Hard fork.** It changes the note format, the value-commitment scheme,
  and consensus, so it is not incremental.

Honest verdict: worth it if the coin wants to be a private asset platform
rather than a single private currency, and the cryptography is proven
(ZSA). But it reshapes the consensus circuit, so it belongs *after* the
base circuit and crypto have been externally audited, with issuance treated
as the deliberate exception to the privacy guarantee — everything else
staying uniform and indistinguishable from the native coin.
