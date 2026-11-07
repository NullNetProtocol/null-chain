# Monero-style atomic swaps for NULL

Date: 2026-11-04. Status: technical background and proposed adaptation;
not an implemented or audited NULL swap protocol.

NULL's chosen direction is a Monero-style scriptless swap: ownership of
funds on one chain is linked cryptographically to ownership on the other,
while every NULL transfer remains shielded. The decision is recorded in
[decisions.md](decisions.md#2026-11-04-monero-style-atomic-swaps-always-shielded-on-null);
[TODO.md](../TODO.md#atomic-swaps) tracks implementation work and
[future.md](future.md#atomic-swaps) contains the shorter design sketch.

## 1. Policy and scope

Swap funding, settlement, refunds and recovery must use ordinary shielded
NULL notes. DEX compatibility never justifies transparent addresses,
unshielded spendable outputs, public swap amounts or a temporary exit
from NULL's shielded pool. There is no unshielded fallback.

The initial research target is NULL–BTC or NULL–LTC. The other chain
must provide the timing and transaction mechanisms required by the
selected protocol. Direct NULL–XMR swaps require separate research.

This document distinguishes three things:

- The published BTC–XMR constructions, used as technical references.
- NULL's existing primitives and wallet interfaces, inspected in this repo.
- The proposed adaptation, whose full security argument remains open.

“Scriptless” does not mean that neither chain uses scripts. The reference
construction uses Bitcoin transaction conditions while requiring no hashlock
or swap timelock on Monero. The original work combines ECDSA one-time
verifiably encrypted signatures with cross-group proofs. See
[Gugger's original paper](https://eprint.iacr.org/2020/1126).

## 2. Joint control and adaptor signatures

Consider Alice, who sells XMR, and Bob, who pays BTC. They generate fresh,
swap-specific secret shares `a` and `b`. Conceptually, the private-side
output has spend authority:

```text
k = (a + b) mod q
K = aG + bG = kG
```

Here `G` is the spend generator and `q` its group order. Public shares let
them construct `K` without revealing either secret. Neither party initially
knows `k`; learning the other share enables spending. These are temporary
swap keys, never shares of either user's existing wallet seed.

An adaptor signature is a verifiable pre-signature with two complementary
operations:

```text
signature = Adapt(pre_signature, secret)
secret    = Extract(pre_signature, signature)
```

These are abstract interfaces, not cryptographic implementation formulas.
Completing a pre-signature can enable a payment; publishing the completed
signature lets its pre-signature holder extract the corresponding secret.
The public signature alone does not disclose that secret to an observer
without the required transcript. These mechanisms underpin the
[original BTC–XMR construction](https://eprint.iacr.org/2020/1126).

For NULL, the proposed use is to make Bitcoin redemption reveal Alice's
NULL share to Bob. Bob would then control the shielded note. The complete
construction must specify signature verification, extraction, malicious
key handling and transcript binding before this becomes an implementation.

## 3. Binding keys across different curves

Bitcoin uses secp256k1; Monero's reference construction uses a different
group; NULL uses Pallas for spend authorization. A public point on one
curve cannot simply be reused on another.

The proposed NULL protocol needs a proof relating:

```text
T_BTC  = a * G_secp256k1
T_NULL = a * G_spend_Pallas
```

The proof must establish knowledge of the same secret integer without
revealing it. Otherwise a participant could arrange for Bitcoin redemption
to reveal a secret unrelated to the shielded funds.

Cross-group discrete-log equality proofs address this problem. Different
group orders require a defined common integer range and correct scalar
encodings; independently reducing arbitrary bytes modulo each order is
not a sufficient argument. See Sarang Noether's
[MRL-0010](https://web.getmonero.org/es/resources/research-lab/pubs/MRL-0010.pdf).

For NULL, selecting an audited secp256k1–Pallas implementation remains an
open dependency. The proof transcript must bind the intended swap,
participants and public keys, with replay protection across sessions and
networks. Successful verification must precede funding.

## 4. Reference successful execution: BTC–XMR

In the COMIT reference flow, recovery material is exchanged before funding.
Bob first locks BTC. Alice checks it, then funds the shared XMR output.
Bob verifies that deposit before releasing the redemption pre-signature.
Alice redeems BTC using `a`; Bob extracts `a` and combines it with `b` to
spend the XMR. See the
[COMIT protocol walkthrough](https://comit.network/blog/2020/10/06/monero-bitcoin/).

```mermaid
sequenceDiagram
    participant A as Alice: sells XMR
    participant B as Bob: pays BTC
    participant BTC as Bitcoin
    participant XMR as Monero
    A->>B: Exchange and verify keys, proofs and recovery signatures
    B->>BTC: Fund BTC lock
    A->>BTC: Verify lock and confirmations
    A->>XMR: Fund jointly controlled output
    B->>XMR: Verify deposit and confirmations
    B->>A: Provide BTC redemption pre-signature
    A->>BTC: Redeem BTC using secret a
    B->>BTC: Observe completed signature; extract a
    B->>XMR: Spend using a and b
```

The ordering matters: Alice cannot obtain the redemption pre-signature
before depositing, and she does not deposit before verifying Bitcoin
funding and recovery conditions. Dedicated viewing material allows deposit
verification. Bitcoin and Monero nodes validate their own transactions;
they do not communicate with each other. The clients coordinate the swap.
This sequence describes the
[reference protocol](https://comit.network/blog/2020/10/06/monero-bitcoin/),
not an executable NULL protocol.

## 5. Cancellation, refunds and inactivity

The COMIT construction has Bitcoin cancellation, refund and punishment
paths. Cancellation becomes available after a deadline. A Bitcoin refund
reveals Bob's private-side share, enabling Alice to recover her XMR.
If Bob remains inactive beyond a later deadline, Alice can instead claim
the BTC as compensation, while the XMR may remain permanently locked.
See sections 3.2–3.4 of
[Hoenisch and Soriano del Pino](https://arxiv.org/html/2101.12332).

| Reference outcome | BTC result | XMR result |
|---|---|---|
| Successful exchange | Alice receives BTC | Bob obtains spend authority |
| Cancellation followed by refund | Bob recovers BTC, less fees | Alice obtains recovery authority |
| Bob misses the refund window; Alice uses punishment | Alice receives BTC as compensation | XMR can remain locked |

Consequently, this reference does not establish that every interruption
returns both original assets. Monitoring, confirmation margins and timely
publication are security requirements, not optional conveniences.
These limitations are explicit in the
[reference analysis](https://arxiv.org/html/2101.12332).

For NULL, the acceptable failure behavior must be decided explicitly.
Choosing the Monero-style direction does not approve copying every
penalty mechanism. A protocol specification must distinguish recovery,
compensation and permanent lock, including who must act and when. None
of those paths may introduce an unshielded NULL output.

Bitcoin's relative-locktime semantics are specified in
[BIP 68](https://bips.dev/68/); script-enforced checks of relative output
age are specified in [BIP 112](https://bips.dev/112/). The exact deadline
construction must be selected and reviewed with the transaction graph.

## 6. Mapping the idea onto NULL

The following is a proposal inferred from NULL's current key and circuit
structure. It is not a demonstrated security result.

### 6.1 Ordinary note, jointly controlled authority

NULL separates spend authorization from note detection and proof inputs:

```text
ask = spend-authorizing scalar
ak  = ask * G_spend
fvk = (ak, nk, rivk)
ivk = H_ivk(ak, nk, rivk)
```

See [keys.rs](../crates/crypto/src/keys.rs) and
[the circuit statement](circuit.md). A candidate swap key would use an
aggregate `ak = aG_spend + bG_spend`, with dedicated `nk` and `rivk`.
Participants would need to agree on and verify all this material before
deriving the receiving address. Adding two existing NULL receiving
addresses is not an equivalent construction.

The target output is a normal encrypted note whose owner happens to be
jointly controlled. Before share recovery, neither party should be able
to authorize a spend independently. After recovering the missing share,
the intended party should be able to create a normal shielded spend.
The same must hold for any recovery path chosen by the final protocol.

### 6.2 Builder and wallet changes

Currently [SpendInfo](../crates/protocol/src/builder.rs) takes a
`SpendingKey`, from which the builder derives authorization and viewing
material. Recovering an aggregate scalar `ask = a + b` does not recover
a seed whose derivation produces that scalar and the agreed `fvk`.

The builder therefore needs a reviewed interface accepting consistent
spend-authorizing and viewing material directly. Wallet storage and
recovery must also represent such swap keys without pretending they are
ordinary seed-derived accounts. Existing
[wallet key handling](../crates/wallet/src/keys.rs) does not establish
complete support for this use case.

The proof must still establish note ownership and membership, nullifier
correctness and value conservation. The existing randomized spend key
`rk = ak + alpha * G_spend` must remain correctly tied to authorization.
See [signature.rs](../crates/crypto/src/signature.rs) and
[circuit.md](circuit.md).

### 6.3 Joint ownership is distinct from threshold signing

The recovered full scalar may allow an ordinary RedPallas signature after
the swap releases a share. That alone does not require a threshold signing
round. If the selected protocol needs signatures while both shares remain
separate, an additional joint signing construction is needed.

[FROST, RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) describes
threshold Schnorr signing. Citing FROST does not establish RedPallas
compatibility or supply the adaptor signatures, cross-group proof and
refund protocol. The exact signing construction remains open.

### 6.4 Existing consensus is a goal, not a guarantee

[NULL transactions](../crates/protocol/src/transaction.rs) currently have
no swap script, locktime or expiry field. The design goal is to preserve
those transaction shapes and enforce swap coordination through keys and
the counterparty chain.

A complete implementation must prove that this works under existing
consensus. A required transparent output or public swap amount would
reject the candidate design; it would not justify relaxing the policy.
Any proposed shielded consensus change would require its own review.

## 7. Operational requirements for a NULL prototype

These are proposed requirements, not claims about the reference projects.

- **Persist before funding.** Save the authenticated swap transcript,
  recovery transactions, keys and state before any irreversible step.
  A restart must not depend on renewed cooperation from the peer.
- **Verify actual funding.** Verify the amount, destination, transaction
  conditions and confirmations on both chains. A peer's claim or a
  transaction identifier alone is insufficient.
- **Use isolated keys.** Allocate dedicated swap keys and disclose only
  the viewing material needed for that swap. Never share the user's main
  wallet viewing key. Account for everything a dedicated full viewing key
  reveals, including subsequent spending of that note.
- **Handle chain races.** Define confirmation policy, reorg behavior,
  conflicting spends, Bitcoin fee increases and publication deadlines.
  Mempool visibility is not final settlement.
- **Handle anchor age.** NULL currently retains valid anchors for 100
  blocks; its mainnet target spacing is 120 seconds. Those are block-based
  rules, not a guaranteed wall-clock window. See
  [params.rs](../crates/chain/src/params.rs) and [params.md](params.md).
  Refresh witnesses and rebuild transactions safely. Do not assume a
  pre-signed NULL recovery transaction remains valid indefinitely.
- **Handle upgrades and reservations.** Signatures bind the consensus
  branch. Define behavior around upgrades and prevent ordinary wallet
  operations from spending reserved swap notes. Existing persisted
  [send operations](../crates/wallet/src/operations.rs) are infrastructure
  to assess, not a complete two-chain swap state machine.
- **State availability requirements.** Explain when the client must
  monitor and act. Any delegated monitoring must have an explicit trust
  and privacy model. Do not promise unattended automatic recovery.

## 8. Privacy properties and limits

The target is ordinary NULL transaction shapes with no public swap amount,
cross-chain hash marker or special swap output. This does not mean a
transaction's occurrence, action class or network traffic becomes invisible.
See [protocol.md](protocol.md) and [threat-model.md](threat-model.md).

| Observer | Information to account for |
|---|---|
| Public NULL observer | Ordinary transaction metadata and timing; no extra swap-specific fields |
| Public BTC/LTC observer | The counterparty chain's public amounts, funding and spending patterns |
| Trading counterparty | Agreed amounts, protocol transcript and dedicated swap viewing information |
| Order or network observer | Advertised offers, interaction timing and potentially network identifiers |

The privacy review must include failure paths and transcript disclosure.
Removing a shared hash does not prove resistance to timing correlation or
linkage by a counterparty that publishes its records. Authenticated
encrypted communication and suitable network routing are separate design
requirements from keeping funds shielded.

A Bitcoin implementation could investigate a Taproot/Schnorr construction,
but [BIP 340](https://bips.dev/340/) specifies signatures, not a complete
atomic swap. It does not prove that all funding, refund and failure paths
are indistinguishable from ordinary Bitcoin use. No such guarantee is
assumed here.

## 9. Research and implementation sequence

1. Specify one pair and transaction graph, including every terminal state,
   deadlines, fees, confirmations and availability assumptions.
2. Select reviewed primitives for key generation, cross-group proofs and
   adaptor signatures. Resolve RedPallas integration and scalar encoding.
3. Demonstrate aggregate NULL key construction, dedicated scanning and
   ordinary shielded spending using explicit authorization/viewing inputs.
4. Build a persistent two-chain coordinator with reproducible testnet
   scenarios for success, rejection, refund, dropout, restart, fee pressure,
   anchor expiry, reorg and upgrade boundaries.
5. Review both protocol security and privacy independently. Document any
   loss, compensation or permanent-lock outcomes and their assumptions.
6. Evaluate DEX integration and liquidity only once feasibility is clear.
   A DEX requiring an unshielded NULL hop is incompatible with the policy.

The initial deliverable is a validated protocol and prototype. This note
does not establish mainnet readiness, guaranteed recovery, direct NULL–XMR
support or the absence of a future shielded consensus change.

## References

- Joël Gugger, *Bitcoin-Monero Cross-chain Atomic Swap*, IACR ePrint
  2020/1126 (2020): [original paper](https://eprint.iacr.org/2020/1126).
  Establishes the original construction; it is not identical to every
  later COMIT variant.
- Lucas Soriano del Pino, *Monero-Bitcoin Atomic Swap*, COMIT Developer Hub
  (2020): [protocol walkthrough](https://comit.network/blog/2020/10/06/monero-bitcoin/).
- Philipp Hoenisch and Lucas Soriano del Pino, *Atomic Swaps between
  Bitcoin and Monero*, arXiv:2101.12332v2 (2021):
  [technical paper](https://arxiv.org/html/2101.12332), particularly
  sections 3.2–3.5. Basis for the reference recovery and punishment discussion.
- Sarang Noether, *Discrete logarithm equality across groups*, Monero
  Research Lab, MRL-0010 (2018):
  [technical note](https://web.getmonero.org/es/resources/research-lab/pubs/MRL-0010.pdf).
- Deirdre Connolly et al., *The Flexible Round-Optimized Schnorr Threshold
  (FROST) Protocol for Two-Round Schnorr Signatures*, RFC 9591 (2024):
  [specification](https://www.rfc-editor.org/rfc/rfc9591.html).
- Bitcoin Improvement Proposals:
  [BIP 68: Relative lock-time](https://bips.dev/68/),
  [BIP 112: CHECKSEQUENCEVERIFY](https://bips.dev/112/), and
  [BIP 340: Schnorr signatures for secp256k1](https://bips.dev/340/).

Repository links above support the NULL-specific observations. External
references describe primitives and reference protocols; they do not audit
or validate the proposed NULL adaptation.
