# Security Review

**Project:** `null`
**Remediation verification:** 2026-09-14
**Previous review:** 2026-09-14
**First re-review:** 2026-09-13
**Original review:** 2026-09-12
**Status:** Internal code review; not an independent or formal cryptographic audit

## Executive summary

The code is **not ready for a mainnet launch**.

The remediation verification confirms that every finding through RC-13 is
fixed with regression coverage. In the last change, undigested post-genesis
databases are refused while a genesis-only store can be safely stamped, closing
RC-08's migration gap. One shared `header_lookback` now supplies the required
`difficulty_window + 1` headers to main-chain validation, side-chain validation,
the bundled miner and test construction, closing RC-13's mainnet-only target
mismatch.

No direct arbitrary-mint, same-chain double-spend, or practical monetary
overflow exploit was identified. Nullifier uniqueness is enforced within a
transaction and across a block on both validation paths, then against persistent
chain state and atomically in storage when a block is applied. Public amounts
and block credit use bounded checked arithmetic; hidden values are
range-constrained; and binding signatures enforce the exact fee or coinbase
balance without a practical scalar-field wrap under the action limit.

No new security finding was identified in the remediation changes. The
mainnet-sized retarget regression reaches a harder target and proves that the
easiest target is rejected on both the main-chain and side-chain paths. The
legacy-store regression separately covers the safe genesis-only case and the
refused post-genesis case.

Independent review of the circuit and cryptographic construction remains the
largest residual monetary risk. The public testnet, launch parameters, peer
seeds, and checkpoints also remain incomplete.

## Scope and methodology

The review focused on code paths that can affect ownership, supply integrity,
double-spend resistance, arithmetic safety, consensus state, wallet secrets,
and node availability:

- `crates/circuit`
- `crates/crypto`
- `crates/protocol`
- `crates/chain`
- `crates/storage`
- `crates/wallet`
- consensus-relevant portions of `crates/node` and `crates/p2p`

The review consisted of manual source inspection, tracing transaction and block
state transitions, checking integer and group-arithmetic bounds, and running the
project's build and test gates. It was not a formal verification of the Halo2
circuit or its underlying cryptographic assumptions.

## Severity definitions

- **Critical:** Directly permits theft, undetectable inflation, arbitrary
  consensus-state creation, or spending without authorization.
- **High:** A practical mainnet blocker capable of persistent consensus,
  availability, or wallet-security failure.
- **Medium:** A meaningful security or fund-safety weakness requiring correction
  before launch, but with material prerequisites or limited impact.
- **Low:** A correctness or defense-in-depth issue with impractical current
  exploitation conditions.

## Findings summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| RC-01 | High | Uncommitted authorization data permits persistent side-chain block poisoning | Fixed 2026-09-12 |
| RC-02 | High | Depth-32 commitment tree can be deliberately exhausted | Fixed 2026-09-13 |
| RC-03 | High | Wallet note updates reuse ChaCha20-Poly1305 nonces | Fixed 2026-09-12 |
| RC-04 | Medium | Inbound connection limit is applied only after an unbounded handshake stage | Fixed 2026-09-12 |
| RC-05 | Medium | Header synchronization queue can grow without a global bound | Fixed 2026-09-12 |
| RC-06 | Medium | Mainnet and testnet use the same address prefix | Fixed 2026-09-12 |
| RC-07 | Low | Block height saturates instead of rejecting exhaustion | Fixed 2026-09-12 |
| RC-08 | Medium | Existing chain state is not bound to the active upgrade schedule | Fixed 2026-09-14 |
| RC-09 | Medium | A downward reorganization across activation can retain wrong-branch mempool entries | Fixed 2026-09-14 |
| RC-10 | Medium | Side-chain pre-storage checks omit cheap contextual and block-wide rejection rules | Fixed 2026-09-14 |
| RC-11 | Low | Compact reconstruction can substitute an authorization variant for the wrong branch | Fixed 2026-09-14 |
| RC-12 | Low | Circuit and roadmap documentation still specifies the obsolete depth and `K` | Fixed 2026-09-14 |
| RC-13 | High | Mainnet validator and miner use different difficulty-history lengths | Fixed 2026-09-14 |

## Detailed findings

### RC-01: Uncommitted authorization data permits persistent side-chain block poisoning

**Severity:** High
**Impact:** Persistent failure to follow a valid best-work branch; network
fragmentation or targeted node denial of service

Transaction IDs intentionally exclude proofs and signatures:

- [`crates/protocol/src/transaction.rs`](../crates/protocol/src/transaction.rs#L5)
- [`crates/protocol/src/transaction.rs`](../crates/protocol/src/transaction.rs#L172)

The block transaction root commits only to these transaction IDs:

- [`crates/protocol/src/block.rs`](../crates/protocol/src/block.rs#L185)
- [`crates/protocol/src/block.rs`](../crates/protocol/src/block.rs#L203)

For a side-chain block, import performs PoW, transaction-root, and checkpoint
checks, then stores the block before full transaction validation:

- [`crates/chain/src/chain.rs`](../crates/chain/src/chain.rs#L104)
- [`crates/chain/src/chain.rs`](../crates/chain/src/chain.rs#L116)
- [`crates/storage/src/store.rs`](../crates/storage/src/store.rs#L198)

This creates the following attack:

1. The attacker obtains a valid competing block.
2. The attacker corrupts a proof or signature. The transaction effects, txid,
   transaction root, header, proof of work, and block hash remain unchanged.
3. The corrupted block is delivered to a victim while it is a side-chain block.
4. The victim stores the corrupted bytes under the valid block hash.
5. A subsequently received authentic block is ignored as already known.
6. If the branch gains more work, reorganization fails during full validation
   and restores the victim's prior chain. The poisoned bytes remain stored, so
   future attempts fail again.

All valid authorization variants prove and authorize the same transaction
effects, so excluding them from the stable transaction ID need not itself be a
problem. The vulnerability arises because the block header does not commit to
the selected authorization data while block storage and duplicate detection are
keyed only by that header hash.

**Recommendation:** Add a consensus commitment to authorization data, such as a
separate authorization root or a full-transaction root in the block header.
Alternatively, do not mark a header hash as fully known until a body has passed
full validation, and allow an invalid candidate body to be replaced. Add a
regression test in which an invalid authorization variant arrives before the
valid variant on a competing branch.

**Resolution (2026-09-12):** Signature and proof verification are stateless,
so a side-chain block now passes the whole stateless check set before it is
stored: transaction count, structure, balances, one signature batch and one
proof batch (`Validator::check_authorization`). A body with corrupted
authorization data is rejected and nothing is written under its header hash,
so the authentic body is still accepted later. Proof of work already gates the
verification cost. Header commitment to authorization data was not added: it
is a consensus change with no benefit once storage requires verification, and
the stable txid stays useful. Side-chain blocks that later win a
reorganization are verified twice; that cost is accepted. Regression test:
`a_side_chain_block_with_a_bad_proof_is_not_stored_and_cannot_shadow_the_real_one`
in `crates/chain/tests/chain.rs`. The threat model's malleability paragraph
was corrected.

### RC-02: Depth-32 commitment tree can be deliberately exhausted

**Severity:** High
**Impact:** Permanent consensus halt once the tree can accept no more outputs

The global note commitment tree has depth 32:

- [`crates/crypto/src/merkle.rs`](../crates/crypto/src/merkle.rs#L18)

The storage frontier returns `TreeFull` after `2^32` leaves:

- [`crates/storage/src/tree.rs`](../crates/storage/src/tree.rs#L38)

A block permits 512 transactions, each transaction may contain 16 actions, and
every action—including a dummy action—appends an output commitment:

- [`crates/protocol/src/consensus.rs`](../crates/protocol/src/consensus.rs#L18)
- [`crates/protocol/src/consensus.rs`](../crates/protocol/src/consensus.rs#L39)
- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L196)

At maximum load this is 8,192 leaves per block:

```text
2^32 leaves / 8,192 leaves per block = 524,288 blocks
524,288 blocks * 120 seconds = 62,914,560 seconds
                                  ~= 728 days
                                  ~= 2 years
```

A miner can create padded self-spends and recover their fees through the
coinbase of blocks it mines. Even without a single miner filling every block,
the tree is a fixed lifetime resource with no rollover rule. Once full, the
mandatory coinbase itself cannot append its output actions and no further valid
block can be produced.

**Recommendation:** Increase the tree depth substantially or design a
consensus-level tree epoch/rollover mechanism. The latter changes anchors,
witness handling, wallet scanning, and circuit semantics and requires its own
security review. Add boundary tests that start near the final valid position and
exercise block validation, mining, reorganization, and wallet behavior.

**Resolution (2026-09-13):** The tree depth is 48, which at the maximum block
load lasts over 100,000 years. An epoch rollover was rejected because the
anchor would reveal each spent note's epoch and partition the anonymity set.
The circuit moved from `K = 11` to `K = 12`; depth 40 and 48 were measured to
cost the same there, so 48 was taken. Proving is about 1.55 times slower and
proofs are 64 bytes longer per class; verification is unchanged. Positions are
64-bit throughout; the verifying key hash and the mainnet genesis hash are
re-pinned. A full tree is still a consensus failure (`TreeFull` invalidates the
block); boundary tests at position `2^48` are not possible with the frontier
store, which only appends from genesis, so the constant and the position width
are tested instead. Numbers in `docs/perf.md`, reasoning in
`docs/decisions.md`. Separately, the network upgrade mechanism in
`docs/upgrades.md` now makes a change of this kind possible after launch.

### RC-03: Wallet note updates reuse ChaCha20-Poly1305 nonces

**Severity:** High
**Impact:** Loss of AEAD confidentiality guarantees between record versions and
possible forgery of encrypted note records when multiple versions are available

The nonce is deterministically derived only from a record tag and database
position:

- [`crates/wallet/src/wallet.rs`](../crates/wallet/src/wallet.rs#L96)

An existing note is encrypted again at the same position when it is marked
spent, and again when a rollback clears that state:

- [`crates/wallet/src/wallet.rs`](../crates/wallet/src/wallet.rs#L397)
- [`crates/wallet/src/wallet.rs`](../crates/wallet/src/wallet.rs#L432)

The plaintext changes because `spent_at` changes:

- [`crates/wallet/src/scan.rs`](../crates/wallet/src/scan.rs#L32)

ChaCha20-Poly1305 requires a nonce never to be reused with the same key. If two
record versions survive in backups, snapshots, or recoverable copy-on-write
pages, keystream reuse exposes the XOR relationship between plaintexts and reuse
of the Poly1305 one-time key undermines record authentication.

**Recommendation:** Generate a fresh random 96-bit nonce for every encryption
operation and store it next to the ciphertext. Authenticate the record type,
position, network identifier, and encoding/schema version as associated data.
Add tests proving that repeated updates and reorg rollbacks always use distinct
nonces.

A further reuse path exists beyond the spent-flag change: after a rollback and
rescan, a different note can occupy the same tree position, so the same nonce
would encrypt two unrelated plaintexts.

**Resolution (2026-09-12):** Every seal draws a fresh random nonce from the
operating system and stores it ahead of the ciphertext. The layout version,
record tag and position are authenticated as associated data, so a record
cannot be moved to another slot or read under a future layout. The network
identifier is not in the associated data; the genesis hash is checked in the
clear on open. Wallet files written before this change no longer open and must
be recreated from the seed phrase, which is acceptable before launch. Tests:
`sealing_the_same_record_twice_uses_distinct_nonces_and_both_open`,
`a_sealed_record_opens_only_under_its_key_tag_and_position`, and the scanning
test asserts that the stored record carries three distinct nonces across
create, spend and rollback.

### RC-04: Inbound limit is applied only after an unbounded handshake stage

**Severity:** Medium
**Impact:** File-descriptor, memory, and task exhaustion by silent TCP clients

The listener spawns a task for every accepted socket without first acquiring a
connection permit:

- [`crates/node/src/net.rs`](../crates/node/src/net.rs#L23)

The Noise handshake performs socket reads without a deadline:

- [`crates/p2p/src/transport.rs`](../crates/p2p/src/transport.rs#L37)

The configured inbound limit is checked only after the handshake completes and
the node receives the connected event:

- [`crates/node/src/node.rs`](../crates/node/src/node.rs#L448)

An attacker can therefore open many sockets and remain silent before reaching
the code that counts inbound peers.

**Recommendation:** Acquire a bounded pre-handshake permit before spawning the
connection task, set strict handshake read/write deadlines, and consider a
separate small allowance for fully connected inbound peers.

**Resolution (2026-09-12):** The Noise handshake runs under a ten-second
deadline (`transport::HANDSHAKE_TIMEOUT`) and fails with `HandshakeTimeout`.
The listener acquires one of 32 pending slots (`net::MAX_PENDING_INBOUND`)
before it accepts a socket and releases it when the handshake ends, so silent
clients hold at most 32 sockets for at most ten seconds each; the existing
post-handshake inbound cap is unchanged. Tests:
`a_silent_peer_times_out_of_the_handshake` in `crates/p2p/src/transport.rs`
and `silent_clients_hold_a_pending_slot_only_until_the_deadline` in
`crates/node/src/net.rs`.

### RC-05: Header synchronization queue can grow without a global bound

**Severity:** Medium
**Impact:** Memory exhaustion by a selected synchronization peer

`BlockSync` stores queued headers in a `VecDeque`:

- [`crates/p2p/src/sync.rs`](../crates/p2p/src/sync.rs#L52)

Each accepted header message appends to that queue, while additional headers are
requested before the existing queue is necessarily drained:

- [`crates/p2p/src/sync.rs`](../crates/p2p/src/sync.rs#L92)
- [`crates/node/src/node.rs`](../crates/node/src/node.rs#L670)

Individual messages are bounded, but the cumulative queue is not. A malicious
sync peer can provide a long chain of structurally linked headers and grow node
memory.

**Recommendation:** Cap total queued plus in-flight headers, apply contextual
header checks as early as practical, and stop requesting additional headers
until the queue falls below a low-water mark.

**Resolution (2026-09-12):** Header requests are paced by the syncer: one
request outstanding at a time, and a new one only while fewer than
`HEADERS_LOW_WATER` (4,000) headers are queued. The queue is therefore bounded
by `MAX_QUEUED_HEADERS` (6,000, about 1.5 MB); a headers message that would
exceed it is rejected as misbehavior. Requests resume as downloaded blocks
drain the queue. Contextual header checks before download were not added;
proof of work is checked on import and a peer feeding bad headers is banned at
the first invalid block. Tests:
`header_requests_pause_at_the_low_water_mark_and_resume_as_blocks_arrive` and
`a_full_queue_rejects_further_headers_and_exhaustion_stops_requests` in
`crates/p2p/src/sync.rs`.

### RC-06: Mainnet and testnet use the same address prefix

**Severity:** Medium
**Impact:** Accidental cross-network payment and preventable fund-recovery events

All payment addresses use the fixed `coin` human-readable prefix:

- [`crates/protocol/src/address.rs`](../crates/protocol/src/address.rs#L19)

The address itself carries no network identifier, so user interfaces cannot
reject a testnet address supplied to a mainnet node or vice versa.

**Recommendation:** Define distinct mainnet and testnet HRPs and make the network
an explicit input to address encoding and decoding. Consider also binding the
network or genesis identifier into transaction signature domains to prevent
replay across intentionally cloned networks.

A testnet transaction carries a testnet anchor, which is not a mainnet tree
root, so cross-network replay already fails on the anchor check. The
signature-domain binding is defense in depth rather than a replay fix.

**Resolution (2026-09-12):** Addresses are written with `coin` on the main
network and `tcoin` on test networks (`address::AddressPrefix`), and decoding
takes the expected prefix and refuses the other. The prefix is a chain
parameter; node commands take it from `--network`, and wallet commands that
talk to a node derive it from the node's genesis hash so a mainnet address
cannot be paid from a testnet node or the reverse. The signature-domain binding
was not added at the time; the upgrade mechanism of 2026-09-13 then gave each
network its own branch id in every sighash, which provides it. Tests:
`an_address_for_another_network_is_refused` in
`crates/protocol/src/address.rs` and `a_network_is_recognized_by_its_genesis_hash`
in `crates/node/src/config.rs`.

### RC-07: Block height saturates instead of rejecting exhaustion

**Severity:** Low
**Impact:** Height-index corruption and invalid repeated-height blocks after
`u32::MAX`

Expected next heights are calculated with `saturating_add(1)` in block
validation, storage, and mining:

- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L59)
- [`crates/storage/src/store.rs`](../crates/storage/src/store.rs#L224)
- [`crates/node/src/miner.rs`](../crates/node/src/miner.rs#L57)

At `u32::MAX`, another block at the same height satisfies this comparison and
overwrites height-indexed state. At a two-minute interval this is more than
16,000 years away, so it is not a practical present-day monetary exploit, but
consensus must define terminal behavior rather than silently saturate.

**Recommendation:** Use `checked_add(1)` and reject block production and import
when the height space is exhausted. Add a unit test at `u32::MAX`.

**Resolution (2026-09-12):** `consensus::next_height` returns
`Error::HeightExhausted` at `u32::MAX` and is the only way validation, storage
and the miner compute the next height. Test:
`next_height_counts_up_and_refuses_exhaustion` in
`crates/protocol/src/consensus.rs`. The call sites cannot be driven to
`u32::MAX` in a test, since the store only appends sequentially from genesis.

### RC-08: Existing chain state is not bound to the active upgrade schedule

**Severity:** Medium

**Impact:** A node upgraded late, downgraded, or started with different consensus
parameters can silently trust a main chain that the running binary considers
invalid, remain on a fork, and mine descendants of invalid state

`Chain::new` checks only whether height zero has the expected genesis hash:

- [`crates/chain/src/chain.rs`](../crates/chain/src/chain.rs#L45)

The database metadata records only the tip hash. It does not record the upgrade
schedule, active branch, circuit/verifying-key identity, or the last block
validated under those rules:

- [`crates/storage/src/store.rs`](../crates/storage/src/store.rs#L27)

An upgrade schedule deliberately does not change genesis. Consider an old node
that continues past an activation under the old branch, followed by an operator
installing the new binary while reusing its database. Startup accepts the store
because genesis matches, but none of the already-applied post-activation blocks
is revalidated under the new branch. The node then builds new-branch blocks on
top of an invalid old-branch history. A downgrade has the symmetric problem.
This becomes more serious if a future upgrade changes monetary or state rules,
not just the signature domain.

**Recommendation:** Bind persisted chain state to a consensus-state identifier
that covers the schedule and verifying keys. When that identifier changes,
refuse startup with an actionable error or replay/rebuild from the earliest
affected activation. Add tests that build past activation under old parameters,
reopen under new parameters, and prove that the node cannot silently use the
old state. Document the late-upgrade and downgrade procedure.

**Partial resolution (2026-09-14):** The store records a digest of the genesis
branch, the upgrade schedule and the verifying key's pinned description
(`chain::rules_digest`, domain `null_RulesDigest`). Opening a store recorded
under a different digest fails with `Error::RulesMismatch`, which tells the
operator to delete the database and resync. Refusal was chosen over rewinding:
frontiers are pruned beyond the reorganization depth, so a rewind to an
arbitrary activation height is not generally possible, and a resync is the
honest answer. Tests: `rules_digest_covers_the_branch_and_the_schedule` in
`crates/chain/src/chain.rs` and `a_store_built_under_other_rules_is_refused` in
`crates/chain/tests/chain.rs`. `docs/upgrades.md` documents the late-upgrade and
downgrade procedure.

The remaining migration path is trust on first use. If `rules_digest()` returns
`None`, `Chain::new` records the running binary's digest regardless of the
store's height or provenance. The test above covers a store that already has a
different digest; it does not cover a legacy store without one. A node can thus
run an old, pre-digest binary past an activation and then open that invalid
state directly with a newer binary: the newer digest is attached and the
history is trusted, reproducing the original late-upgrade failure. This matters
for the first upgrade after deploying the digest mechanism, or whenever an
operator skips the required bootstrap release.

**Remaining recommendation:** Record the digest only for a fresh store (or a
store containing genesis alone). Refuse and require a resync when a legacy
store has post-genesis state but no digest. Add a regression test constructing
such a store and proving that `Chain::new` refuses it. Treat deployment of this
rule as a mandatory migration release before any activation.

**Resolution (2026-09-14, second pass):** A store with no digest is stamped
only when it holds genesis alone; one with any further history and no digest is
refused with `RulesMismatch`, whose message now says "different or unrecorded".
Test: `a_store_with_history_but_no_rules_digest_is_refused` in
`crates/chain/tests/chain.rs` covers both the genesis-only and the with-history
cases. `docs/upgrades.md` states that the digest release is a mandatory
migration before any activation.

### RC-09: Downward activation reorg retains wrong-branch mempool entries

**Severity:** Medium

**Impact:** Persistent invalid mining templates and transaction replacement
failure after a higher-work, lower-height reorganization crosses an activation

On a reorganization, the node filters transactions from reverted blocks before
re-admitting them, but it does not compare the branch expected before the reorg
with the branch expected at the new tip:

- [`crates/node/src/node.rs`](../crates/node/src/node.rs#L779)

`Mempool::readmit` concerns only the supplied reverted transactions. Existing
pool entries are retained, and `select` checks anchor age but does not recheck
their signatures:

- [`crates/chain/src/mempool.rs`](../crates/chain/src/mempool.rs#L129)
- [`crates/chain/src/mempool.rs`](../crates/chain/src/mempool.rs#L198)

Applying the replacement branch clears the pool only if one of its applied
blocks is exactly the last block before activation. A cumulative-work reorg can
legitimately finish at a lower height. If it moves from after activation to a
tip below `activation - 1`, none of the replacement blocks triggers that clear.
A transaction anchored before the fork but signed for the newer branch remains
selectable under the older branch. Locally mined blocks containing it fail
signature validation, and its branch-independent txid prevents admission of a
correctly re-signed variant until the stale entry is removed.

**Recommendation:** Capture `branch_at(next_height(old_tip))` before import and
compare it with `branch_at(next_height(new_tip))` after every reorganization.
Clear or fully revalidate the pool when they differ. Add a higher-work,
lower-height reorg test that crosses an activation in both directions.

**Resolution (2026-09-14):** The pool remembers the branch its signatures were
verified for and compares it with the next block's branch, read from the store's
actual tip, on every insert, readmit, select and applied block. Any difference
empties the pool, whichever way the tip moved, so the activation-height special
case is gone and no caller has to remember to capture a branch. Readmission takes
the reverted blocks and skips those from another branch itself. Test:
`a_reorganization_below_an_activation_empties_the_pool_too` in
`crates/chain/tests/mempool.rs` reverts from above an activation to below it.

### RC-10: Side-chain pre-storage checks omit cheap invalidity checks

**Severity:** Medium

**Impact:** CPU, bandwidth, and persistent disk amplification using blocks that
can never be valid on any reorganization

Before storing a side-chain block, `Chain::import` checks Equihash and whether
the header hash meets the target declared by that same header, then performs the
expensive signature and proof batches:

- [`crates/chain/src/chain.rs`](../crates/chain/src/chain.rs#L116)
- [`crates/chain/src/pow.rs`](../crates/chain/src/pow.rs#L30)

This path does not compare the target with the parent-derived expected target or
even reject a target above `pow_limit`. It also calls `check_authorization`,
which checks duplicate nullifiers inside each transaction but not duplicates
across transactions:

- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L138)
- [`crates/protocol/src/validate.rs`](../crates/protocol/src/validate.rs#L17)

An attacker can choose an almost-unrestricted compact target, create one valid
regular transaction against an arbitrary private tree, repeat that same
transaction hundreds of times, and attach a valid coinbase for the resulting
fees. The block passes pre-storage authorization even though its target and
repeated nullifier guarantee that full validation will fail. Transaction and
proof bytes can be reused in each descendant; only a new Equihash solution and
header are needed. These blocks remain in the block table and may later trigger
failed reorganization attempts.

This does not permit invalid state to be applied: `validate_and_apply` checks the
expected target and a block-wide nullifier set before storage mutation. It does,
however, defeat the stated goal that only plausibly valid, adequately worked
side-chain bodies receive expensive verification and persistent storage.

**Recommendation:** Before authorization batching, reject cross-transaction
nullifier duplicates and `target > pow_limit`. Prefer validating the side-chain
header context against its stored ancestry, including height, expected target,
timestamp, checkpoint, and invalid-ancestor status, before verifying or storing
the body. Cache invalid branches and cap/prune non-main-chain storage. Add a
regression test with repeated transactions and an above-limit target.

**Resolution (2026-09-14):** A side-chain block now passes
`Validator::check_side_chain_block` before storage: height follows the parent,
checkpoint, then the same header rules the main chain applies (version,
median-time timestamp, expected target from the difficulty rule, proof of work)
computed over the block's own ancestry by following previous-hash links, then
the transaction root and the stateless transaction checks. Block-wide nullifier
uniqueness moved into the stateless batch, ahead of any signature or proof
verification, so a repeated transaction is rejected before the batches run on
either path. Not done: caching invalid branches and capping side-chain storage;
with the expected-target check every stored side-chain block now carries real
proof of work, which is the bound. Tests:
`a_side_chain_block_with_the_wrong_target_is_not_stored` and
`a_side_chain_block_repeating_a_transaction_is_not_stored` in
`crates/chain/tests/chain.rs`.

### RC-11: Compact reconstruction can use the wrong authorization branch

**Severity:** Low

**Impact:** Valid compact blocks can be reconstructed with invalid signatures,
causing rejection and peer misbehavior scoring around an activation

The txid excludes both authorization data and the branch id, while the sighash
includes the branch id:

- [`crates/protocol/src/transaction.rs`](../crates/protocol/src/transaction.rs#L177)

Compact block reconstruction fills a transaction slot from the local mempool by
txid without checking that the entry was signed for the compact block's height:

- [`crates/node/src/node.rs`](../crates/node/src/node.rs#L833)

The owner of a transaction can produce two authorization variants with identical
effecting data and txid, one for each branch. Near activation, a node whose pool
contains the variant for its next block can substitute it into a valid compact
side-chain block at a height governed by the other branch. The assembled block
then fails validation and the sender can be scored or banned even though its
announced block was valid.

**Recommendation:** Tag mempool entries with the branch under which they were
verified. Use one for compact reconstruction only when that branch equals
`branch_at(compact.header.height)`; otherwise request the full transaction.
Cover compact blocks on both sides of an activation.

**Resolution (2026-09-14):** The pool is verified for exactly one branch, the
next block's (RC-09), so the check is per compact block rather than per entry:
when the compact block's height is under another branch than the next block,
the pool is not consulted and every transaction is requested from the sender.
Test: `the_pool_fills_compact_blocks_only_on_its_own_branch` in
`crates/node/src/node.rs`.

### RC-12: Consensus documentation still describes depth 32 and `K = 11`

**Severity:** Low

**Impact:** External reviewers or independent implementations can analyze or
implement the wrong circuit and derive incompatible keys, proofs, and genesis

The implementation now uses a 48-level tree and `K = 12`, but the circuit
statement still says depth 32, a 32-bit position, and 32 siblings. The roadmap
also still marks `K = 11` and depth 32 as the chosen values, and the Merkle
gadget/storage comments retain the old number:

- [`docs/circuit.md`](circuit.md#L32)
- [`TODO.md`](../TODO.md#L67)
- [`crates/circuit/src/gadgets/merkle.rs`](../crates/circuit/src/gadgets/merkle.rs#L1)
- [`crates/storage/src/tree.rs`](../crates/storage/src/tree.rs#L38)

Shared constants keep the compiled components consistent, so this is not a
runtime money exploit. It is nevertheless unsafe specification drift for a
consensus system.

**Recommendation:** Update the live circuit specification, roadmap, and source
comments to depth 48, 48 position bits/siblings, 64-bit stored positions, and
`K = 12`. Preserve historical depth-32 discussion only where explicitly dated.

**Resolution (2026-09-14):** `docs/circuit.md`, the two roadmap lines, the
Merkle gadget's module comment and the storage tree's capacity note now state
depth 48, 64-bit positions and `K = 12`; the dated decision entries keep the
history.

### RC-13: Mainnet validator and miner use different difficulty-history lengths

**Severity:** High

**Impact:** Bundled miners can have every correctly retargeted block rejected
from height 61, while custom miners can keep producing blocks at the easiest
target; consensus availability failure, ineffective hashrate adjustment, and
accelerated subsidy issuance in wall-clock time

`difficulty::next_target` needs `difficulty_window + 1` headers to obtain the
configured number of solve-time pairs. If it receives fewer, it returns
`pow_limit`:

- [`crates/chain/src/difficulty.rs`](../crates/chain/src/difficulty.rs#L29)

The validator's shared main-chain/side-chain lookback asks for only
`max(difficulty_window, MEDIAN_TIME_SPAN)` headers:

- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L113)

For mainnet, `difficulty_window` is 60 and the median span is 11. Validation
therefore always gives `next_target` only 60 headers, one fewer than required,
and always expects `pow_limit`. The bundled node's template path independently
and correctly asks for 61 headers:

- [`crates/node/src/node.rs`](../crates/node/src/node.rs#L987)

At tip height 60 it can therefore compute the first real retarget. If the first
60 solve times average below the target 120 seconds, the mined block at height
61 has a target below `pow_limit` and the same node rejects it as not matching
the difficulty rule. A custom miner instead keeps declaring and satisfying
`pow_limit`, which validators accept indefinitely. Higher hashrate can advance
the height and subsidy schedule faster than intended. The nominal supply cap
still holds because subsidy remains a function of height; this is not an
arbitrary-mint or arithmetic-overflow path.

The test network does not expose the bug: its difficulty window is 6, so the
validator's 11-header median lookback also supplies the 7 headers the difficulty
rule needs. The difficulty unit tests call `next_target` directly with the
correct number of samples and likewise cannot catch drift between its callers.

**Recommendation:** Change the validator lookback to
`difficulty_window.saturating_add(1).max(MEDIAN_TIME_SPAN)` and use one shared
helper for both validation and template construction. Add an end-to-end
regression configuration with `difficulty_window >= MEDIAN_TIME_SPAN`, extend
through its first fast retarget, and assert that the miner's adjusted target is
accepted while `pow_limit` is rejected on both main-chain and side-chain paths.

**Resolution (2026-09-14):** `validate::header_lookback` is the one place that
says how many headers the header rules read, `difficulty_window + 1` or the
median span, whichever is larger. The validator, the node's block template and
the test harness all call it. Test:
`a_mainnet_sized_difficulty_window_retargets_and_is_enforced` in
`crates/chain/tests/chain.rs` uses a window of 12 with blocks five times faster
than the interval, extends through the first retarget, and rejects the easiest
target on both the main-chain and the side-chain path. The test was run against
the old lookback and fails there.

## Upgrade mechanism assessment

The branch-domain design correctly makes old-branch signatures invalid at the
activation height, and the normal upward activation path is covered by chain and
mempool tests. Main and test networks currently have different genesis branch
ids, and neither network currently schedules an actual upgrade.

The database binding now also handles its bootstrap boundary: a legacy store
with post-genesis history and no digest is refused, while genesis alone may be
safely stamped. The digest release remains a mandatory migration before any
activation is scheduled.

The mechanism is infrastructure rather than a complete implementation of every
future upgrade type. The chain currently holds one verifying key and transaction
parsing uses global versions and proof lengths. A circuit, proof-format, or
encoding upgrade will therefore need explicit branch-specific key selection and
dual historical parsing in addition to adding an `Upgrade` row. Those code paths
must be implemented and tested before scheduling such an upgrade.

`networks_have_distinct_branches_and_well_formed_schedules` in
`crates/chain/src/params.rs` now collects every branch id of every network and
fails on a repeat, so a collision is a build failure rather than a runtime
property. The genesis hash was not added to the sighash.

## Monetary safety assessment

### Double-spend resistance

The reviewed nullifier handling is coherent:

- Duplicate nullifiers inside a transaction are rejected by structural
  validation: [`crates/protocol/src/validate.rs`](../crates/protocol/src/validate.rs#L36).
- A single `seen` set spans every transaction in a block, catching cross-
  transaction duplicates: [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L269).
- Each nullifier is checked against persistent chain state:
  [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L216).
- Storage inserts every nullifier atomically with the block and refuses an
  unexpected duplicate: [`crates/storage/src/store.rs`](../crates/storage/src/store.rs#L251).
- Reorganization removes only nullifiers belonging to reverted blocks before
  validating the replacement branch.

No direct path for spending the same note twice on one valid chain was found.

### Amounts and integer overflow

Public amounts are bounded to `MAX_MONEY`, and their additions and subtractions
are checked:

- [`crates/protocol/src/amount.rs`](../crates/protocol/src/amount.rs#L14)
- [`crates/protocol/src/amount.rs`](../crates/protocol/src/amount.rs#L47)

Block fees and coinbase credit are recomputed with checked addition:

- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L245)

The circuit constrains both old and new hidden note values below `2^64`:

- [`crates/circuit/src/action.rs`](../crates/circuit/src/action.rs#L277)
- [`crates/circuit/src/gadgets/range.rs`](../crates/circuit/src/gadgets/range.rs#L24)

Each action constrains its public value commitment to the signed difference
between its old and new values:

- [`crates/circuit/src/action.rs`](../crates/circuit/src/action.rs#L429)

The binding verification key subtracts the required public balance from the sum
of those commitments:

- [`crates/crypto/src/signature.rs`](../crates/crypto/src/signature.rs#L216)

With at most 16 actions, the absolute integer sum is below `2^68`, far below the
approximately 254-bit Pallas scalar order. Consequently, an attacker cannot make
an unbalanced transaction appear balanced by wrapping the group scalar under
the current action limit.

No practical monetary overflow was found. The prior height-exhaustion issue is
fixed by RC-07's checked terminal behavior.

### Supply creation

The validator treats the first transaction as the only value-creating
transaction and supplies it the exact negative balance of subsidy plus fees.
Every other transaction must balance to its action-count-derived fee:

- [`crates/chain/src/validate.rs`](../crates/chain/src/validate.rs#L245)
- [`crates/protocol/src/validate.rs`](../crates/protocol/src/validate.rs#L43)

A malicious coinbase can technically consume real notes rather than using only
dummy spends, but the binding equation still limits its net value creation to
the exact block credit. This is a specification mismatch, not an identified
inflation path.

Before its fix, RC-13 did not change the amount created by an individual block,
but it removed the intended mainnet hashrate feedback and could advance
subsidy-bearing heights faster than the documented schedule. The shared header
lookback now makes validators and miners enforce the same retarget.

The decisive residual risk is circuit soundness. A constraint omission could
create silent inflation, and a fully shielded pool does not permit external
supply reconciliation. The project's threat model acknowledges this:

- [`docs/threat-model.md`](threat-model.md#L39)

The external audit of `crates/circuit` and `crates/crypto` remains incomplete:

- [`TODO.md`](../TODO.md#L152)

## Verification results

The following checks passed at the reviewed commit:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace --release --locked
```

The workspace registered 384 tests. All 380 executed tests passed; four ignored
measurement/generation tests were not treated as security coverage.

`cargo-audit 0.22.2` scanned 212 locked dependency entries against 1,244 RustSec
advisories. It reported no known vulnerability and one allowed unmaintained
package warning:

- `atomic-polyfill 1.0.3` — `RUSTSEC-2023-0089`

A clean build, test suite, and advisory scan do not establish circuit soundness
or absence of protocol-level vulnerabilities.

## Mainnet readiness requirements

At minimum, a mainnet release should be blocked until all of the following are
complete:

1. Every finding through RC-13 is fixed, with regression tests.
2. Obtain independent reviews of the Halo2 circuit, cryptographic construction,
   consensus validation, storage/reorganization logic, and wallet encryption.
3. Add property or model-based tests for supply conservation, nullifier state,
   failed/retried reorganization, and authorization-data malleability.
4. Run a long-lived adversarial public testnet with realistic proving, mining,
   block-load, reorganization, database-recovery, and upgrade scenarios.
5. Finalize all provisional monetary and consensus parameters, seed peers, and
   launch checkpoints. The current documentation still describes the project as
   a local testnet and lists these launch items as incomplete:
   [`README.md`](../README.md#L6), [`docs/params.md`](params.md#L3),
   [`TODO.md`](../TODO.md#L139).

## Final verdict

The core transaction balance and nullifier design appears thoughtful. This
review found no immediate direct mint, same-chain double-spend, practical
monetary-overflow exploit, or remaining open implementation finding. Every
finding through RC-13 is fixed with regression coverage.

That is not yet a mainnet-ready verdict. The lack of independent circuit,
cryptography and consensus review remains the largest unknown monetary risk;
the public adversarial testnet, model/property testing, final parameters, seed
peers and launch checkpoints are also incomplete. The current code should not
custody funds with material value until those release requirements are met.
