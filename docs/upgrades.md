# Network upgrades

How a change of consensus rules is scheduled, shipped and activated.
Kept deliberately small: one table per network, one identifier per rule
set, one place in the code that says which rules apply at a height.

## The mechanism

Every network's `ChainParams` carries a `genesis_branch: BranchId` and an
`upgrades: &[Upgrade]` list, each entry a `(height, branch)` pair sorted
by height. `ChainParams::branch_at(height)` returns the branch of the
last upgrade activated at or below `height`, or the genesis branch. That
function is the only way consensus code learns which rules are in force.

A `BranchId` is a 32-bit identifier of a rule set. It is not stored in
any block or transaction. Instead every signature hash binds it:

```
sighash = BLAKE2b-256[SIGHASH](effecting data || branch id)
```

So a transaction is signed for exactly one rule set, and the signatures
fail under any other. Consequences:

- After an upgrade, transactions signed for the old rules are invalid in
  new blocks and the reverse, so neither side of a fork can replay the
  other's transactions. A wallet rebuilds a pending payment after the
  activation height.
- Main and test networks have different genesis branches, so a test
  network transaction is never valid on the main network.
- The mempool empties when the block before an activation height is
  applied, and admits only transactions signed for the new branch from
  then on. Transactions from reverted blocks are readmitted only if
  their block's branch matches the next block's.
- The txid does not include the branch, so a transaction keeps its id
  across networks and forks; only its validity changes.

Nothing else changes at an activation height unless code gates on it.

## Shipping an upgrade

1. Pick a new branch id: any 32-bit value not used by the network before,
   written as a named constant with a comment saying what it activates.
2. Gate the rule change in code on the branch:
   `if params.branch_at(height) == BRANCH_X { new rule } else { old rule }`.
   Keep the old rule for every height below the activation so nodes can
   still validate history from genesis.
3. Add `Upgrade { height, branch }` to the network's `upgrades` list.
   `ChainParams::upgrades_are_well_formed` is tested for every network:
   ascending heights, none at genesis, distinct branches.
4. Add tests: a block at `height - 1` follows the old rule and one at
   `height` the new one. The chain tests have `Harness::with_params` for
   this; `an_upgrade_changes_which_signatures_a_block_accepts` is the
   template.
5. Record the change in `docs/decisions.md`, add the branch and height to
   `docs/params.md`, and release the software well before the height.

A node that has not upgraded keeps validating under the old branch past
the activation height. It rejects the first block signed for the new
branch as having invalid signatures, bans the peer that sent it, and
stays on the old chain: a hard fork, visible in its logs.

## Late upgrades and downgrades

The chain database records a digest of the rules it was built under: the
genesis branch, the upgrade schedule and the circuit's verifying key. A
binary whose digest differs refuses to open the database with
`store was built under different consensus rules or circuit; delete it
and resync`. That covers the operator who installs a new release after
having mined or followed the old chain past the activation height, and
the operator who downgrades: in both cases blocks applied under the other
rules are not silently trusted. A database with history but no recorded
digest, written by a release from before the digest existed, is refused
for the same reason; only a database holding genesis alone is stamped on
open. There is no in-place rewind; delete the data directory and resync
from peers. Wallet files are unaffected, since the wallet rescans from
the node. The release that introduced the digest is therefore a
mandatory migration before any activation can be scheduled.

Because the digest changes with every scheduled upgrade, a release that
adds a row to the schedule also invalidates every existing database, so
ship it well before the activation height and say so in the release
notes. Mempool contents are not persisted and need no migration.

## What this does not do

- No signalling or voting. Activation is by height, chosen in advance.
- No version bits in headers. `BLOCK_VERSION` and `TX_VERSION` stay
  fixed; a transaction's shape is the same on every branch, which is what
  keeps it free of fingerprints. A future upgrade that must change the
  shape gates the new encoding on the branch and bumps the version for
  every transaction at once.
- No peer-level branch check. Peers compare genesis hashes on connect;
  a peer on the other side of a fork is discovered and banned when it
  sends an invalid block, as with any invalid block.
