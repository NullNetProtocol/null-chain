# JSON-RPC reference for exchange and mining pool integration

Every method the node (`nulld --rpc-http`) and the wallet daemon
(`null-wallet-rpc`) serve, with the reasoning behind the shape of the
interface. `guide-exchange.md` and `guide-pool.md` are the walk-throughs
in the order an integrator does things. It began as the plan of 2026-09-14 and became the reference
as each phase shipped the same day; the phase headings are kept so the
history reads in order.

## What is different about a shielded-only chain

Every integration guide for a Bitcoin-like coin assumes three things that
are false here. The plan is shaped by them.

1. **The chain reveals nothing about addresses.** There is no balance to
   look up, no "transactions to address X". Deposits are found only by
   trial-decrypting outputs with a viewing key. So the node cannot answer
   "did my customer pay?"; only a wallet holding the exchange's incoming
   viewing key can. The integration surface is therefore a node RPC plus
   a wallet RPC, like Monero, not one node RPC like Bitcoin.
2. **Sending takes seconds, not milliseconds.** A payment carries a
   zero-knowledge proof: about 0.8 s for two actions and 4.8 s for
   sixteen (`docs/perf.md`). Send calls must be asynchronous: they return
   an operation id, and the caller polls. Zcash's `z_sendmany` has the
   same shape for the same reason.
3. **The coinbase is a shielded transaction with a proof.** A mining pool
   cannot assemble a coinbase from a script the way it does for Bitcoin.
   The node must build the coinbase, proof included, for the pool's
   payout address and hand the pool a finished header to grind. That
   changes the template protocol.

Three properties work in our favour and the plan uses them.

- **Diversified addresses.** One incoming viewing key decrypts notes sent
  to any of its 2^88 addresses, and the wallet can recover which address
  index a note was sent to. An exchange gives every customer their own
  deposit address and detects all deposits with a single key, no per-user
  keys and no address reuse. This replaces Bitcoin's HD derivation and
  Monero's integrated addresses in one mechanism.
- **Batching is native.** A transaction holds up to 16 actions at a fixed
  fee of 10,000 units per action. One withdrawal transaction pays up to
  fifteen customers plus change for 160,000 units, and a batch of
  withdrawals is indistinguishable from any other 16-action transaction.
- **Memos.** Every output carries an encrypted 512-byte memo, so a
  deposit can carry a customer tag as an alternative to per-customer
  addresses, and a withdrawal can carry a reference the customer can see.

## The two services

The node serves chain, mempool, mining and verification methods on
`--rpc-http`. It holds no keys. The wallet daemon serves addresses,
balances, deposits and withdrawals for one wallet file on its own
listener and token, syncing from a node over the node's control socket
(`crates/node/src/rpc.rs`, the line protocol the CLI also uses). A pool
needs only the node; an exchange needs both.

## Transport and conventions

- JSON-RPC 2.0 over HTTP POST, on a new `--rpc-http <addr>` listener.
  The line protocol stays for the CLI; both dispatch to the same
  `Request` enum so there is one behaviour.
- Auth: the existing node token in an `Authorization: Bearer` header.
  The listener binds to localhost by default; a pool or exchange fronts
  it with its own proxy, as with every other coin daemon.
- Batch requests supported. Standard JSON-RPC error codes, plus one
  application range documented per method.
- Amounts are integers in the smallest unit, sent as JSON strings to
  avoid 53-bit precision loss. Heights are numbers. Hashes, txids,
  nullifiers, blocks and transactions are lowercase hex. Addresses are
  bech32m text with the network prefix.
- Every response carries the node's `network` and `branch` so a client
  cannot mix networks or sign for the wrong rules by accident.
- Method names follow Bitcoin and Zcash where the meaning is the same, so
  integrators can reuse their mental model, and differ where it is not.

## Phase 0: the layer and the index (done 2026-09-14)

- `--rpc-http <addr>` serves JSON-RPC 2.0 over HTTP (`crates/node/src/jsonrpc.rs`)
  on the same token as the control socket, presented as
  `Authorization: Bearer <token>`. One `POST` per connection, any path,
  body up to 32 MB, batches allowed. Transport failures answer with HTTP
  400, 401 or 405 and a JSON-RPC error body; everything after that is
  HTTP 200 with a result or an error object.
- The store indexes every main-chain transaction id to `(height, index)`
  and records a layout version; a database from before the index is
  refused with "store layout outdated" rather than served without it.
- `crates/node/tests/rpc.rs` spawns a mining node and exercises every
  method over real HTTP.

### Error codes

| Code | Meaning |
|---|---|
| -32700 | body is not JSON |
| -32600 | not a JSON-RPC 2.0 call (missing `"jsonrpc": "2.0"`, method, or params not an array or object; empty batch) |
| -32601 | unknown method |
| -32602 | a parameter is missing, of the wrong type, or not valid hex of the right length |
| -32603 | the node failed while serving the call |
| -32001 | token missing or wrong (with HTTP 401) |
| -1 | the block, transaction or nullifier does not exist |
| -2 | the node refused a submission; the message says why |
| -3 | the node loop has stopped |

### Conventions in force

Parameters are positional or named; both forms below are equivalent:
`{"params": [7]}` and `{"params": {"height": 7}}`. Amounts are decimal
strings in the smallest unit. Hashes, ids, nullifiers, keys and encoded
objects are lowercase hex. Heights, counts and sizes are numbers. Branch
ids are `0x` hex of their 32-bit value.

## Phase 1: node methods (done 2026-09-14)

| Method | Parameters | Result |
|---|---|---|
| `getblockchaininfo` | | `network`, `height`, `best_block_hash`, `genesis_hash`, `syncing`, `branch` (at the tip), `next_branch` (for the next block), `genesis_branch`, `upgrades[{height, branch}]`, `block_interval`, `difficulty_window`, `anchor_max_age`, `max_reorg_depth`, `max_future_seconds`, `pow_limit` (compact hex), `equihash{n,k}`, `fee_per_action`, `action_classes`, `max_actions`, `proof_lengths{class: bytes}`, `max_block_transactions`, `coinbase_maturity` (0), `coin`, `max_money`, `premine` |
| `getblockcount` | | tip height |
| `getbestblockhash` | | tip hash |
| `getblockhash` | `height` | hash, or -1 |
| `getblock` | `block` (height or hash), `verbosity` = 1 | 0: hex. 1 and 2: `hash`, `height`, `version`, `previousblockhash`, `time`, `commitment_root`, `tx_root`, `target` (compact hex), `target_hex` (256-bit), `nonce`, `solution`, `size`, `in_main_chain`, `confirmations` (-1 off the main chain), `nextblockhash` (null at the tip or off chain), `transaction_count`, `tx` (txids at 1, decoded transactions at 2) |
| `getblockheader` | `block` | as `getblock` at verbosity 1 without `tx` |
| `getrawtransaction` | `txid`, `verbose` = false | hex, or the decoded form: `txid`, `version`, `anchor`, `action_count`, `actions[{nullifier, rk, cmx, cv_net}]`, `fee`, `size`, `proof_size`, and `height`, `index`, `confirmations` once mined (0 confirmations while pooled). Serves pooled transactions too |
| `gettransactionstatus` | `txid` | `{status: "pooled", confirmations: 0}`, `{status: "confirmed", height, index, confirmations}`, or `{status: "unknown"}` |
| `sendrawtransaction` | `hex` | txid. Resubmitting a pooled transaction returns its id again; a mined or invalid one is refused with -2 |
| `getrawmempool` | | txids, oldest first |
| `getmempoolinfo` | | `size`, `capacity` |
| `getnullifierstatus` | `nullifier` | `{spent}`. Every nullifier of every mined transaction is spent, the dummy spends of a coinbase included |
| `getcompactblock` | `height` | hex of the compact block light clients sync on |
| `getpeerinfo` | | `[{id, addr, target, direction, ready, version, best_height, score}]` |
| `getnetworkinfo` | | `network`, `protocol_version`, `connections`, `connections_in`, `connections_out`, `handshaking` |
| `getconnectioncount` | | ready peers |
| `uptime` | | seconds since start |
| `stop` | | `"stopping"`; the node exits after answering |
| `help` | | the method names |

A decoded transaction shows what the chain reveals and nothing more:
no addresses, no amounts, no memos. Those exist only for a holder of the
relevant viewing key, through the wallet daemon of Phase 3.

## Phase 2: mining pool methods (done 2026-09-14)

| Method | Parameters | Result |
|---|---|---|
| `getmininginfo` | | `height`, `best_block_hash`, `syncing`, `next_height`, `next_target` (compact hex), `next_target_hex`, `pow_limit`, `subsidy` (next block, smallest units), `mempool`, `work_per_second` (decimal, see below), `block_interval`, `equihash{n, k, personalization, solution_length}` |
| `getblocktemplate` | `payout_address`, `longpollid` (optional) | see below |
| `submitblock` | `template_id`, `timestamp`, `nonce` (32 bytes hex), `solution` (hex, padded to the header field) or a single `block` hex | `{status: "accepted" \| "duplicate" \| "stale", hash}`; an invalid block is error -2 with the validator's reason |

**The template.** The node builds the coinbase paying the subsidy plus
the fees of the selected mempool transactions to `payout_address`,
proves it (about 0.8 s, on the blocking pool, with a proving key built
on the first call), and returns everything the pool needs to grind:

- `template_id`, `height`, `prev_hash`, `longpollid` (same as
  `prev_hash`), `branch`, `expires_at`
- the header fields except nonce and solution: `version`, `timestamp`
  (the node's minimum), `min_timestamp`, `max_timestamp` (the
  future-drift limit; the pool may pick anything between),
  `commitment_root`, `tx_root`, `target` (compact hex) and `target_hex`
- `pow_input`: the exact bytes the header hashes before the nonce, as
  `BlockHeader::pow_input` writes them: version (1 byte), previous hash
  (32), height (LE32), timestamp (LE64), commitment root (32), tx root
  (32), compact target (LE32). Equihash runs over `pow_input || nonce`
  with the `equihash` parameters and personalization; the block hash is
  `BLAKE2b-256[BLOCK_HASH]` of the full header and must be at or below
  `target_hex`. A pool should check that its own serialization of the
  fields equals `pow_input` before grinding.
- `transaction_count`, `coinbase_value`, `fees`

A template for a payout address is reused for 5 seconds, so a pool
asking every second pays one proof per five seconds per address, and it
is rebuilt on a new tip. Templates stay valid for submission for 10
minutes and at most 64 are kept. With `longpollid` set to the tip the
pool last saw, the call waits up to 60 seconds for the tip to change
before answering, so a pool need not poll. `--blocknotify '<command>'`
runs a shell command with `%s` replaced by the hash of every new tip,
for pools that prefer a hook. Templates are refused while the node is
syncing.

**Submission.** By template id the pool sends only what it changed:
timestamp, nonce and solution; the node reassembles the block from the
cached template and imports it exactly as it would a block from a peer.
`accepted` means the block extended or reorganized onto the main chain,
`duplicate` that it was already known, `stale` that it was valid but a
side-chain block. Full-block submission is for pools that assemble their
own blocks from a template's transactions.

**`work_per_second`** is the sum of the work of the blocks in the last
difficulty window divided by the seconds they span, where a block's work
is `2^256 / (target + 1)`: the expected number of Equihash solutions the
whole network tries per second. It is a coarse estimate from block
timestamps, as Bitcoin's `networkhashps` is.

**Rules a pool must know.** There is no coinbase maturity: a coinbase
output is spendable once its anchor is a valid root, which is the next
block. Reorganizations deeper than 200 blocks are refused, so 200
confirmations is safe against anything the network will accept; pools
choose their own smaller number. Stratum is the pool's side: it splits
the 32-byte nonce space among miners, validates shares against
`pow_input` with its own Equihash verifier, and pays miners through the
wallet daemon of Phase 3, fifteen per transaction.

**What the pool does itself.** Stratum is the pool's side: it splits the
nonce space among miners, validates shares against `pow_input` with its
own Equihash verifier, and pays miners. Zcash pools already do exactly
this with a 32-byte nonce and Equihash, so the header layout here should
be documented against Zcash's stratum so a pool operator sees what to
change. Payouts to miners are batched shielded sends, fifteen per
transaction, through the wallet daemon below.

**Rules to state up front.** There is no coinbase maturity rule: a
coinbase output is spendable as soon as its anchor is a valid root, which
is the next block. Reorganizations deeper than 200 blocks are refused, so
a pool that waits 200 confirmations before paying miners is safe against
any reorganization the network will accept; in practice a much smaller
number is fine and the pool chooses its own risk.

## Phase 3: the wallet daemon (done 2026-09-14)

`null-wallet-rpc` is a separate long-running process that holds one
wallet file, syncs it from a node over the node's control socket, serves
the wallet methods over JSON-RPC behind its own token, and carries send
operations from request to confirmation. It is separate from the node
for the same reasons Monero separates them: the node is public
infrastructure and holds no keys; the wallet holds keys and belongs on a
locked-down host; an exchange runs one node and several daemons (hot,
watch-only for deposits, per desk).

```
nulld create --wallet hot.redb --network main            # prints the seed phrase
nulld export-viewing-key --wallet hot.redb --network main  # for the deposit hosts
nulld create --wallet deposits.redb --viewing-key <nullview1...> --network main
null-wallet-rpc --wallet deposits.redb --network main \
    --node 127.0.0.1:18444 --node-token-file /var/lib/null/rpc.token \
    --listen 127.0.0.1:18447
```

The passphrase comes from `NULL_WALLET_PASSPHRASE` or a prompt. The
daemon's token comes from `--token` or `NULL_WALLET_RPC_TOKEN`, else it
is generated and written to `wallet-rpc.token` next to the wallet file.
It syncs every two seconds (`--sync-interval`), with full blocks so memos
are recovered (`--light` scans compact blocks instead). Its JSON-RPC uses
the same transport, envelope, error codes and conventions as the node's.

**Keys and addresses.**

| Method | Parameters | Result |
|---|---|---|
| `getwalletinfo` | | `network`, `watch_only`, `scanned_height`, `node_height`, `synced`, `notes`, `unspent`, `balance`, `pending_operations`, `last_error` (of the sync loop, or null) |
| `getnewaddress` | `label` = "" | `{index, address, label}`: the next diversified address, recorded under the label. Index 0 is the default address, used for change |
| `listaddresses` | | `[{index, address, label}]`, the default address first |
| `getaddressinfo` | `address` | `{is_mine, index, label}` |
| `validateaddress` | `address` | `{valid, network}` |
| `exportviewingkey` | | `{viewing_key, watch_only}`: the full viewing key as `nullview1...` / `tnullview1...`, for a watch-only wallet |

A watch-only wallet is created from an exported key with
`nulld create --viewing-key`. It finds notes, their memos and their
spends exactly as the full wallet does; `sendmany` on it is refused.
This is what an exchange runs on its deposit-detection hosts, with the
spending key nowhere near them.

**Deposits.** Confirmations are counted from the block holding the note
to the wallet's scanned height. A reorganization rolls the wallet back
on its own; a note that disappears with its block disappears from these
lists. Ten confirmations, twenty minutes, is a reasonable deposit
threshold; the network refuses reorganizations deeper than 200.

| Method | Parameters | Result |
|---|---|---|
| `getbalance` | `min_confirmations` = 1 | `{spendable, locked, pending, total}`: spendable has enough confirmations and is not set aside; locked is set aside for pending operations; pending has too few confirmations |
| `listunspent` | `min_confirmations` = 1, `since_height` = 0 | unspent notes: `position`, `txid`, `height`, `confirmations`, `amount`, `address`, `address_index`, `label`, `memo` (text, `{hex}` for binary, null when empty), `spent`, `spent_at`, `spent_by`, `locked` |
| `listreceived` | `min_confirmations` = 1, `since_height` = 0 | every note ever received, spent ones included, same fields |
| `gettransaction` | `txid` | `{txid, height, confirmations, received: [notes], spent: [notes], net}`: our side of one transaction; `net` is received minus spent as a signed decimal string, so a withdrawal shows the fee as part of the outflow |
| `rescan` | `from_height` = 0 | rolls the wallet back and rescans from there |

**Withdrawals.**

| Method | Parameters | Result |
|---|---|---|
| `sendmany` | `recipients: [{address, amount, memo?}]` (1 to 15), `min_confirmations` = 1 | `{operation_id, status: "queued"}` at once |
| `getoperationstatus` | `operation_id` | `operation_id`, `status` (`queued`, `proving`, `submitted`, `confirmed`, `failed`, `cancelled`), `created_at`, `recipients`, `total`, `min_confirmations`, `txid`, `height`, `confirmations`, `attempts`, `error` |
| `listoperations` | `status` (optional filter) | every operation, oldest first |
| `canceloperation` | `operation_id` | the operation, now `cancelled`; only a `queued` operation with no recorded transaction can be cancelled, since an earlier broadcast may still be mined. Operations report this as `cancellable` |
| `estimatefee` | `recipients` = 1 | `{fee, actions}` for that many recipients plus change; a lower bound, since spending many small notes can need a larger class |
| `quotepayment` | `recipients`, `min_confirmations` = 1 | `{fee, total, spends, actions}` for exactly these recipients, selecting notes as `sendmany` would now; `REJECTED` with the shortfall on insufficient funds. Exact for the wallet's current notes; a queued payment builds later and may select differently |

The sync loop builds and proves queued operations one at a time on the
blocking pool; reads keep being served meanwhile. Interrupted builds
resume after restart. Before any broadcast, one database commit records
the exact transaction, txid, and input reservations. `submitted` means
that durable broadcast intent exists; it does not guarantee the node has
acknowledged acceptance. A lost response, timeout, or rejection keeps the
transaction pending and its inputs reserved. The next pass reconciles
its txid and rebroadcasts the same bytes; submission errors appear in
`getwalletinfo.last_error`.

If an unconfirmed anchor ages past the network's limit (100 blocks), the
operation can be rebuilt, up to five build attempts. Replacements spend
only inputs common to all earlier attempts, and all transaction versions
are retained and checked for confirmation. A failed replacement or an
exhausted retry budget leaves any earlier broadcast pending with its
reservations intact; it must not be mistaken for a failed payment.
Only notes with at least `min_confirmations` are spent; change goes to
the default address. Amounts are decimal strings (numbers are accepted).

Rollback reopens removed confirmations and their input reservations in
the same database transaction as the note rollback. Every synchronization
also checks confirmations against the node's current transaction index,
including in compact-scan mode and when an older attempt is mined. A
rescan waits for active synchronization/proving to finish. Cancellation
and the prover's claim are conditional database updates, so only one can
win.

**Upgrading older wallets.** Legacy interrupted `proving` records may
already have been broadcast without their transaction bytes being saved.
They become `failed` with an explicit instruction to reconcile the payment
before retrying; they are never automatically paid again. New builds use
a distinct disk tag, still displayed as `proving`. Older records remain
readable, but do not downgrade a wallet after this update. Upgrade a remote
node alongside its wallet daemon: the control protocol now exposes
`txstatus <txid>`, returning `unknown`, `pooled`, or
`confirmed <height> <index>` after the `ok` prefix.

**Backup.** Stop the daemon and copy the wallet file, or restore from
the seed phrase with `nulld create --phrase` and rescan.

## Phase 4: selective disclosure (done 2026-09-14)

Both are owner-controlled and off-chain; neither touches consensus.

**Payment disclosure.** "Prove to a customer that withdrawal X paid
them." The sender's wallet reveals, for one output of one transaction,
the recipient's transmission key and the ephemeral secret it used: the
two values that decrypt exactly that output and nothing else. A verifier
with any node checks them against the output's ciphertext, commitment
and ephemeral key, so a disclosure cannot claim an amount, address or
memo the transaction does not carry.

| Where | Method | Parameters | Result |
|---|---|---|---|
| wallet daemon | `getpaymentdisclosure` | `txid`, `index` (optional) | `[{index, disclosure (hex), address, amount, memo}]` for every output this wallet sent in the transaction, change included |
| node | `verifypaymentdisclosure` | `disclosure` (hex) | `{valid: true, txid, index, address, amount, memo, height, confirmations}` or `{valid: false, reason}` |

**Address ownership.** "Prove you control this address." The checker
encrypts a message of their choosing to the address; only the holder of
its incoming viewing key can read it back. No signature scheme is
involved, so no new cryptography: it is one note encryption and one
decryption.

| Where | Method | Parameters | Result |
|---|---|---|---|
| node (or any party) | `createchallenge` | `address`, `message` | `{challenge (hex)}` |
| wallet daemon | `answerchallenge` | `challenge` (hex) | `{message}`; error -2 if the challenge is not for this wallet |

The checker keeps the message secret, hands over the challenge, and
compares the answer. A watch-only wallet can answer, since it holds the
incoming viewing key; that is the intended use on a deposit host.

**Still not in scope.** Explorers show blocks, txids, action counts and
nullifiers only; say so before someone builds a balance view. Hardware
wallets and multisig do not exist; multisig on a shielded pool needs a
threshold spend-authorization scheme (FROST over RedPallas is the known
design) and should be planned, not promised.

## Order of work and estimates

| Phase | Content | Estimate |
|---|---|---|
| 0 | JSON-RPC layer, txid index, test harness | done |
| 1 | node methods | done |
| 2 | templates, submission, long poll, mining info | done |
| 3 | wallet daemon, watch-only wallets, async operations | done |
| 4 | disclosure, ownership proofs | done |

Phases 1 and 2 give a mining pool everything it needs. Phase 3 gives an
exchange everything it needs. Write the exchange integration guide and
the pool integration guide as the last step of each phase, with worked
examples against the public testnet, since that is what an integrator
actually reads.
