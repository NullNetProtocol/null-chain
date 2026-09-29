# Mining pool integration guide

How to run a pool for this coin. `docs/rpc.md` is the method reference;
this guide is the walk-through. The proof of work is Equihash `(144, 5)`
on the main network, the same family Zcash pools already run, so most
of an existing Zcash pool applies with the differences called out below.

## What is different, in one paragraph

The coinbase is a shielded transaction with a zero-knowledge proof, so
a pool cannot assemble it. The node builds and proves the coinbase for
your payout address and hands you a finished header to grind. You send
back only what you changed: timestamp, nonce and solution. Payouts to
miners are shielded sends through the wallet daemon, fifteen per
transaction. A mined block's reward matures after 100 blocks on mainnet
(`coinbase_maturity` in `getblockchaininfo`): it enters the note tree at
height `h + 99`, the wallet daemon finds it then, and it is spendable from
`h + 100`.

## 1. Run a synced node with JSON-RPC

```
nulld run --network test --datadir /var/lib/null \
    --rpc 127.0.0.1:18444 --rpc-http 127.0.0.1:18446 \
    --blocknotify 'curl -s http://127.0.0.1:9000/newtip/%s'
TOKEN=$(cat /var/lib/null/rpc.token)
rpc() { curl -s -H "Authorization: Bearer $TOKEN" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" http://127.0.0.1:18446/; }
rpc getmininginfo '[]'
```

`getmininginfo` reports `syncing`; the node refuses templates while it
is true. `--blocknotify` is optional: it runs a shell command with `%s`
replaced by the hash of every new tip, for pools that prefer a hook to
long polling. `work_per_second` is a coarse network-rate estimate from
block timestamps, like Bitcoin's `networkhashps`.

## 2. A payout address

Create the pool's wallet and take its default address; the same wallet
daemon pays miners later.

```
export NULL_WALLET_PASSPHRASE='choose a long one'
nulld create --wallet /srv/pool/pool.redb --network test
# address: tnull1...
```

## 3. Get a template

```
rpc getblocktemplate '["tnull1..."]'
```

The answer is the block minus the proof of work:

- `template_id`: what you submit against; `expires_at`: when it stops
  being accepted (ten minutes).
- `height`, `prev_hash`, `branch`.
- Header fields: `version`, `timestamp`, `min_timestamp`,
  `max_timestamp`, `commitment_root`, `tx_root`, `target` (compact hex),
  `target_hex` (the 256-bit value the block hash must not exceed).
- `pow_input`: the exact bytes to hash, see below.
- `equihash`: `n`, `k`, `personalization` (hex of the eight-byte
  prefix), `solution_length` in bytes.
- `transaction_count`, `coinbase_value`, `fees`, `longpollid`.

The first call builds and proves the coinbase, about a second; the same
template is handed back for five seconds after, then rebuilt. Ask again
whenever the tip changes. To be told when it changes, pass the
`longpollid` you were given; the call then waits up to a minute for a
new tip before answering with a fresh template:

```
rpc getblocktemplate '["tnull1...", "<longpollid>"]'
```

## 4. What to hash

Everything a miner grinds is fixed by `pow_input`, which is the header
serialized without its proof-of-work fields, in this order:

| Field | Bytes | Encoding |
|---|---|---|
| version | 1 | |
| previous block hash | 32 | as given |
| height | 4 | little-endian |
| timestamp | 8 | little-endian seconds |
| commitment root | 32 | as given |
| transaction root | 32 | as given |
| target | 4 | little-endian compact form |

Then the 32-byte nonce and the solution. Rebuild the input from the
fields yourself and check it equals `pow_input` before grinding; the
integration test does exactly that, and it catches serialization slips
before they cost you a block.

Equihash runs as Zcash's does, with one change: the BLAKE2b
personalization is the eight-byte prefix `nullPoW_` followed by `n` and
`k` as little-endian 32-bit integers, where Zcash uses `ZcashPoW`. The
hash input is `pow_input || nonce`. The solution is the same minimal
encoding Zcash uses, `solution_length` bytes long; the header field is
100 bytes, and the node zero-pads a shorter solution.

The block hash is `BLAKE2b-256` with personalization `null_BlockHash__`
over the full header (`pow_input || nonce || solution` with the solution
padded to 100 bytes), and it must be at or below `target_hex`, compared
as a big-endian 256-bit integer.

If you change the timestamp, stay between `min_timestamp` and
`max_timestamp`, and remember that it is part of `pow_input`, so shares
are only valid for the timestamp they were hashed with.

## 5. Submit

```
rpc submitblock '["<template_id>", <timestamp>, "<nonce hex>", "<solution hex>"]'
{"status":"accepted","hash":"..."}
```

`accepted` means the block is on the main chain. `duplicate` means the
node already had it. `stale` means it was valid but a competing block
won; you get this when you submit against a template whose tip has
moved. An invalid block is error code -2 with the validator's reason,
such as `hash does not meet the target`, and the template stays usable
for another try.

Pools that assemble their own blocks can submit the full block as hex
instead: `submitblock '["<block hex>"]'`. Get the transactions from a
template's `getblock` equivalent only if you need them; the template id
path is simpler and is what the built-in miner's code path does.

## 6. Shares and Stratum

Stratum is your side. Give miners the template's header fields and a
share target easier than the block target, validate shares against
`pow_input` with your own Equihash verifier using the personalization
above, and submit any share that also meets the block target. The
32-byte nonce is large enough to partition among miners however you
like. Nothing in the header is per-miner, so one template serves every
connected miner until the tip moves.

## 7. Paying miners

Run the wallet daemon on the pool wallet and batch payouts:

```
null-wallet-rpc --wallet /srv/pool/pool.redb --network test \
    --node 127.0.0.1:18444 --node-token-file /var/lib/null/rpc.token
W=$(cat /srv/pool/wallet-rpc.token)
wrpc() { curl -s -H "Authorization: Bearer $W" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" http://127.0.0.1:18447/; }
wrpc sendmany '[[{"address":"tnull1...","amount":"120000000"}, ...up to 15...], 100]'
wrpc getoperationstatus '[<operation_id>]'
```

The second `sendmany` parameter is the minimum confirmations a note
needs before it is spent; block rewards are notes like any other, so
this is your payout maturity policy. The network refuses
reorganizations deeper than 200 blocks, so 200 is safe against anything
it will accept; pools pick their own smaller number. The fee is fixed by
action class: fifteen recipients plus change is sixteen actions,
160,000 units, so batching is where the savings are. Operations persist
and rebuild themselves if a transaction is not mined; see the exchange
guide for the lifecycle.

## 8. Test drive on one machine

Start a node without a miner and a wallet, then run the four calls in
order: `getmininginfo`, `getblocktemplate`, grind, `submitblock`. The
test network's Equihash is `(48, 5)` and the target is trivial, so a
naive solver finds a solution in milliseconds. `crates/node/tests/mining.rs`
is a complete pool in miniature: template, header rebuild and check,
grind, submit by id, submit a full block, a duplicate, a stale rival,
and a long poll. Reading it once is the fastest way to see every field
in use.
