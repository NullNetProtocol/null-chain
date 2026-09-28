# Exchange integration guide

How to run deposits and withdrawals for this coin, in the order you will
do them. `docs/rpc.md` is the method reference; this guide is the
walk-through. Every example below runs on one machine against the test
network; swap `--network test` for `main` and the `tnull1` prefixes for
`null1` when you go live.

## What is different, in one paragraph

There are no transparent addresses and no balances on chain. A deposit
is found by trial-decrypting outputs with your viewing key, which is
what the wallet daemon does for you. Every customer gets their own
deposit address, all derived from one key, so you never manage per-user
keys. Withdrawals take seconds to prove, so `sendmany` returns an
operation id and you poll it. Fees are fixed per action: one withdrawal
transaction pays up to fifteen customers, and the fee is the same
whether it carries one or fifteen.

## 1. Run a node

```
nulld run --network test --datadir /var/lib/null \
    --rpc 127.0.0.1:18444 --rpc-http 127.0.0.1:18446
```

`--rpc` is the control socket the wallet daemon syncs from; `--rpc-http`
is JSON-RPC for your own tooling. Both share the token the node writes
to `/var/lib/null/rpc.token`. Wait for it to sync:

```
TOKEN=$(cat /var/lib/null/rpc.token)
curl -s -H "Authorization: Bearer $TOKEN" -d \
  '{"jsonrpc":"2.0","method":"getblockchaininfo","id":1}' http://127.0.0.1:18446/
```

`syncing` false and `height` matching what other nodes report means you
are caught up. Keep `getblockchaininfo` in your monitoring: it also
carries `branch` and `upgrades`, which is how you will learn that a
network upgrade is scheduled.

## 2. Create the wallets

Two wallets: a hot wallet that holds the spending key and signs
withdrawals, and a watch-only wallet, made from the hot wallet's
exported viewing key, that detects deposits on a host that holds no
spending key.

```
export NULL_WALLET_PASSPHRASE='choose a long one'
nulld create --wallet /srv/hot/hot.redb --network test
# prints the seed phrase: write it down, it restores this wallet anywhere
nulld export-viewing-key --wallet /srv/hot/hot.redb --network test
# prints tnullview1...
nulld create --wallet /srv/deposits/watch.redb --viewing-key tnullview1... --network test
```

The viewing key sees every note and memo the hot wallet receives or
sends, and every spend. Treat it as confidential: it cannot move funds,
but it reveals your whole flow.

## 3. Run the daemons

```
null-wallet-rpc --wallet /srv/deposits/watch.redb --network test \
    --node 127.0.0.1:18444 --node-token-file /var/lib/null/rpc.token \
    --listen 127.0.0.1:18447
null-wallet-rpc --wallet /srv/hot/hot.redb --network test \
    --node 127.0.0.1:18444 --node-token-file /var/lib/null/rpc.token \
    --listen 127.0.0.1:18448
```

Each daemon generates its own token into `wallet-rpc.token` next to its
wallet file unless you pass `--token`. The passphrase comes from
`NULL_WALLET_PASSPHRASE` or a prompt. Both daemons sync every two
seconds. Check either one:

```
W=$(cat /srv/deposits/wallet-rpc.token)
rpc() { curl -s -H "Authorization: Bearer $W" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "http://127.0.0.1:$3/"; }
rpc getwalletinfo '[]' 18447
```

`synced` true means the wallet's scanned height equals the node's.
`last_error` is non-null when the node cannot be reached; alert on it.

## 4. Deposit addresses

Ask the watch-only daemon for one address per customer, labelled with
your customer id:

```
rpc getnewaddress '["customer-10042"]' 18447
{"index":1,"address":"tnull1...","label":"customer-10042"}
```

Store the address and the index with the customer. Every address is
valid forever, and a customer can reuse theirs; reuse costs nothing in
privacy on this chain, since addresses never appear on it. If you would
rather use one address and a memo per customer, that works too: memos
are 512 bytes and come back with every deposit. Per-customer addresses
are the more robust choice because customers forget memos.

`listaddresses` returns everything you have handed out; `getaddressinfo`
maps an address back to its label.

## 5. Detecting deposits

Poll the watch-only daemon:

```
rpc listreceived '[10, 1500]' 18447
```

The first parameter is the minimum confirmations, the second the height
to list from. Each entry has `txid`, `height`, `confirmations`,
`amount` (a decimal string in smallest units; 100,000,000 per coin),
`address_index`, `label`, `memo` and `spent`. Credit the customer named
by `label` once `confirmations` reaches your threshold, and remember the
`txid` plus `address_index` pair so you never credit the same note twice.

On confirmations: the network refuses reorganizations deeper than 200
blocks, so 200 is safe against anything the network will accept. Ten
blocks, twenty minutes, is a reasonable everyday threshold. If a block
is reorganized away, the wallet rolls back by itself and the note
disappears from `listreceived`; a deposit you credited at ten
confirmations will not disappear in practice, but your reconciliation
job should still re-list from a height a few hundred blocks back and
compare.

`gettransaction` with a txid shows your side of one transaction:

```
rpc gettransaction '["<txid>"]' 18447
```

## 6. Withdrawals

Send from the hot daemon. Batch up to fifteen customers per call:

```
H=$(cat /srv/hot/wallet-rpc.token); W=$H
rpc sendmany '[[{"address":"tnull1...","amount":"250000000","memo":"withdrawal 88231"},
                {"address":"tnull1...","amount":"1000000"}], 10]' 18448
{"operation_id":17,"status":"queued"}
```

The second parameter is the minimum confirmations a note must have to
be spent. Then poll:

```
rpc getoperationstatus '[17]' 18448
```

`status` goes `queued`, `proving`, `submitted` (now with a `txid`), then
`confirmed` (with `height` and `confirmations`). `failed` carries an
`error`, most often insufficient funds. Store the `txid` with the
withdrawal once `submitted`; it does not change on a rebuild unless the
anchor expires (see below), so read it again from the operation when
you mark the withdrawal complete.

What the daemon does for you, so you do not have to: the notes chosen
for an operation are locked so a later send cannot pick them; the
transaction is resubmitted every sync until its spend appears in a
block; if it is not mined within 100 blocks the anchor it proved against
expires and the operation is rebuilt with a fresh one, up to five times.
Operations persist in the wallet file, so a restart resumes them. Only
a `queued` operation can be cancelled, since a submitted one may still
be mined.

`estimatefee` tells you the fee for a given number of recipients:

```
rpc estimatefee '[2]' 18448
{"fee":"40000","actions":4}
```

The fee depends only on the action class the transaction lands in
(2, 4, 8 or 16 actions at 10,000 units each), so fifteen recipients cost
160,000 units in total. Change returns to the hot wallet's default
address automatically.

## 7. Balances and accounting

```
rpc getbalance '[10]' 18448
{"spendable":"...","locked":"...","pending":"...","total":"..."}
```

`spendable` has enough confirmations and is not set aside; `locked` is
set aside for pending operations; `pending` has too few confirmations.
`listunspent` lists the notes behind those numbers.

For a full audit of a transaction from the outside, have the sender
produce a payment disclosure:

```
rpc getpaymentdisclosure '["<txid>"]' 18448
```

Hand the `disclosure` string to whoever needs to verify it; any node
checks it with `verifypaymentdisclosure` and reports the address,
amount and memo it proves. This is how you settle "you never paid me"
without revealing anything else.

To prove a customer controls an address they gave you, encrypt a
message to it with the node's `createchallenge` and ask them to return
the message; only the address's owner can read it. A watch-only wallet
can answer, so an exchange can prove ownership of its own deposit
addresses to a counterparty the same way.

## 8. Backup, restore, keys

Back up the seed phrase printed at creation. A wallet file can be copied
while its daemon is stopped. To restore: `nulld create --phrase` with the
seed phrase, then run the daemon and let it scan from genesis, or call
`rescan` with a starting height. Address labels and operations live in
the wallet file, not in the seed, so keep a copy of the file too or
re-create labels from your database after a restore.

Never run the hot daemon on a host reachable from outside your network.
Its JSON-RPC has a token and no TLS; front it with your own proxy if it
must cross a network boundary. The watch-only daemon holds no spending
key, which is the point of running deposits on a separate host.

## 9. Test drive on one machine

`scripts/testnet.sh` starts a miner and a follower with wallets and a
faucet, and prints PASS. From there, point a `null-wallet-rpc` at the
follower's control socket with the miner's wallet file and run the
calls above; the miner's coinbase notes give you funds to send.
