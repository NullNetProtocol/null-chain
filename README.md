# Null network

A shielded-only privacy cryptocurrency written from scratch in Rust.
Anonymity first, performance second, nothing transparent. Ticker `NULL`;
addresses start with `null1` (`tnull1` on the test network); the node is
`nulld` and the wallet daemon `null-wallet-rpc`.

Status: a working local testnet. Nodes mine, sync, relay transactions
over encrypted connections with Dandelion++, and a command line wallet
scans balances and sends payments. Every transaction is a zero-knowledge
proof over a Halo2 circuit; there are no transparent addresses.

The roadmap is in [`TODO.md`](TODO.md), engineering rules in
[`CLAUDE.md`](CLAUDE.md), design decisions in
[`docs/decisions.md`](docs/decisions.md), the protocol in
[`docs/protocol.md`](docs/protocol.md), the circuit statement in
[`docs/circuit.md`](docs/circuit.md), the threat model in
[`docs/threat-model.md`](docs/threat-model.md), the parameters in
[`docs/params.md`](docs/params.md), the upgrade procedure in
[`docs/upgrades.md`](docs/upgrades.md), the JSON-RPC reference in
[`docs/rpc.md`](docs/rpc.md) with the exchange and pool walk-throughs in
[`docs/guide-exchange.md`](docs/guide-exchange.md) and
[`docs/guide-pool.md`](docs/guide-pool.md), and measured numbers in
[`docs/perf.md`](docs/perf.md).

## Build and test

```
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

A `Makefile` wraps the common commands: `make build`, `make test`,
`make release`, `make run ARGS="--network test --mine <ADDR>"`, and
`make check` (fmt-check + clippy + test, the pre-commit gate). `make help`
lists them.

`scripts/testnet.sh` runs two nodes, a payment and the faucet on one
machine and prints PASS or FAIL. `scripts/testnet-docker.sh` does the
same with six containers: two miners, two followers, a faucet and a
trader; see `deploy/testnet/docker-compose.yml`.

## Platforms and data directories

`nulld`, `null-wallet-rpc`, and `null-desktop` build and run on Linux,
macOS, and Windows, and CI tests all three. With no path flags they share
one per-user data directory:

| OS      | Data directory                                        |
|---------|-------------------------------------------------------|
| Linux   | `$XDG_DATA_HOME/null`, else `~/.local/share/null`     |
| macOS   | `~/Library/Application Support/Null`                  |
| Windows | `%LOCALAPPDATA%\Null`, else `%APPDATA%\Null`          |

Inside it, each network has its own directory: `<network>/chain/` holds
the node's `chain.redb` and `rpc.token`, and `<network>/wallet.redb` is the
default wallet. So `nulld run` uses the same chain as the desktop app, and
`null-wallet-rpc` finds the desktop wallet and the node token by itself.
Only one process can open a database at a time. `nulld run --datadir <dir>`
points the node elsewhere, and `--in-memory` keeps the chain in memory.
`null-wallet-rpc --wallet <file> --node-token-file <file>` overrides its
defaults. Both daemons stop gracefully on Ctrl-C, `SIGTERM`, and Windows
console close, logoff, and shutdown events.

On Unix, new directories are owner-only (`0700`) and token files `0600`.
On Windows, files inherit the directory's access list; the defaults under
`%LOCALAPPDATA%` are private to the user. If you pass a `--datadir`
elsewhere on Windows, choose a folder other users cannot read. The
`Makefile`, `scripts/`, and `deploy/` helpers are Unix shell; on Windows,
run the `cargo` commands directly.

## Run a local testnet

The native desktop scaffold runs the full node, wallet, and authenticated
JSON-RPC server in one process:

```
cargo run --release -p null-desktop -- --network test --connect 127.0.0.1:19000
```

First launch creates the application data directory and `null.conf`, then
offers to generate a recovery phrase or import one. Later launches find the
wallet automatically and ask for its passphrase. No wallet-file selection is
needed. It includes balances, receiving addresses, payments, activity, and
node status. See [`docs/desktop.md`](docs/desktop.md)
for configuration, RPC access, architecture, and remaining desktop work.

The `test` network uses a tiny proof of work so blocks mine in a few
seconds on one machine. Everything below runs on localhost.

Create an encrypted wallet for the miner and one for a friend. The
passphrase is prompted, or taken from `NULL_WALLET_PASSPHRASE`. Each
wallet prints a 24-word seed phrase once; write it down, it restores the
wallet anywhere with `create --phrase`, which reads the phrase from
`NULL_SEED_PHRASE` or a hidden prompt:

```
./target/release/nulld create --wallet miner.wallet --network test
./target/release/nulld create --wallet friend.wallet --network test
./target/release/nulld create --wallet restored.wallet --network test --phrase
```

Start a mining node with the address that `create` printed, then a
second node that connects to it:

```
./target/release/nulld run --network test --listen 127.0.0.1:19000 \
    --mine <MINER_ADDRESS> --rpc 127.0.0.1:18444 --datadir /tmp/null-miner

./target/release/nulld run --network test --connect 127.0.0.1:19000 \
    --rpc 127.0.0.1:18445 --datadir /tmp/null-follower
```

To reach peers over Tor, add `--proxy 127.0.0.1:9050`; every outbound
connection then goes through the SOCKS5 proxy and `.onion` names work in
`--connect`. For I2P, add `--i2p 127.0.0.1:7656` to reach `.i2p` peers
through a router's SAM bridge. Seed lists are empty until a public
network exists, so pass `--connect` or `--seed`.

Each node logs with a level and a timestamp — `21:17:47 INFO  mined block 1 …` —
colored when the output is a terminal (set `NO_COLOR` or pipe it to disable);
`--log-level debug|info|warn|error` sets the threshold. `--metrics 127.0.0.1:9100` serves
Prometheus metrics at `/metrics`: height, peers, mempool, blocks mined
against blocks still in the chain, and uptime. The status line carries
the same mined and in-chain counts. The control socket speaks one
command per line and demands the node's token first. The node writes
the token to `rpc.token` in its data directory; commands take it with
`--rpc-token-file`, `--rpc-token` or `NULL_RPC_TOKEN`:

```
printf 'auth %s\nstatus\n' "$(cat /tmp/null-follower/rpc.token)" | nc 127.0.0.1 18445
./target/release/nulld status --rpc 127.0.0.1:18445 \
    --rpc-token-file /tmp/null-follower/rpc.token
```

`--rpc-http 127.0.0.1:18446` adds JSON-RPC 2.0 over HTTP behind the same
token, which is what exchanges, pools and explorers integrate against;
[`docs/rpc.md`](docs/rpc.md) lists the methods, and `null-wallet-rpc`
is the wallet daemon that serves deposits and withdrawals over the same
kind of interface:

```
curl -s -H "Authorization: Bearer $(cat /tmp/null-follower/rpc.token)" \
    -d '{"jsonrpc":"2.0","method":"getblockchaininfo","id":1}' http://127.0.0.1:18446/
```

Check the miner's balance and pay the friend through the follower:

```
./target/release/nulld balance --wallet miner.wallet \
    --rpc 127.0.0.1:18444 --rpc-token-file /tmp/null-miner/rpc.token
./target/release/nulld send --wallet miner.wallet --to <FRIEND_ADDRESS> \
    --amount 123456 --rpc 127.0.0.1:18445 --rpc-token-file /tmp/null-follower/rpc.token
```

A wallet file holds the spending key and the notes encrypted under the
passphrase, and keeps a pruned witness tree and scan state so only new
blocks are scanned; it rolls back on its own if the node's chain
reorganized. `--sk <HEX>` instead of `--wallet` scans from genesis in
memory with a key from `keygen`.

`balance` and `send` take `--light` to scan compact blocks instead of
full ones: the node sends only the nullifier, commitment, ephemeral key
and a short ciphertext lead per action, the wallet detects its notes from
the lead and builds the same witness tree, and memos are not recovered.

Add `--mining-threads <N>` to mine on N cores; each worker mines from a
random nonce so their throughput adds up. On mainnet, where single-
threaded Equihash solving dominates, this scales nearly linearly.

Amounts are in smallest units; one coin is 100 000 000 units and the
block subsidy starts at ten coins. Building a payment generates the
proving key and proves the transaction, which takes a couple of seconds.

A faucet that pays a fixed amount to any address, rate-limited, is
`nulld faucet`; see `deploy/README.md` for it, for seed nodes, for Tor
and for the control token on a public host.

The control socket is bound to localhost by default. The token keeps
other local users out; it is not a reason to expose the socket.
