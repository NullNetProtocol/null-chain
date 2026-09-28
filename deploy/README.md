# Running public infrastructure

## A seed node

1. Build with the Dockerfile at the repository root, or `cargo build
   --release --locked`. Compare `sha256sum target/release/nulld` with
   another builder before trusting a binary.
2. Install `nulld.service`, create the `null` user and `/var/lib/null`,
   and open port 19000.
3. Add the node's `host:19000` to the seed list in
   `crates/node/src/config.rs` for the network, or hand it to users for
   `--seed`.

## Over Tor

Install Tor with `torrc.example`, start the node with
`--proxy 127.0.0.1:9050`, and publish `<onion hostname>:19000`.

## Over I2P

Run an I2P router with the SAM bridge enabled and start the node with
`--i2p 127.0.0.1:7656`. It opens a transient session and reaches `.i2p`
peers passed to `--connect` or `--seed`. Inbound I2P service is not yet
supported.

## The control socket

`nulld run` generates a token and writes it to `rpc.token` in the data
directory, readable by the owner only, or takes one with `--rpc-token`
or `NULL_RPC_TOKEN`. Every client command needs it: `--rpc-token-file
/var/lib/null/rpc.token`, `--rpc-token <TOKEN>` or `NULL_RPC_TOKEN`.
Keep the socket on localhost regardless; the token stops other local
users, not the network.

## A faucet

Create a wallet, fund it from a miner, then:

```
NULL_WALLET_PASSPHRASE=... nulld faucet --wallet faucet.redb \
    --rpc 127.0.0.1:18444 --rpc-token-file /var/lib/null/rpc.token \
    --listen 127.0.0.1:8080 --amount 100000000
```

Put a reverse proxy with TLS in front of it. It pays each address once
an hour and each client once every ten minutes.
