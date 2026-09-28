#!/bin/sh
# Roles for the containerized testnet. Test only: spending keys come from
# the environment so every container knows every address, and every node
# uses the shared NULL_RPC_TOKEN so the clients below can reach it.
set -eu
export NULL_WALLET_PASSPHRASE=testnet
WALLET=/home/null/wallet.redb
RPC="${RPC:-0.0.0.0:18444}"

address_of() { nulld address --sk "$1"; }

case "$ROLE" in
  miner)
    # Mines to MINE_TO_SK's address, or to its own.
    TARGET=$(address_of "${MINE_TO_SK:-$SK}")
    exec nulld run --network test --listen 0.0.0.0:19000 --rpc "$RPC" \
        --rpc-token "$NULL_RPC_TOKEN" --datadir /home/null/data --mine "$TARGET" $CONNECT_ARGS
    ;;
  follower)
    exec nulld run --network test --listen 0.0.0.0:19000 --rpc "$RPC" \
        --rpc-token "$NULL_RPC_TOKEN" --datadir /home/null/data $CONNECT_ARGS
    ;;
  faucet)
    # Waits for its node, imports its key, serves payouts.
    until nulld status --rpc "$NODE_RPC" >/dev/null 2>&1; do sleep 2; done
    nulld create --wallet "$WALLET" --sk "$SK" --network test
    exec nulld faucet --wallet "$WALLET" --rpc "$NODE_RPC" --listen 0.0.0.0:8080 --amount 50000000
    ;;
  trader)
    # Asks the faucet for coins, then pays the miners in turn forever.
    until nulld status --rpc "$NODE_RPC" >/dev/null 2>&1; do sleep 2; done
    nulld create --wallet "$WALLET" --sk "$SK" --network test
    ME=$(address_of "$SK")
    until curl -sf "http://faucet:8080/pay/$ME"; do sleep 5; done
    echo "trader funded, waiting for the payout to be mined"
    sleep 20
    i=0
    while true; do
      for target_sk in $TARGET_SKS; do
        i=$((i + 1))
        TARGET=$(address_of "$target_sk")
        if nulld send --wallet "$WALLET" --to "$TARGET" --amount $((1000 + i)) --rpc "$NODE_RPC"; then
          echo "sent payment $i to $TARGET"
        else
          echo "payment $i not sent yet"
        fi
        sleep 15
      done
    done
    ;;
  *)
    echo "unknown ROLE $ROLE" >&2
    exit 1
    ;;
esac
