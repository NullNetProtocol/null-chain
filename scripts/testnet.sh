#!/usr/bin/env bash
# End-to-end check on one machine: two nodes, encrypted wallets, a
# payment, and the faucet. Prints PASS or FAIL at the end.
#
#   scripts/testnet.sh            # builds release, runs for ~40 s
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release -p null-node
B=./target/release/nulld
S=$(mktemp -d)
export NULL_WALLET_PASSPHRASE=testnet
trap 'pkill -P $$ >/dev/null 2>&1 || true' EXIT

MINER_ADDR=$($B create --wallet "$S/miner.wallet" --network test | awk '/address/ {print $2}')
FRIEND_ADDR=$($B create --wallet "$S/friend.wallet" --network test | awk '/address/ {print $2}')

$B run --network test --listen 127.0.0.1:19000 --mine "$MINER_ADDR" \
    --rpc 127.0.0.1:18444 --datadir "$S/miner" > "$S/miner.log" 2>&1 &
sleep 3
$B run --network test --connect 127.0.0.1:19000 \
    --rpc 127.0.0.1:18445 --datadir "$S/follower" > "$S/follower.log" 2>&1 &
sleep 12

# Each node wrote its control token to its data directory; the raw socket
# wants it on the first line, the commands take it as a file.
MINER_RPC=(--rpc 127.0.0.1:18444 --rpc-token-file "$S/miner/rpc.token")
FOLLOWER_RPC=(--rpc 127.0.0.1:18445 --rpc-token-file "$S/follower/rpc.token")
status() { printf 'auth %s\nstatus\n' "$(cat "$3")" | timeout 3 nc "$1" "$2" | tail -1; }
echo "miner:    $(status 127.0.0.1 18444 "$S/miner/rpc.token")"
echo "follower: $(status 127.0.0.1 18445 "$S/follower/rpc.token")"
if printf 'status\n' | timeout 3 nc 127.0.0.1 18444 | grep -q unauthorized; then
    echo "control socket refuses requests without the token"
else
    echo "FAIL: control socket answered without a token"
    exit 1
fi

BEFORE=$($B balance --wallet "$S/miner.wallet" "${MINER_RPC[@]}" | tail -1)
echo "miner balance: $BEFORE"
$B send --wallet "$S/miner.wallet" --to "$FRIEND_ADDR" --amount 123456 "${FOLLOWER_RPC[@]}"
sleep 8
AFTER=$($B balance --wallet "$S/friend.wallet" "${MINER_RPC[@]}" | tail -1)
echo "friend balance: $AFTER"

$B faucet --wallet "$S/miner.wallet" "${MINER_RPC[@]}" \
    --listen 127.0.0.1:18080 --amount 777 > "$S/faucet.log" 2>&1 &
sleep 4
FAUCET=$(curl -s "http://127.0.0.1:18080/pay/$FRIEND_ADDR")
echo "faucet: $FAUCET"

FOLLOWER_H=$(status 127.0.0.1 18445 "$S/follower/rpc.token" | sed 's/.*height=\([0-9]*\).*/\1/')
MINER_H=$(status 127.0.0.1 18444 "$S/miner/rpc.token" | sed 's/.*height=\([0-9]*\).*/\1/')
if [[ "$AFTER" == *"balance 123456"* && "$FAUCET" == paid* && "$FOLLOWER_H" -ge $((MINER_H - 2)) ]]; then
    echo "PASS: nodes in sync at height $MINER_H, payment and faucet delivered"
else
    echo "FAIL: see $S/miner.log and $S/follower.log"
    exit 1
fi
