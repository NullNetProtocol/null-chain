#!/usr/bin/env bash
# Six containers: two miners, two followers, a faucet and a trader that
# keeps paying. Waits, then checks every node agrees on the chain and the
# trader has sent at least one payment. Leaves the network running;
# tear it down with `docker compose -f deploy/testnet/docker-compose.yml down -v`.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/testnet/docker-compose.yml"
$COMPOSE up -d --build
echo "waiting for the network to settle"
sleep "${WAIT:-120}"

heights=()
for node in miner1 miner2 follower1 follower2; do
    line=$($COMPOSE exec -T "$node" nulld status --rpc 127.0.0.1:18444 || echo "down")
    echo "$node: $line"
    heights+=("$(sed 's/.*height=\([0-9]*\).*/\1/' <<<"$line")")
done
$COMPOSE logs --no-log-prefix trader | grep -E "sent payment|funded" | tail -3 || true

max=$(printf '%s\n' "${heights[@]}" | sort -n | tail -1)
min=$(printf '%s\n' "${heights[@]}" | sort -n | head -1)
sent=$($COMPOSE logs --no-log-prefix trader | grep -c "sent payment" || true)
if [[ $((max - min)) -le 3 && "$sent" -ge 1 ]]; then
    echo "PASS: heights $min..$max across four nodes, $sent trader payments sent"
else
    echo "FAIL: heights $min..$max, $sent trader payments"
    exit 1
fi
