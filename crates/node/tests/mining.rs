//! What a mining pool does: fetch a template, grind the header it
//! describes, submit the solution by template id or as a full block,
//! and long-poll for the next tip.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::time::Duration;

use null_chain::pow::EquihashPow;
use null_crypto::encoding::{from_hex, to_hex};
use null_crypto::keys::SpendingKey;
use null_node::config::{Config, Network};
use null_node::jsonrpc::REJECTED;
use null_node::node::spawn;
use null_node::rpc::Token;
use null_protocol::block::{Block, BlockHash, BlockHeader, PowSolution};
use null_protocol::bytes::Encodable;
use null_protocol::transaction::Anchor;
use null_wallet::keys::WalletKeys;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn post(addr: SocketAddr, token: &str, body: &str) -> Value {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

async fn call(addr: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let reply = post(addr, token, &body.to_string()).await;
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

async fn call_err(addr: SocketAddr, token: &str, method: &str, params: Value) -> i64 {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let reply = post(addr, token, &body.to_string()).await;
    assert!(reply["result"].is_null(), "{method}: {reply}");
    reply["error"]["code"].as_i64().unwrap()
}

/// The header a pool rebuilds from a template, before grinding.
fn header_from(template: &Value) -> BlockHeader {
    let hex = |key: &str| from_hex(template[key].as_str().unwrap()).unwrap();
    BlockHeader {
        version: u8::try_from(template["version"].as_u64().unwrap()).unwrap(),
        prev_hash: BlockHash::from_bytes(hex("prev_hash").try_into().unwrap()),
        height: u32::try_from(template["height"].as_u64().unwrap()).unwrap(),
        timestamp: template["timestamp"].as_u64().unwrap(),
        commitment_root: Anchor::from_slice(&hex("commitment_root")).unwrap(),
        tx_root: hex("tx_root").try_into().unwrap(),
        target: u32::from_str_radix(template["target"].as_str().unwrap(), 16).unwrap(),
        nonce: [0; 32],
        solution: PowSolution::empty(),
    }
}

/// Grinds `header` until it meets its target.
fn solve(header: &mut BlockHeader, rng: &mut ChaCha20Rng) {
    let pow = EquihashPow::new(Network::Test.params().equihash);
    assert!(pow.mine(header, 4096, rng).unwrap(), "test network puzzle");
}

fn submission(header: &BlockHeader, template_id: &str) -> Value {
    json!([
        template_id,
        header.timestamp,
        to_hex(&header.nonce),
        to_hex(header.solution.as_bytes()),
    ])
}

// One node spawn (verifying key, prover) serves every assertion; the
// steps also build on each other's chain state.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_mines_through_templates_and_submissions() {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let payout = keys
        .default_address()
        .unwrap()
        .encode(Network::Test.address_prefix());
    let token = Token::new("pool").unwrap();
    let node = spawn(Config {
        rpc_http: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: Some(token.clone()),
        ..Config::test()
    })
    .await
    .unwrap();
    let addr = node.rpc_http_addr.unwrap();
    let t = token.expose();

    let info = call(addr, t, "getmininginfo", json!([])).await;
    assert_eq!(info["height"], 0);
    assert_eq!(info["syncing"], false);
    assert_eq!(info["next_height"], 1);
    assert_eq!(
        info["subsidy"], "950000000",
        "9.5 coins after the premine carve-out"
    );
    assert_eq!(info["equihash"]["n"], 48);
    assert_eq!(info["next_target"].as_str().unwrap().len(), 8);

    // A template, reused while fresh.
    let template = call(addr, t, "getblocktemplate", json!([payout])).await;
    assert_eq!(template["height"], 1);
    assert_eq!(template["transaction_count"], 1);
    assert_eq!(template["coinbase_value"], "950000000");
    assert_eq!(template["prev_hash"], info["best_block_hash"]);
    let again = call(
        addr,
        t,
        "getblocktemplate",
        json!({"payout_address": payout}),
    )
    .await;
    assert_eq!(again["template_id"], template["template_id"]);
    assert_eq!(
        call_err(addr, t, "getblocktemplate", json!(["tnull1nonsense"])).await,
        null_node::jsonrpc::INVALID_PARAMS
    );

    // The pool rebuilds the header, checks it hashes the bytes the node
    // said, grinds it, and submits by template id.
    let mut header = header_from(&template);
    assert_eq!(to_hex(&header.pow_input()), template["pow_input"]);
    let id = template["template_id"].as_str().unwrap();
    // An unsolved header is refused, and refusal does not consume the template.
    assert_eq!(
        call_err(addr, t, "submitblock", submission(&header, id)).await,
        REJECTED
    );
    solve(&mut header, &mut rng);
    let accepted = call(addr, t, "submitblock", submission(&header, id)).await;
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["hash"], header.hash().to_string());
    assert_eq!(call(addr, t, "getblockcount", json!([])).await, 1);
    assert_eq!(
        call(addr, t, "submitblock", submission(&header, id)).await["status"],
        "duplicate"
    );

    // Height 2 as a full block, with the template's transactions.
    let template_2 = call(addr, t, "getblocktemplate", json!([payout])).await;
    assert_eq!(template_2["height"], 2);
    let mut header_2 = header_from(&template_2);
    solve(&mut header_2, &mut rng);
    let id_2 = template_2["template_id"].as_str().unwrap();
    let accepted_2 = call(addr, t, "submitblock", submission(&header_2, id_2)).await;
    assert_eq!(accepted_2["status"], "accepted");
    let full = call(addr, t, "getblock", json!([2, 0])).await;
    let block_2 = Block::from_slice(&from_hex(full.as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(block_2.hash(), header_2.hash());
    // The same block again as raw hex is a duplicate, not an error.
    assert_eq!(
        call(addr, t, "submitblock", json!([to_hex(&block_2.to_vec())])).await["status"],
        "duplicate"
    );

    // A competing block at height 2 on the old template is stale.
    let mut rival = header_from(&template_2);
    rival.timestamp += 1;
    solve(&mut rival, &mut rng);
    let stale = call(addr, t, "submitblock", submission(&rival, id_2)).await;
    assert_eq!(stale["status"], "stale");
    assert_eq!(call(addr, t, "getblockcount", json!([])).await, 2);

    // Long polling: the call returns only once the tip moves.
    let tip = call(addr, t, "getbestblockhash", json!([])).await;
    let waiter = tokio::spawn({
        let payout = payout.clone();
        let tip = tip.clone();
        let token = t.to_string();
        async move { call(addr, &token, "getblocktemplate", json!([payout, tip])).await }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!waiter.is_finished(), "still waiting for a new tip");
    let template_3 = call(addr, t, "getblocktemplate", json!([payout])).await;
    let mut header_3 = header_from(&template_3);
    solve(&mut header_3, &mut rng);
    let id_3 = template_3["template_id"].as_str().unwrap();
    assert_eq!(
        call(addr, t, "submitblock", submission(&header_3, id_3)).await["status"],
        "accepted"
    );
    let released = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(released["height"], 4);
    assert_eq!(released["prev_hash"], header_3.hash().to_string());

    node.shutdown().await;
}
