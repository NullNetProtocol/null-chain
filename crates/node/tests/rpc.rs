//! JSON-RPC over HTTP against a live mining node: auth, every chain
//! method, transaction submission and status, batches and error codes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use null_circuit::proof::ProvingKey;
use null_crypto::encoding::{from_hex, to_hex};
use null_crypto::keys::SpendingKey;
use null_node::config::{Config, Network};
use null_node::jsonrpc::{
    INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, NOT_FOUND, PARSE_ERROR,
};
use null_node::node::{spawn, Handle, Request, Response};
use null_node::rpc::Token;
use null_protocol::amount::Amount;
use null_protocol::block::Block;
use null_protocol::bytes::Encodable;
use null_protocol::memo::Memo;
use null_wallet::keys::WalletKeys;
use null_wallet::spend::{build_payment, Payment};
use null_wallet::wallet::Wallet;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// One raw HTTP POST; returns the status line and the JSON body.
async fn post(addr: SocketAddr, token: Option<&str>, body: &str) -> (String, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let request = format!(
        "POST / HTTP/1.1\r\nHost: node\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_string();
    (status, serde_json::from_str(body).unwrap())
}

/// A single call; returns the `result` or panics with the error.
async fn call(addr: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let (status, reply) = post(addr, Some(token), &body.to_string()).await;
    assert_eq!(status, "HTTP/1.1 200 OK", "{method}: {reply}");
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 1);
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

/// A single call expected to fail; returns the error code.
async fn call_err(addr: SocketAddr, token: &str, method: &str, params: Value) -> i64 {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 2});
    let (_, reply) = post(addr, Some(token), &body.to_string()).await;
    assert!(reply["result"].is_null(), "{method}: {reply}");
    reply["error"]["code"].as_i64().unwrap()
}

async fn height(handle: &Handle) -> u32 {
    match handle.request(Request::Status).await.unwrap() {
        Response::Status { height, .. } => height,
        other => panic!("unexpected {other:?}"),
    }
}

async fn wait_for(deadline: Duration, mut check: impl AsyncFnMut() -> bool) {
    let started = Instant::now();
    while !check().await {
        assert!(started.elapsed() < deadline, "timed out");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// One node spawn (verifying key, prover, mining) serves every assertion;
// splitting it would multiply the test time, not the coverage.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_rpc_serves_the_chain_and_accepts_transactions() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let miner_sk = SpendingKey::random(&mut rng);
    let miner_keys = WalletKeys::from_spending_key(miner_sk.clone()).unwrap();
    let receiver = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let token = Token::new("hunter2").unwrap();
    let node = spawn(Config {
        network: Network::Test,
        datadir: None,
        listen: None,
        connect: Vec::new(),
        proxy: None,
        i2p: None,
        mine_to: Some(miner_keys.default_address().unwrap()),
        mining_threads: 1,
        rpc: None,
        rpc_http: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: Some(token.clone()),
        block_notify: None,
        metrics: None,
        max_inbound: 125,
    })
    .await
    .unwrap();
    let addr = node.rpc_http_addr.unwrap();
    let t = token.expose();
    wait_for(Duration::from_secs(120), async || height(&node).await >= 2).await;

    // Auth and transport errors.
    let ping = json!({"jsonrpc": "2.0", "method": "getblockcount", "id": 1}).to_string();
    assert_eq!(post(addr, None, &ping).await.0, "HTTP/1.1 401 Unauthorized");
    assert_eq!(
        post(addr, Some("wrong"), &ping).await.0,
        "HTTP/1.1 401 Unauthorized"
    );
    let (status, reply) = post(addr, Some(t), "{not json").await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(reply["error"]["code"], PARSE_ERROR);
    let (_, reply) = post(addr, Some(t), r#"{"method": "getblockcount"}"#).await;
    assert_eq!(reply["error"]["code"], INVALID_REQUEST);
    assert_eq!(
        call_err(addr, t, "dance", json!([])).await,
        METHOD_NOT_FOUND
    );
    assert_eq!(
        call_err(addr, t, "getblockhash", json!(["x"])).await,
        INVALID_PARAMS
    );
    assert_eq!(
        call_err(addr, t, "getblockhash", json!([])).await,
        INVALID_PARAMS
    );

    // Chain state.
    let count = call(addr, t, "getblockcount", json!([]))
        .await
        .as_u64()
        .unwrap();
    assert!(count >= 2);
    let best = call(addr, t, "getbestblockhash", json!([])).await;
    let tip_hash = call(addr, t, "getblockhash", json!([count])).await;
    assert_eq!(best, tip_hash);
    assert_eq!(
        call_err(addr, t, "getblockhash", json!([count + 1_000])).await,
        NOT_FOUND
    );
    let genesis_hash = call(addr, t, "getblockhash", json!({"height": 0})).await;
    let info = call(addr, t, "getblockchaininfo", json!([])).await;
    assert_eq!(info["network"], "test");
    assert_eq!(info["genesis_hash"], genesis_hash);
    assert_eq!(info["fee_per_action"], "10000");
    assert_eq!(info["branch"], "0x54455354");
    assert_eq!(info["proof_lengths"]["2"], 8736);
    assert_eq!(info["coinbase_maturity"], 0);

    // Blocks by height and hash, at every verbosity.
    let hex = call(addr, t, "getblock", json!([1, 0])).await;
    let block_1 = Block::from_slice(&from_hex(hex.as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(block_1.header().height, 1);
    let by_hash = call(addr, t, "getblock", json!([block_1.hash().to_string()])).await;
    assert_eq!(by_hash["height"], 1);
    assert_eq!(by_hash["in_main_chain"], true);
    assert_eq!(by_hash["previousblockhash"], genesis_hash);
    assert_eq!(
        by_hash["nextblockhash"],
        call(addr, t, "getblockhash", json!([2])).await
    );
    assert!(by_hash["confirmations"].as_i64().unwrap() >= 2);
    assert_eq!(
        by_hash["tx"][0],
        block_1.transactions()[0].txid().to_string()
    );
    let decoded = call(addr, t, "getblock", json!([1, 2])).await;
    assert_eq!(decoded["tx"][0]["action_count"], 2);
    assert_eq!(decoded["tx"][0]["height"], 1);
    assert_eq!(decoded["tx"][0]["fee"], "20000");
    let header = call(addr, t, "getblockheader", json!([1])).await;
    assert!(header.get("tx").is_none());
    assert_eq!(header["hash"], block_1.hash().to_string());
    assert_eq!(header["target"].as_str().unwrap().len(), 8);
    assert_eq!(header["target_hex"].as_str().unwrap().len(), 64);
    assert_eq!(
        call_err(addr, t, "getblock", json!([&"00".repeat(32)])).await,
        NOT_FOUND
    );
    let compact = call(addr, t, "getcompactblock", json!([1])).await;
    assert!(compact.as_str().unwrap().len() > 100);

    // Transactions by id.
    let coinbase = block_1.transactions()[0].clone();
    let coinbase_id = coinbase.txid().to_string();
    let raw = call(addr, t, "getrawtransaction", json!([coinbase_id])).await;
    assert_eq!(raw, to_hex(&coinbase.to_vec()));
    let verbose = call(addr, t, "getrawtransaction", json!([coinbase_id, true])).await;
    assert_eq!(verbose["height"], 1);
    assert_eq!(verbose["index"], 0);
    assert_eq!(verbose["actions"].as_array().unwrap().len(), 2);
    let status = call(addr, t, "gettransactionstatus", json!([coinbase_id])).await;
    assert_eq!(status["status"], "confirmed");
    assert_eq!(status["height"], 1);
    let unknown = "11".repeat(32);
    assert_eq!(
        call(addr, t, "gettransactionstatus", json!([unknown])).await["status"],
        "unknown"
    );
    assert_eq!(
        call_err(addr, t, "getrawtransaction", json!([unknown])).await,
        NOT_FOUND
    );
    // Every nullifier enters the set when its block applies, dummies of a
    // coinbase included; only one never seen is unspent.
    let nullifier = to_hex(&coinbase.actions()[0].body().nullifier().to_bytes());
    assert_eq!(
        call(addr, t, "getnullifierstatus", json!([nullifier])).await["spent"],
        true
    );
    assert_eq!(
        call(addr, t, "getnullifierstatus", json!(["00".repeat(32)])).await["spent"],
        false
    );

    // Submit a payment and follow it from the pool into a block.
    let genesis = match node.request(Request::Block(0)).await.unwrap() {
        Response::Block(Some(block)) => block,
        other => panic!("{other:?}"),
    };
    let wallet = Wallet::in_memory(&miner_sk, genesis.hash(), &mut rng).unwrap();
    let scanned_to = height(&node).await;
    for h in 0..=scanned_to {
        let Response::Block(Some(block)) = node.request(Request::Block(h)).await.unwrap() else {
            panic!("block {h}")
        };
        wallet.scan(&block).unwrap();
    }
    let pk = ProvingKey::build().unwrap();
    let payment = Payment {
        recipient: receiver.default_address().unwrap(),
        amount: Amount::from_raw(1_000).unwrap(),
        memo: Memo::empty(),
    };
    let branch = Network::Test.params().genesis_branch;
    let tx = build_payment(&wallet, payment, &pk, branch, &mut rng).unwrap();
    let txid = tx.txid().to_string();
    let submitted = call(addr, t, "sendrawtransaction", json!([to_hex(&tx.to_vec())])).await;
    assert_eq!(submitted, txid);
    let pooled = call(addr, t, "getrawmempool", json!([])).await;
    let pooled_status =
        call(addr, t, "gettransactionstatus", json!([txid])).await["status"].clone();
    assert!(
        pooled.as_array().unwrap().contains(&json!(txid)) || pooled_status == "confirmed",
        "{pooled} {pooled_status}"
    );
    assert!(
        call(addr, t, "getmempoolinfo", json!([])).await["capacity"]
            .as_u64()
            .unwrap()
            > 0
    );
    // Resubmitting is idempotent while pooled and refused once mined.
    let again = json!({"jsonrpc": "2.0", "method": "sendrawtransaction",
        "params": [to_hex(&tx.to_vec())], "id": 3});
    let (_, reply) = post(addr, Some(t), &again.to_string()).await;
    assert!(
        reply["result"] == json!(txid) || reply["error"]["code"].is_i64(),
        "{reply}"
    );
    wait_for(Duration::from_secs(120), async || {
        call(addr, t, "gettransactionstatus", json!([txid])).await["status"] == "confirmed"
    })
    .await;
    let mined = call(addr, t, "getrawtransaction", json!([txid, true])).await;
    assert!(mined["confirmations"].as_i64().unwrap() >= 1);
    assert_eq!(
        call(
            addr,
            t,
            "getnullifierstatus",
            json!([to_hex(&tx.actions()[0].body().nullifier().to_bytes())])
        )
        .await["spent"],
        true
    );

    // Network and operations.
    assert_eq!(call(addr, t, "getpeerinfo", json!([])).await, json!([]));
    assert_eq!(call(addr, t, "getconnectioncount", json!([])).await, 0);
    let network = call(addr, t, "getnetworkinfo", json!([])).await;
    assert_eq!(network["connections"], 0);
    assert_eq!(network["network"], "test");
    assert!(call(addr, t, "uptime", json!([])).await.as_u64().is_some());
    assert!(
        call(addr, t, "help", json!([]))
            .await
            .as_array()
            .unwrap()
            .len()
            > 10
    );

    // A batch keeps order and isolates errors.
    let batch = json!([
        {"jsonrpc": "2.0", "method": "getblockcount", "id": "a"},
        {"jsonrpc": "2.0", "method": "dance", "id": "b"},
        {"jsonrpc": "2.0", "method": "getblockhash", "params": {"height": 0}, "id": "c"},
    ]);
    let (_, replies) = post(addr, Some(t), &batch.to_string()).await;
    let replies = replies.as_array().unwrap();
    assert_eq!(replies[0]["id"], "a");
    assert!(replies[0]["result"].as_u64().unwrap() >= 2);
    assert_eq!(replies[1]["error"]["code"], METHOD_NOT_FOUND);
    assert_eq!(replies[2]["result"], genesis_hash);
    let (_, empty) = post(addr, Some(t), "[]").await;
    assert_eq!(empty["error"]["code"], INVALID_REQUEST);

    // Stop ends the loop.
    assert_eq!(call(addr, t, "stop", json!([])).await, "stopping");
    wait_for(Duration::from_secs(10), async || {
        node.request(Request::Status).await.is_err()
    })
    .await;
    node.shutdown().await;
}
