//! The wallet daemon against a live mining node: sync, addresses with
//! labels, balances, a multi-recipient send carried from queued to
//! confirmed, transaction views, operations, and a watch-only wallet.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use null_chain::genesis::genesis;
use null_crypto::keys::SpendingKey;
use null_node::config::{Config, Network};
use null_node::jsonrpc::{NOT_FOUND, REJECTED};
use null_node::node::spawn;
use null_node::rpc::{Endpoint, Token};
use null_node::walletd;
use null_protocol::viewing_key::decode_full_viewing_key;
use null_wallet::keys::WalletKeys;
use null_wallet::wallet::Wallet;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn post(addr: SocketAddr, token: &str, body: &str) -> Value {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: wallet\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
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

async fn wait_for(deadline: Duration, mut check: impl AsyncFnMut() -> bool) {
    let started = Instant::now();
    while !check().await {
        assert!(started.elapsed() < deadline, "timed out");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// One node, one daemon and one proving key serve every assertion, and
// the steps build on each other's chain state.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wallet_daemon_serves_an_exchange() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let miner_sk = SpendingKey::random(&mut rng);
    let miner_keys = WalletKeys::from_spending_key(miner_sk.clone()).unwrap();
    let customer = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let node_token = Token::new("node").unwrap();
    let node = spawn(Config {
        mine_to: Some(miner_keys.default_address().unwrap()),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        rpc_http: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: Some(node_token.clone()),
        ..Config::test()
    })
    .await
    .unwrap();
    let node_rpc = node.rpc_http_addr.unwrap();
    let n = "node";
    let genesis_hash = genesis(&Network::Test.params()).hash();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exchange.redb");
    drop(Wallet::create(&path, &miner_sk, genesis_hash, b"pw", &mut rng).unwrap());
    let wallet = Wallet::open(&path, genesis_hash, b"pw").unwrap();
    let token = Token::new("wallet").unwrap();
    let daemon = walletd::run(walletd::Config {
        wallet,
        network: Network::Test,
        node: Endpoint {
            addr: node.rpc_addr.unwrap().to_string(),
            token: node_token,
        },
        listen: "127.0.0.1:0".parse().unwrap(),
        token: token.clone(),
        sync_interval: Duration::from_millis(500),
        light: false,
    })
    .await
    .unwrap();
    let addr = daemon.addr;
    let t = token.expose();
    let prefix = Network::Test.address_prefix();

    // It syncs and sees the coinbase notes once they mature: the rewards
    // of blocks 1 to 3 have entered the tree by block 12.
    let three_matured = u64::from(common::first_spendable_height() + 1);
    wait_for(Duration::from_secs(240), async || {
        let info = call(addr, t, "getwalletinfo", json!([])).await;
        info["scanned_height"]
            .as_u64()
            .is_some_and(|h| h >= three_matured)
    })
    .await;
    let info = call(addr, t, "getwalletinfo", json!([])).await;
    assert_eq!(info["network"], "test");
    assert_eq!(info["watch_only"], false);
    assert!(info["unspent"].as_u64().unwrap() >= 3);
    let balance = call(addr, t, "getbalance", json!([1])).await;
    assert!(
        balance["spendable"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 2_000_000_000
    );
    let unspent = call(addr, t, "listunspent", json!([])).await;
    assert_eq!(unspent[0]["address_index"], 0);
    assert!(unspent[0]["txid"].is_string());
    assert_eq!(unspent[0]["memo"], Value::Null);

    // Deposit addresses with labels.
    let alice = call(addr, t, "getnewaddress", json!(["alice"])).await;
    assert_eq!(alice["index"], 1);
    let alice_address = alice["address"].as_str().unwrap().to_string();
    let bob = call(addr, t, "getnewaddress", json!({"label": "bob"})).await;
    assert_eq!(bob["index"], 2);
    let listed = call(addr, t, "listaddresses", json!([])).await;
    assert_eq!(listed.as_array().unwrap().len(), 3);
    assert_eq!(listed[1]["label"], "alice");
    let info = call(addr, t, "getaddressinfo", json!([alice_address])).await;
    assert_eq!(info["is_mine"], true);
    assert_eq!(info["label"], "alice");
    let customer_address = customer.default_address().unwrap().encode(prefix);
    assert_eq!(
        call(addr, t, "getaddressinfo", json!([customer_address])).await["is_mine"],
        false
    );
    assert_eq!(
        call(addr, t, "validateaddress", json!([customer_address])).await["valid"],
        true
    );
    assert_eq!(
        call(addr, t, "validateaddress", json!(["tnull1junk"])).await["valid"],
        false
    );
    assert_eq!(
        call(addr, t, "estimatefee", json!([2])).await["fee"],
        "40000",
        "two recipients plus change is the four-action class"
    );

    // A withdrawal to the customer and a deposit to alice in one send.
    let sent = call(
        addr,
        t,
        "sendmany",
        json!([[
        {"address": customer_address, "amount": "1000", "memo": "withdrawal 1"},
        {"address": alice_address, "amount": 500},
    ], 1]),
    )
    .await;
    let id = sent["operation_id"].as_u64().unwrap();
    assert_eq!(sent["status"], "queued");
    wait_for(Duration::from_secs(180), async || {
        call(addr, t, "getoperationstatus", json!([id])).await["status"] == "confirmed"
    })
    .await;
    let op = call(addr, t, "getoperationstatus", json!([id])).await;
    let txid = op["txid"].as_str().unwrap().to_string();
    assert_eq!(op["total"], "1500");
    assert_eq!(op["attempts"], 1);
    assert!(op["confirmations"].as_u64().unwrap() >= 1);

    // The wallet sees the deposit to alice with her label, the change,
    // and the spent coinbase note, all under the one txid.
    wait_for(Duration::from_secs(30), async || {
        call(addr, t, "listreceived", json!([1]))
            .await
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["label"] == "alice")
    })
    .await;
    let received = call(addr, t, "listreceived", json!([1])).await;
    let to_alice = received
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["label"] == "alice")
        .unwrap();
    assert_eq!(to_alice["amount"], "500");
    assert_eq!(to_alice["address_index"], 1);
    assert_eq!(to_alice["txid"], txid);
    let view = call(addr, t, "gettransaction", json!([txid])).await;
    assert_eq!(
        view["received"].as_array().unwrap().len(),
        2,
        "alice's note and the change"
    );
    assert_eq!(view["spent"].as_array().unwrap().len(), 1);
    assert_eq!(view["net"], "-41000", "1000 out plus a four-action fee");
    assert_eq!(view["spent"][0]["spent_by"], json!(txid));
    assert_eq!(
        call_err(addr, t, "gettransaction", json!(["00".repeat(32)])).await,
        NOT_FOUND
    );
    let listed = call(addr, t, "listoperations", json!(["confirmed"])).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);

    // An impossible send fails and frees its notes; a queued one can be
    // cancelled but a confirmed one cannot.
    let broke = call(
        addr,
        t,
        "sendmany",
        json!([[
            {"address": customer_address, "amount": "99999999999999"},
        ]]),
    )
    .await;
    let broke_id = broke["operation_id"].as_u64().unwrap();
    wait_for(Duration::from_secs(30), async || {
        call(addr, t, "getoperationstatus", json!([broke_id])).await["status"] == "failed"
    })
    .await;
    let failed = call(addr, t, "getoperationstatus", json!([broke_id])).await;
    assert!(
        failed["error"].as_str().unwrap().contains("insufficient"),
        "{failed}"
    );
    assert_eq!(call(addr, t, "getbalance", json!([])).await["locked"], "0");
    assert_eq!(
        call_err(addr, t, "canceloperation", json!([id])).await,
        REJECTED
    );
    assert_eq!(
        call_err(addr, t, "getoperationstatus", json!([999])).await,
        NOT_FOUND
    );
    assert_eq!(
        call_err(
            addr,
            t,
            "sendmany",
            json!([[{"address": "tnull1junk", "amount": "1"}]])
        )
        .await,
        null_node::jsonrpc::INVALID_PARAMS
    );

    // The sender proves the withdrawal to anyone through a disclosure the
    // node verifies; a tampered one proves nothing.
    let disclosures = call(addr, t, "getpaymentdisclosure", json!([txid])).await;
    let to_customer = disclosures
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["amount"] == "1000")
        .unwrap();
    assert_eq!(to_customer["address"], customer_address);
    assert_eq!(to_customer["memo"], "withdrawal 1");
    let proof = to_customer["disclosure"].as_str().unwrap().to_string();
    let verified = call(node_rpc, n, "verifypaymentdisclosure", json!([proof])).await;
    assert_eq!(verified["valid"], true);
    assert_eq!(verified["amount"], "1000");
    assert_eq!(verified["address"], customer_address);
    assert_eq!(verified["memo"], "withdrawal 1");
    assert!(verified["confirmations"].as_i64().unwrap() >= 1);
    let mut tampered = proof.clone();
    tampered.replace_range(tampered.len() - 2.., "00");
    let refused = call(node_rpc, n, "verifypaymentdisclosure", json!([tampered])).await;
    assert_eq!(refused["valid"], false);
    assert_eq!(
        call_err(addr, t, "getpaymentdisclosure", json!(["00".repeat(32)])).await,
        NOT_FOUND
    );

    // Alice proves she controls her address by reading a challenge.
    let challenge = call(
        node_rpc,
        n,
        "createchallenge",
        json!([alice_address, "nonce 77"]),
    )
    .await;
    let answer = call(addr, t, "answerchallenge", json!([challenge["challenge"]])).await;
    assert_eq!(answer["message"], "nonce 77");
    let foreign = call(
        node_rpc,
        n,
        "createchallenge",
        json!([customer_address, "nonce 78"]),
    )
    .await;
    assert_eq!(
        call_err(addr, t, "answerchallenge", json!([foreign["challenge"]])).await,
        REJECTED
    );

    // Rescan from genesis finds the same notes again.
    let before = call(addr, t, "getwalletinfo", json!([])).await["notes"].clone();
    let received_before = call(addr, t, "listreceived", json!([])).await;
    call(addr, t, "rescan", json!([0])).await;
    wait_for(Duration::from_secs(60), async || {
        let info = call(addr, t, "getwalletinfo", json!([])).await;
        // Mining continues during the rescan, so the wallet can already
        // contain additional coinbase notes when it catches up.
        info["synced"] == true && info["notes"].as_u64() >= before.as_u64()
    })
    .await;
    let received_after = call(addr, t, "listreceived", json!([])).await;
    for note in received_before.as_array().unwrap() {
        assert!(
            received_after.as_array().unwrap().iter().any(|rescanned| {
                rescanned["position"] == note["position"]
                    && rescanned["txid"] == note["txid"]
                    && rescanned["amount"] == note["amount"]
            }),
            "rescan lost note {note}"
        );
    }

    // The exported viewing key opens a watch-only wallet that sees the
    // same notes and refuses to spend.
    let exported = call(addr, t, "exportviewingkey", json!([])).await;
    let fvk = decode_full_viewing_key(exported["viewing_key"].as_str().unwrap(), prefix).unwrap();
    assert_eq!(fvk.to_bytes(), miner_keys.full_viewing_key().to_bytes());
    daemon.shutdown();
    let watch_path = dir.path().join("watch.redb");
    drop(Wallet::create_watch_only(&watch_path, fvk, genesis_hash, b"pw", &mut rng).unwrap());
    let watch = Wallet::open(&watch_path, genesis_hash, b"pw").unwrap();
    let watch_token = Token::new("watch").unwrap();
    let watcher = walletd::run(walletd::Config {
        wallet: watch,
        network: Network::Test,
        node: Endpoint {
            addr: node.rpc_addr.unwrap().to_string(),
            token: Token::new("node").unwrap(),
        },
        listen: "127.0.0.1:0".parse().unwrap(),
        token: watch_token.clone(),
        sync_interval: Duration::from_millis(500),
        light: false,
    })
    .await
    .unwrap();
    let w = watch_token.expose();
    wait_for(Duration::from_secs(120), async || {
        call(watcher.addr, w, "getwalletinfo", json!([])).await["synced"] == true
    })
    .await;
    let info = call(watcher.addr, w, "getwalletinfo", json!([])).await;
    assert_eq!(info["watch_only"], true);
    assert!(
        info["notes"].as_u64() >= before.as_u64(),
        "sees every note the full wallet saw, plus any mined since"
    );
    assert_eq!(
        call_err(
            watcher.addr,
            w,
            "sendmany",
            json!([[{"address": customer_address, "amount": "1"}]])
        )
        .await,
        REJECTED
    );
    watcher.shutdown();
    node.shutdown().await;
}
