//! Two in-process nodes: a miner and a follower that syncs from it, then
//! a payment submitted to the follower is relayed and mined by the miner.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use null_circuit::proof::ProvingKey;
use null_crypto::keys::SpendingKey;
use null_node::config::{Config, Network};
use null_node::node::{spawn, Handle, Request, Response};
use null_protocol::amount::Amount;
use null_protocol::memo::Memo;
use null_wallet::keys::WalletKeys;
use null_wallet::spend::{build_payment, Payment};
use null_wallet::wallet::Wallet;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_syncs_from_miner_and_relays_a_payment() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let miner_sk = SpendingKey::random(&mut rng);
    let miner_keys = WalletKeys::from_spending_key(miner_sk.clone()).unwrap();
    let miner_address = miner_keys.default_address().unwrap();
    let receiver = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();

    let miner = spawn(Config {
        network: Network::Test,
        datadir: None,
        listen: Some("127.0.0.1:0".parse().unwrap()),
        connect: Vec::new(),
        proxy: None,
        i2p: None,
        mine_to: Some(miner_address),
        mining_threads: 1,
        rpc: None,
        rpc_http: None,
        rpc_token: None,
        block_notify: None,
        metrics: None,
        max_inbound: 125,
    })
    .await
    .unwrap();
    let follower = spawn(Config {
        network: Network::Test,
        datadir: None,
        listen: None,
        connect: vec![miner.listen_addr.unwrap().to_string()],
        proxy: None,
        i2p: None,
        mine_to: None,
        mining_threads: 1,
        rpc: None,
        rpc_http: None,
        rpc_token: None,
        block_notify: None,
        metrics: None,
        max_inbound: 125,
    })
    .await
    .unwrap();

    // The follower catches up with the miner.
    wait_for(Duration::from_secs(120), async || {
        height(&follower).await >= 3
    })
    .await;
    let miner_height = height(&miner).await;
    assert!(miner_height >= 3);

    // Scan the miner's chain as its wallet and pay the receiver through
    // the follower, which relays to the miner.
    let scanned_to = height(&miner).await;
    let Response::Block(Some(genesis)) = miner.request(Request::Block(0)).await.unwrap() else {
        panic!("genesis")
    };
    let wallet = Wallet::in_memory(&miner_sk, genesis.hash(), &mut rng).unwrap();
    for h in 0..=scanned_to {
        let Response::Block(Some(block)) = miner.request(Request::Block(h)).await.unwrap() else {
            panic!("block")
        };
        wallet.scan(&block).unwrap();
    }
    assert!(
        wallet.balance().unwrap() > 0,
        "the miner earned coinbase notes"
    );
    let pk = ProvingKey::build().unwrap();
    let payment = Payment {
        recipient: receiver.default_address().unwrap(),
        amount: Amount::from_raw(1_000).unwrap(),
        memo: Memo::empty(),
    };
    // The test network schedules no upgrades, so the genesis branch is in
    // force at every height.
    let branch = Network::Test.params().genesis_branch;
    let tx = build_payment(&wallet, payment, &pk, branch, &mut rng).unwrap();
    let nullifier = *tx.actions()[0].body().nullifier();
    let Response::Submitted(_) = follower
        .request(Request::Submit(Box::new(tx)))
        .await
        .unwrap()
    else {
        panic!("submit")
    };

    // The miner eventually includes it: one of its nullifiers is spent.
    wait_for(Duration::from_secs(120), async || {
        matches!(
            miner.request(Request::IsSpent(nullifier)).await.unwrap(),
            Response::Spent(true)
        )
    })
    .await;
    // And the follower sees the same chain.
    wait_for(Duration::from_secs(60), async || {
        matches!(
            follower.request(Request::IsSpent(nullifier)).await.unwrap(),
            Response::Spent(true)
        )
    })
    .await;

    follower.shutdown().await;
    miner.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_connections_are_capped() {
    let node = spawn(Config {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        max_inbound: 2,
        ..Config::test()
    })
    .await
    .unwrap();
    let addr = node.listen_addr.unwrap();
    let genesis = node_genesis(&node).await;
    // Three dialers complete the transport handshake; only two get a peer
    // slot, so the third never sees a Version message.
    let mut versions = 0;
    let mut kept = Vec::new();
    for _ in 0..3 {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut writer, mut reader) =
            null_p2p::transport::establish(stream, null_p2p::noise::Role::Initiator)
                .await
                .unwrap();
        let hello =
            null_p2p::message::Message::Version(null_p2p::peer::version_info(7, 0, genesis, 0));
        writer.send(&hello).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), reader.recv()).await;
        if matches!(got, Ok(Ok(null_p2p::message::Message::Version(_)))) {
            versions += 1;
        }
        kept.push((writer, reader));
    }
    assert_eq!(versions, 2);
    drop(kept);
    node.shutdown().await;
}

async fn node_genesis(node: &Handle) -> null_protocol::block::BlockHash {
    match node.request(Request::Block(0)).await.unwrap() {
        Response::Block(Some(block)) => block.hash(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_resumes_its_chain_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let miner_keys =
        WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(9)))
            .unwrap();
    let config = Config {
        datadir: Some(dir.path().to_path_buf()),
        mine_to: Some(miner_keys.default_address().unwrap()),
        ..Config::test()
    };
    let node = spawn(config.clone()).await.unwrap();
    wait_for(Duration::from_secs(120), async || height(&node).await >= 2).await;
    let tip = match node.request(Request::Status).await.unwrap() {
        Response::Status { height, hash, .. } => (height, hash),
        other => panic!("unexpected {other:?}"),
    };
    node.shutdown().await;

    let reopened = spawn(Config {
        mine_to: None,
        ..config
    })
    .await
    .unwrap();
    let after = match reopened.request(Request::Status).await.unwrap() {
        Response::Status { height, hash, .. } => (height, hash),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(after, tip, "the chain survives a restart intact");
    reopened.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_endpoint_reports_mined_blocks_and_the_status_line_counts_them() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let miner = spawn(Config {
        mine_to: Some(keys.default_address().unwrap()),
        metrics: Some("127.0.0.1:0".parse().unwrap()),
        ..Config::test()
    })
    .await
    .unwrap();
    wait_for(Duration::from_secs(120), async || height(&miner).await >= 2).await;

    let (found, in_chain) = match miner.request(Request::Status).await.unwrap() {
        Response::Status {
            mined,
            mined_in_chain,
            ..
        } => (mined, mined_in_chain),
        other => panic!("unexpected {other:?}"),
    };
    assert!(found >= 2);
    assert_eq!(found, in_chain, "a lone miner has no stale blocks");

    let mut stream = tokio::net::TcpStream::connect(miner.metrics_addr.unwrap())
        .await
        .unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200 OK"));
    assert!(body.contains("null_blocks_mined{state=\"found\"} "));
    assert!(body.contains("null_height "));
    assert!(body.contains("null_uptime_seconds "));

    let mut stream = tokio::net::TcpStream::connect(miner.metrics_addr.unwrap())
        .await
        .unwrap();
    stream
        .write_all(b"GET /other HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 404"));
    miner.shutdown().await;
}

async fn peer_count(handle: &Handle) -> usize {
    match handle.request(Request::Status).await.unwrap() {
        Response::Status { peers, .. } => peers,
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_discovers_a_peer_it_was_never_configured_with() {
    // A listens. B connects to A and listens, so it learns A's address.
    // C connects only to B and must reach A through gossiped addresses.
    let seed = spawn(Config {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        ..Config::test()
    })
    .await
    .unwrap();
    let seed_addr = seed.listen_addr.unwrap().to_string();

    let relay = spawn(Config {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        connect: vec![seed_addr.clone()],
        ..Config::test()
    })
    .await
    .unwrap();
    let relay_addr = relay.listen_addr.unwrap().to_string();

    let far = spawn(Config {
        connect: vec![relay_addr],
        ..Config::test()
    })
    .await
    .unwrap();

    // C starts with one configured peer (B) and must find a second (A).
    wait_for(Duration::from_secs(60), async || {
        peer_count(&far).await >= 2
    })
    .await;
    assert!(
        peer_count(&far).await >= 2,
        "the far node reached a peer it was never given"
    );

    far.shutdown().await;
    relay.shutdown().await;
    seed.shutdown().await;
}
