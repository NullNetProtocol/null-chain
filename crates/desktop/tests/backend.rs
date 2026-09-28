//! Exercises the actual desktop backend without a display or child processes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::Duration;

use null_chain::genesis::genesis;
use null_desktop::backend::{Action, Backend, Config, OpenMode};
use null_desktop::config::{Args, Startup};
use null_node::config::{Config as NodeConfig, Network};
use null_node::jsonrpc::{Dispatch, Params, REJECTED};
use null_node::rpc::Token;
use null_wallet::wallet::Wallet;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

async fn ready(backend: &mut Backend) -> SocketAddr {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            {
                let state = backend.snapshots.borrow();
                assert!(state.error.is_none(), "{:?}", state.error);
                if state.ready {
                    return state.rpc.unwrap();
                }
            }
            backend.snapshots.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

async fn http(addr: SocketAddr, token: &str, method: &str, params: Value) -> (String, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let body = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string();
    let request = format!("POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.lines().next().unwrap().into(),
        serde_json::from_str(body).unwrap(),
    )
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gui_and_http_share_one_wallet_and_lock_releases_its_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wallet.redb");
    let token_file = directory.path().join("desktop-rpc.token");
    let mut backend = Backend::spawn(Config {
        node: NodeConfig::test(),
        rpc: "127.0.0.1:0".parse().unwrap(),
        token_file: token_file.clone(),
        wallet: path.clone(),
    });
    let addr = ready(&mut backend).await;
    let token = Token::from_file(token_file).unwrap();
    assert_eq!(
        http(addr, "wrong", "getblockcount", json!([])).await.0,
        "HTTP/1.1 401 Unauthorized"
    );
    assert_eq!(
        http(addr, token.expose(), "getblockcount", json!([]))
            .await
            .1["result"],
        0
    );
    assert_eq!(
        http(addr, token.expose(), "getbalance", json!([])).await.1["error"]["code"],
        REJECTED
    );

    let outcome = backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("desktop-test".into()),
            mode: OpenMode::Create,
        })
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome.phrase.as_ref().unwrap().split_whitespace().count(),
        24
    );
    assert!(backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("desktop-test".into()),
            mode: OpenMode::Existing
        })
        .unwrap()
        .await
        .unwrap()
        .is_err());
    let address = http(addr, token.expose(), "getnewaddress", json!(["from RPC"]))
        .await
        .1["result"]
        .clone();
    assert!(address["address"].as_str().unwrap().starts_with("tnull1"));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = backend.snapshots.borrow().clone();
            if snapshot
                .addresses
                .as_array()
                .is_some_and(|v| v.iter().any(|a| a["label"] == "from RPC"))
                && snapshot
                    .wallet
                    .as_ref()
                    .is_some_and(|w| w["synced"] == true)
            {
                break;
            }
            backend.snapshots.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.snapshots.borrow().wallet.as_ref().unwrap()["scanned_height"],
        0
    );
    assert!(!serde_json::to_string(&backend.snapshots.borrow().wallet)
        .unwrap()
        .contains(outcome.phrase.as_ref().unwrap().as_str()));
    // A send from the GUI enters the very same persisted queue served by RPC.
    // This empty wallet cannot pay, but the background worker must report the
    // failure and finish before locking releases the database.
    let queued = backend
        .client
        .submit(Action::Call {
            method: "sendmany".into(),
            params: json!({"recipients": [{"address": address["address"], "amount": "1"}]}),
        })
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert!(
        queued.value["operation_id"].is_u64(),
        "calls return their result"
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let info = http(addr, token.expose(), "listoperations", json!([]))
                .await
                .1;
            if info["result"][0]["status"] == "failed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    backend
        .client
        .submit(Action::Lock)
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    let genesis = genesis(&Network::Test.params()).hash();
    // This fails if any wallet worker or RPC connection still holds the DB.
    let wallet = Wallet::open(&path, genesis, b"desktop-test").unwrap();
    assert_eq!(wallet.addresses().unwrap().len(), 2);
    assert_eq!(wallet.operations().unwrap().len(), 1);
    drop(wallet);
    assert_eq!(
        http(addr, token.expose(), "getbalance", json!([])).await.1["error"]["code"],
        REJECTED
    );
    assert!(backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("wrong".into()),
            mode: OpenMode::Existing
        })
        .unwrap()
        .await
        .unwrap()
        .is_err());
    backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("desktop-test".into()),
            mode: OpenMode::Existing,
        })
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        backend
            .client
            .call("node.getblockcount", &Params::new(json!([])))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        http(addr, token.expose(), "node.stop", json!([])).await.1["error"]["code"],
        REJECTED
    );
    assert_eq!(
        http(addr, token.expose(), "stop", json!([])).await.1["result"],
        "stopping"
    );
    backend.shutdown().await.unwrap();
    drop(Wallet::open(&path, genesis, b"desktop-test").unwrap());
    assert!(
        TcpListener::bind(addr).await.is_ok(),
        "RPC port must be released"
    );
}

#[tokio::test]
async fn desktop_rejects_public_rpc_before_starting_a_node() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Backend::spawn(Config {
        node: NodeConfig::test(),
        rpc: "0.0.0.0:0".parse().unwrap(),
        token_file: directory.path().join("token"),
        wallet: directory.path().join("wallet.redb"),
    });
    assert!(backend.shutdown().await.is_err());
    assert!(!directory.path().join("token").exists());
}

fn setup(datadir: &std::path::Path) -> Startup {
    Startup::load(&Args {
        datadir: Some(datadir.into()),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        ..Args::default()
    })
    .unwrap()
}

async fn open(backend: &Backend, mode: OpenMode) -> null_desktop::backend::Outcome {
    backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("setup-test".into()),
            mode,
        })
        .unwrap()
        .await
        .unwrap()
        .unwrap()
}

async fn default_address(backend: &Backend) -> Value {
    backend
        .client
        .call("listaddresses", &Params::new(json!([])))
        .await
        .unwrap()[0]["address"]
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_setup_recognizes_the_wallet_after_restart_and_import_restores_it() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("original");
    let startup = setup(&data);
    let paths = startup.paths;
    assert!(paths.config.is_file());
    assert!(!paths.wallet.exists());
    let mut backend = Backend::spawn(startup.backend);
    ready(&mut backend).await;
    assert!(!backend.snapshots.borrow().wallet_present);
    let outcome = open(&backend, OpenMode::Create).await;
    let phrase = outcome.phrase.unwrap();
    let address = default_address(&backend).await;
    assert!(backend.snapshots.borrow().wallet_present);
    assert!(paths.wallet.is_file());
    assert!(!std::fs::read_to_string(&paths.config)
        .unwrap()
        .contains(phrase.as_str()));
    backend.shutdown().await.unwrap();

    // No wallet path is passed to the GUI or unlock action on a later launch.
    let startup = setup(&data);
    assert_eq!(startup.paths.wallet, paths.wallet);
    let mut backend = Backend::spawn(startup.backend);
    ready(&mut backend).await;
    assert!(backend.snapshots.borrow().wallet_present);
    assert!(backend.snapshots.borrow().wallet.is_none());
    let refused = backend
        .client
        .submit(Action::Open {
            passphrase: Zeroizing::new("setup-test".into()),
            mode: OpenMode::Create,
        })
        .unwrap()
        .await
        .unwrap();
    assert!(
        refused.is_err(),
        "an existing wallet cannot be replaced by onboarding"
    );
    assert!(open(&backend, OpenMode::Existing).await.phrase.is_none());
    assert_eq!(default_address(&backend).await, address);
    backend.shutdown().await.unwrap();

    let startup = setup(&dir.path().join("imported"));
    let imported_path = startup.paths.wallet;
    let mut backend = Backend::spawn(startup.backend);
    ready(&mut backend).await;
    assert!(!backend.snapshots.borrow().wallet_present);
    assert!(open(&backend, OpenMode::Restore(phrase))
        .await
        .phrase
        .is_none());
    assert_eq!(default_address(&backend).await, address);
    assert!(backend.snapshots.borrow().wallet_present);
    assert!(imported_path.is_file());
    backend.shutdown().await.unwrap();
}
