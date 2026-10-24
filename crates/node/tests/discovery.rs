//! Reachability checks and peer exchange over real encrypted connections.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use null_node::config::{Config, OUTBOUND_TARGET};
use null_node::node::{spawn, Event, Handle, PeerSummary, Request, Response};
use null_p2p::addrbook::Snapshot;
use null_p2p::message::{Message, PeerAddr};
use null_p2p::noise::Role;
use null_p2p::peer::{version_info, Direction};
use null_p2p::transport::{establish, ConnectionReader, ConnectionWriter};
use tokio::net::{TcpListener, TcpStream};

const DEADLINE: Duration = Duration::from_secs(30);
/// Ticks between a node's address exchanges (`discovery::EXCHANGE_SECONDS`).
const EXCHANGE_TICKS: usize = 600;
/// Ticks before a node answers the same peer's `GetAddr` again
/// (`discovery::REPLY_SECONDS`).
const REPLY_TICKS: usize = 60;

fn listener() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn peers(node: &Handle) -> Vec<PeerSummary> {
    match node.request(Request::Peers).await.unwrap() {
        Response::Peers(peers) => peers,
        other => panic!("unexpected {other:?}"),
    }
}

async fn tick(nodes: &[&Handle], times: usize) {
    for _ in 0..times {
        for node in nodes {
            node.events().send(Event::Tick).await.unwrap();
        }
    }
}

async fn wait_for(nodes: &[&Handle], mut check: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !check().await {
            for node in nodes {
                node.events().send(Event::Tick).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

fn address(addr: SocketAddr) -> PeerAddr {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(ip) => ip.octets(),
    };
    PeerAddr {
        ip,
        port: addr.port(),
        last_seen: null_node::now(),
    }
}

struct Client {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

impl Client {
    async fn connect(node: &Handle) -> Self {
        let genesis = match node.request(Request::Block(0)).await.unwrap() {
            Response::Block(Some(block)) => block.hash(),
            other => panic!("unexpected {other:?}"),
        };
        let stream = TcpStream::connect(node.listen_addr.unwrap()).await.unwrap();
        let (writer, reader) = establish(stream, Role::Initiator).await.unwrap();
        let mut client = Self { writer, reader };
        client
            .writer
            .send(&Message::Version(version_info(
                123,
                0,
                genesis,
                null_node::now(),
            )))
            .await
            .unwrap();
        let mut version = false;
        let mut verack = false;
        while !version || !verack {
            match client.recv().await {
                Message::Version(_) => {
                    version = true;
                    client.writer.send(&Message::Verack).await.unwrap();
                }
                Message::Verack => verack = true,
                other => panic!("unexpected handshake message {other:?}"),
            }
        }
        client.barrier().await;
        client
    }

    async fn recv(&mut self) -> Message {
        let message = tokio::time::timeout(DEADLINE, self.reader.recv())
            .await
            .unwrap()
            .unwrap();
        match &message {
            Message::GetAddr => self.writer.send(&Message::Addr(Vec::new())).await.unwrap(),
            Message::Ping(nonce) => self.writer.send(&Message::Pong(*nonce)).await.unwrap(),
            _ => {}
        }
        message
    }

    /// Drain preceding messages and wait until the node processed our writes.
    async fn barrier(&mut self) {
        self.writer.send(&Message::Ping(456)).await.unwrap();
        while self.recv().await != Message::Pong(456) {}
    }

    /// Asks for addresses and returns the next address list received.
    async fn get_addr(&mut self) -> Vec<PeerAddr> {
        self.writer.send(&Message::GetAddr).await.unwrap();
        loop {
            if let Message::Addr(addrs) = self.recv().await {
                return addrs;
            }
        }
    }

    async fn wait_for_address(&mut self, addr: SocketAddr) {
        let expected = address(addr).key();
        tokio::time::timeout(DEADLINE, async {
            loop {
                if let Message::Addr(addrs) = self.recv().await {
                    if addrs.iter().any(|a| a.key() == expected) {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_discovers_a_listener_that_joins_its_seed_later() {
    let seed = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let seed_target = seed.listen_addr.unwrap().to_string();
    let wallet = spawn(Config {
        connect: vec![seed_target.clone()],
        ..Config::test()
    })
    .await
    .unwrap();
    wait_for(&[&wallet], async || {
        peers(&wallet).await.iter().any(|p| p.ready)
    })
    .await;
    let newcomer = spawn(Config {
        listen: Some(listener()),
        connect: vec![seed_target],
        ..Config::test()
    })
    .await
    .unwrap();
    let newcomer_addr = newcomer.listen_addr.unwrap();
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .any(|p| p.ready && p.addr == newcomer_addr)
    })
    .await;
    // Verified addresses are pulled, never pushed: the wallet learns the
    // newcomer at its next exchange with the seed.
    tick(&[&seed, &wallet], EXCHANGE_TICKS).await;
    wait_for(&[&seed, &wallet], async || {
        peers(&wallet)
            .await
            .iter()
            .any(|p| p.ready && p.addr == newcomer_addr)
    })
    .await;
    newcomer.shutdown().await;
    wallet.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_seed_verifies_and_relays_a_new_inbound_listening_node() {
    let mut bootstrap = Vec::new();
    for _ in 0..OUTBOUND_TARGET {
        bootstrap.push(
            spawn(Config {
                listen: Some(listener()),
                ..Config::test()
            })
            .await
            .unwrap(),
        );
    }
    let seed = spawn(Config {
        listen: Some(listener()),
        connect: bootstrap
            .iter()
            .map(|n| n.listen_addr.unwrap().to_string())
            .collect(),
        ..Config::test()
    })
    .await
    .unwrap();
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .filter(|p| p.ready && p.direction == Direction::Outbound)
            .count()
            == OUTBOUND_TARGET
    })
    .await;
    let mut observer = Client::connect(&seed).await;
    let newcomer = spawn(Config {
        listen: Some(listener()),
        connect: vec![seed.listen_addr.unwrap().to_string()],
        ..Config::test()
    })
    .await
    .unwrap();
    let expected = address(newcomer.listen_addr.unwrap()).key();
    tokio::time::timeout(DEADLINE, async {
        while !observer
            .get_addr()
            .await
            .iter()
            .any(|a| a.key() == expected)
        {
            tick(&[&seed], REPLY_TICKS).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        peers(&seed)
            .await
            .iter()
            .filter(|p| p.ready && p.direction == Direction::Outbound)
            .count(),
        OUTBOUND_TARGET
    );
    newcomer.shutdown().await;
    seed.shutdown().await;
    for node in bootstrap {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepting_tcp_without_a_network_handshake_does_not_make_an_address_gossipable() {
    let seed = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let mut sender = Client::connect(&seed).await;
    let mut observer = Client::connect(&seed).await;
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    sender
        .writer
        .send(&Message::Addr(vec![address(silent.local_addr().unwrap())]))
        .await
        .unwrap();
    sender.barrier().await;
    for _ in 0..5 {
        seed.events().send(Event::Tick).await.unwrap();
    }
    let (_socket, _) = tokio::time::timeout(DEADLINE, silent.accept())
        .await
        .unwrap()
        .unwrap();
    observer.writer.send(&Message::GetAddr).await.unwrap();
    loop {
        if let Message::Addr(sample) = observer.recv().await {
            assert!(sample.is_empty(), "an unverified address was relayed");
            break;
        }
    }
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfinished_version_handshake_cannot_start_chain_sync() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = spawn(Config {
        connect: vec![server.local_addr().unwrap().to_string()],
        ..Config::test()
    })
    .await
    .unwrap();
    let (stream, _) = server.accept().await.unwrap();
    let (mut writer, mut reader) = establish(stream, Role::Responder).await.unwrap();
    let Message::Version(ours) = reader.recv().await.unwrap() else {
        panic!("expected version");
    };
    writer
        .send(&Message::Version(version_info(
            123,
            1,
            ours.genesis,
            null_node::now(),
        )))
        .await
        .unwrap();
    // Receiving our Verack proves the node processed the version. The
    // remote side deliberately never acknowledges it, so it is not ready.
    assert_eq!(reader.recv().await.unwrap(), Message::Verack);
    node.events().send(Event::Tick).await.unwrap();
    let Response::Status { syncing, .. } = node.request(Request::Status).await.unwrap() else {
        panic!("expected status");
    };
    assert!(!syncing, "a peer still being verified was used for sync");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn established_peers_repeat_announcements_but_ask_only_outbound_peers_for_addresses() {
    let seed = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let mut observer = Client::connect(&seed).await;
    tick(&[&seed], EXCHANGE_TICKS).await;
    observer.writer.send(&Message::Ping(789)).await.unwrap();
    let expected = address(seed.listen_addr.unwrap()).key();
    let mut announcement = false;
    loop {
        match observer.recv().await {
            Message::Addr(addrs) => announcement |= addrs.iter().any(|a| a.key() == expected),
            Message::GetAddr => panic!("an inbound peer was asked for addresses"),
            Message::Pong(789) => break,
            _ => {}
        }
    }
    assert!(announcement, "the listener was not announced again");
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inbound_peer_can_only_announce_one_address_per_exchange() {
    let seed = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let mut sender = Client::connect(&seed).await;
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flood = [&first, &second, &second]
        .map(|l| address(l.local_addr().unwrap()))
        .to_vec();
    sender.writer.send(&Message::Addr(flood)).await.unwrap();
    sender.barrier().await;
    tick(&[&seed], REPLY_TICKS).await;
    tokio::time::timeout(DEADLINE, first.accept())
        .await
        .unwrap()
        .unwrap();
    tick(&[&seed], REPLY_TICKS).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), second.accept())
            .await
            .is_err(),
        "an address beyond the inbound allowance was dialed"
    );
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_port_override_is_verified_and_shared() {
    let seed = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let forward = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = forward.local_addr().unwrap();
    let node = spawn(Config {
        listen: Some(listener()),
        advertise: Some(public),
        connect: vec![seed.listen_addr.unwrap().to_string()],
        ..Config::test()
    })
    .await
    .unwrap();
    let private = node.listen_addr.unwrap();
    let relay = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = forward.accept().await {
            tokio::spawn(async move {
                let mut outbound = TcpStream::connect(private).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .any(|p| p.ready && p.addr == public)
    })
    .await;
    let mut observer = Client::connect(&seed).await;
    observer.writer.send(&Message::GetAddr).await.unwrap();
    observer.wait_for_address(public).await;
    relay.abort();
    node.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_node_still_shares_the_listeners_it_verified() {
    let dir = tempfile::tempdir().unwrap();
    let listening = spawn(Config {
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let target = listening.listen_addr.unwrap();
    let node = spawn(Config {
        datadir: Some(dir.path().to_path_buf()),
        connect: vec![target.to_string()],
        ..Config::test()
    })
    .await
    .unwrap();
    wait_for(&[&node], async || {
        peers(&node)
            .await
            .iter()
            .any(|p| p.ready && p.addr == target)
    })
    .await;
    node.shutdown().await;

    let saved =
        Snapshot::from_bytes(&std::fs::read(dir.path().join("peers.dat")).unwrap()).unwrap();
    let entry = saved
        .entries()
        .iter()
        .find(|s| s.addr.key() == address(target).key());
    assert!(entry.unwrap().verified_at.is_some(), "saved as verified");

    // With the listener gone the restarted node cannot verify it again, so
    // sharing it proves the verification came from disk.
    listening.shutdown().await;
    let restarted = spawn(Config {
        datadir: Some(dir.path().to_path_buf()),
        listen: Some(listener()),
        ..Config::test()
    })
    .await
    .unwrap();
    let mut client = Client::connect(&restarted).await;
    let shared = client.get_addr().await;
    assert!(
        shared.iter().any(|a| a.key() == address(target).key()),
        "{shared:?}"
    );
    restarted.shutdown().await;
}
