//! A faucet: a tiny HTTP server that pays a fixed amount to any address
//! it is asked for, rate-limited per address and per client.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use null_circuit::proof::ProvingKey;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::consensus::next_height;
use null_wallet::wallet::Wallet;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::cli::{pay, sync_wallet};
use crate::config::Network;
use crate::http::{read_get_path, respond};
use crate::rpc::Endpoint;
use crate::{now, Error, Result};

/// Seconds between payouts to one address.
pub const ADDRESS_COOLDOWN: u64 = 60 * 60;
/// Seconds between payouts to one client address.
pub const CLIENT_COOLDOWN: u64 = 10 * 60;
struct State {
    wallet: Wallet,
    pk: ProvingKey,
    node: Endpoint,
    amount: Amount,
    by_address: HashMap<String, u64>,
    by_client: HashMap<std::net::IpAddr, u64>,
    network: Network,
}

/// Serves `GET /pay/<address>` forever.
///
/// # Errors
/// Fails if the socket cannot be bound or the proving key built.
pub async fn serve(
    listen: SocketAddr,
    node: Endpoint,
    wallet: Wallet,
    amount: Amount,
    network: Network,
) -> Result<()> {
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let listener = TcpListener::bind(listen).await?;
    crate::node::log(&format!(
        "faucet on {listen}, paying {} per request",
        amount.raw()
    ));
    let state = Arc::new(Mutex::new(State {
        wallet,
        pk,
        node,
        amount,
        by_address: HashMap::new(),
        by_client: HashMap::new(),
        network,
    }));
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle(stream, peer, state).await;
        });
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, state: Arc<Mutex<State>>) -> Result<()> {
    let (status, body) = match read_get_path(&mut stream).await?.as_deref() {
        Some(path) => match path.strip_prefix("/pay/") {
            Some(address) => match payout(address, peer.ip(), &state).await {
                Ok(txid) => ("200 OK", format!("paid, transaction {txid}\n")),
                Err(Error::Argument(reason)) => ("429 Too Many Requests", format!("{reason}\n")),
                Err(error) => ("400 Bad Request", format!("{error}\n")),
            },
            None => (
                "200 OK",
                "GET /pay/<address> to receive test coins\n".to_string(),
            ),
        },
        None => ("400 Bad Request", "malformed request\n".to_string()),
    };
    respond(&mut stream, status, &body).await
}

async fn payout(
    address: &str,
    client: std::net::IpAddr,
    state: &Arc<Mutex<State>>,
) -> Result<String> {
    let mut state = state.lock().await;
    let recipient = Address::decode(address, state.network.address_prefix())?;
    let now = now();
    let recent =
        |last: Option<&u64>, cooldown: u64| last.is_some_and(|t| now.saturating_sub(*t) < cooldown);
    if recent(state.by_address.get(address), ADDRESS_COOLDOWN) {
        return Err(Error::Argument("this address was paid recently".into()));
    }
    if recent(state.by_client.get(&client), CLIENT_COOLDOWN) {
        return Err(Error::Argument("this client was paid recently".into()));
    }
    let mut rpc = state.node.connect().await?;
    let maturity = state.network.params().coinbase_maturity;
    let scanned = sync_wallet(&mut rpc, &state.wallet, false, maturity).await?;
    let branch = state.network.params().branch_at(next_height(scanned)?);
    let amount = state.amount;
    let txid = pay(
        &mut rpc,
        &state.wallet,
        &state.pk,
        recipient,
        amount,
        branch,
    )
    .await?;
    state.by_address.insert(address.to_string(), now);
    state.by_client.insert(client, now);
    Ok(txid)
}
