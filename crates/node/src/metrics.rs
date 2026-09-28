//! A Prometheus text endpoint: `GET /metrics` on its own listener.
//!
//! It is unauthenticated, since it exposes nothing a peer could not
//! infer and monitoring systems expect to scrape it plainly, so it
//! binds where `--metrics` says and nowhere by default.

use std::fmt::Write as _;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::http::{read_get_path, respond};
use crate::node::{Event, Request, Response};
use crate::{Error, Result};

/// A snapshot of what the node is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Tip height.
    pub height: u32,
    /// Ready inbound peers.
    pub peers_inbound: usize,
    /// Ready outbound peers.
    pub peers_outbound: usize,
    /// Pooled transactions.
    pub mempool: usize,
    /// Blocks this node's miner found since it started.
    pub blocks_mined: usize,
    /// Of those, the ones in the main chain now; the rest went stale.
    pub blocks_mined_in_chain: usize,
    /// Compact blocks awaiting transactions.
    pub pending_compact_blocks: usize,
    /// Seconds since the node started.
    pub uptime_seconds: u64,
}

/// Renders the snapshot in the Prometheus text format.
#[must_use]
pub fn render(m: &Metrics) -> String {
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, value: String| {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{value}");
    };
    gauge(
        "null_height",
        "Height of the chain tip.",
        format!("null_height {}", m.height),
    );
    gauge(
        "null_peers",
        "Connected peers past the handshake, by direction.",
        format!(
            "null_peers{{direction=\"inbound\"}} {}\nnull_peers{{direction=\"outbound\"}} {}",
            m.peers_inbound, m.peers_outbound
        ),
    );
    gauge(
        "null_mempool_transactions",
        "Transactions in the mempool.",
        format!("null_mempool_transactions {}", m.mempool),
    );
    gauge(
        "null_blocks_mined",
        "Blocks this node found since it started, and how many are in the main chain now.",
        format!(
            "null_blocks_mined{{state=\"found\"}} {}\nnull_blocks_mined{{state=\"in_chain\"}} {}",
            m.blocks_mined, m.blocks_mined_in_chain
        ),
    );
    gauge(
        "null_pending_compact_blocks",
        "Compact blocks waiting for transactions.",
        format!("null_pending_compact_blocks {}", m.pending_compact_blocks),
    );
    gauge(
        "null_uptime_seconds",
        "Seconds since the node started.",
        format!("null_uptime_seconds {}", m.uptime_seconds),
    );
    out
}

/// Serves `GET /metrics` forever.
pub async fn serve(listener: TcpListener, events: mpsc::Sender<Event>) {
    while let Ok((stream, _)) = listener.accept().await {
        let events = events.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let _ = handle(&mut stream, &events).await;
        });
    }
}

async fn handle(stream: &mut tokio::net::TcpStream, events: &mpsc::Sender<Event>) -> Result<()> {
    let (status, body) = match read_get_path(stream).await?.as_deref() {
        Some("/metrics") => match snapshot(events).await {
            Ok(metrics) => ("200 OK", render(&metrics)),
            Err(error) => ("500 Internal Server Error", format!("{error}\n")),
        },
        Some(_) => ("404 Not Found", "GET /metrics\n".to_string()),
        None => ("400 Bad Request", "malformed request\n".to_string()),
    };
    respond(stream, status, &body).await
}

/// Asks the node loop for a snapshot.
///
/// # Errors
/// Returns [`Error::Stopped`] if the loop is gone.
pub async fn snapshot(events: &mpsc::Sender<Event>) -> Result<Metrics> {
    let (reply, response) = oneshot::channel();
    events
        .send(Event::Rpc {
            request: Request::Metrics,
            reply,
        })
        .await
        .map_err(|_| Error::Stopped)?;
    match response.await.map_err(|_| Error::Stopped)? {
        Response::Metrics(metrics) => Ok(*metrics),
        Response::Failed(reason) => Err(Error::Argument(reason)),
        _ => Err(Error::Stopped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_follows_the_text_format() {
        let text = render(&Metrics {
            height: 7,
            peers_inbound: 1,
            peers_outbound: 2,
            mempool: 3,
            blocks_mined: 5,
            blocks_mined_in_chain: 4,
            pending_compact_blocks: 0,
            uptime_seconds: 60,
        });
        for line in [
            "# TYPE null_height gauge",
            "null_height 7",
            "null_peers{direction=\"inbound\"} 1",
            "null_peers{direction=\"outbound\"} 2",
            "null_mempool_transactions 3",
            "null_blocks_mined{state=\"found\"} 5",
            "null_blocks_mined{state=\"in_chain\"} 4",
            "null_pending_compact_blocks 0",
            "null_uptime_seconds 60",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
        assert!(text.ends_with('\n'));
    }
}
