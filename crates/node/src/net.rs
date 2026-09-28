//! Sockets: the listener, the dialer with optional SOCKS5 proxy, and the
//! task that runs one connection and forwards its messages to the loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use null_p2p::message::Message;
use null_p2p::noise::Role;
use null_p2p::peer::Direction;
use null_p2p::transport::{
    establish_within, ConnectionReader, ConnectionWriter, HANDSHAKE_TIMEOUT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::i2p::{self, SamSession};
use crate::node::{Event, PeerId};
use crate::{Error, Result};

/// Messages queued to a peer before it is considered stuck.
const OUTBOX_CAPACITY: usize = 1_024;
/// Inbound connections allowed in the handshake at once. The node's
/// inbound cap only counts peers that finished the handshake, so without
/// this a client could hold any number of sockets open by staying silent.
pub const MAX_PENDING_INBOUND: usize = 32;

/// What bounds the accept loop: how many connections may be mid-handshake
/// and how long each may take.
#[derive(Clone, Copy, Debug)]
pub struct AcceptLimits {
    /// Connections allowed in the handshake at once.
    pub pending: usize,
    /// Deadline for one handshake.
    pub handshake_timeout: Duration,
}

impl Default for AcceptLimits {
    fn default() -> Self {
        Self {
            pending: MAX_PENDING_INBOUND,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

/// Accepts connections forever, spawning a connection task for each,
/// under [`AcceptLimits::default`].
pub async fn listen(listener: TcpListener, events: mpsc::Sender<Event>, next_id: PeerId) {
    listen_within(listener, events, next_id, AcceptLimits::default()).await;
}

/// [`listen`] with explicit limits. A connection is accepted only once a
/// pending slot is free; the slot is held until its handshake ends.
pub async fn listen_within(
    listener: TcpListener,
    events: mpsc::Sender<Event>,
    mut next_id: PeerId,
    limits: AcceptLimits,
) {
    let pending = Arc::new(Semaphore::new(limits.pending));
    loop {
        let Ok(permit) = Arc::clone(&pending).acquire_owned().await else {
            return;
        };
        let Ok((stream, addr)) = listener.accept().await else {
            return;
        };
        let id = next_id;
        next_id = next_id.saturating_add(1);
        let target = addr.to_string();
        tokio::spawn(run_connection(
            Accepted {
                stream,
                role: Role::Responder,
                direction: Direction::Inbound,
                id,
                addr,
                target,
                permit: Some(permit),
                handshake_timeout: limits.handshake_timeout,
            },
            events.clone(),
        ));
    }
}

/// A socket about to be handshaken and run.
struct Accepted {
    stream: TcpStream,
    role: Role,
    direction: Direction,
    id: PeerId,
    addr: SocketAddr,
    target: String,
    /// The pending-inbound slot, released once the handshake ends.
    permit: Option<OwnedSemaphorePermit>,
    handshake_timeout: Duration,
}

/// Dials `target` (`host:port`) and runs the connection: `.i2p` peers
/// through the SAM session, everything else through `proxy` or directly.
pub fn dial(
    target: String,
    proxy: Option<SocketAddr>,
    i2p: Option<Arc<SamSession>>,
    id: PeerId,
    events: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stream = match (i2p, proxy) {
            (Some(session), _) if i2p::is_i2p(&target) => {
                session.connect(i2p::destination_of(&target)).await
            }
            (_, Some(proxy)) => socks5_connect(proxy, &target).await,
            _ => TcpStream::connect(&target).await.map_err(Error::from),
        };
        match stream {
            Ok(stream) => {
                let addr = stream
                    .peer_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                run_connection(
                    Accepted {
                        stream,
                        role: Role::Initiator,
                        direction: Direction::Outbound,
                        id,
                        addr,
                        target,
                        permit: None,
                        handshake_timeout: HANDSHAKE_TIMEOUT,
                    },
                    events,
                )
                .await;
            }
            Err(_) => {
                let _ = events.send(Event::DialFailed { id, target }).await;
            }
        }
    })
}

/// Opens a TCP connection to `target` through a SOCKS5 proxy without
/// authentication, passing the hostname to the proxy so it resolves it.
/// This is how Tor reaches `.onion` peers.
///
/// # Errors
/// Fails on a socket error or a proxy refusal.
pub async fn socks5_connect(proxy: SocketAddr, target: &str) -> Result<TcpStream> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| Error::Argument(format!("bad target {target}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| Error::Argument(format!("bad port in {target}")))?;
    let host_len =
        u8::try_from(host.len()).map_err(|_| Error::Argument("hostname too long".into()))?;
    let mut stream = TcpStream::connect(proxy).await?;

    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(Error::Argument("proxy refused the handshake".into()));
    }

    let mut request = vec![5, 1, 0, 3, host_len];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head.get(1) != Some(&0) {
        return Err(Error::Argument(format!(
            "proxy connect failed with code {}",
            head.get(1).copied().unwrap_or(0)
        )));
    }
    let bound_len = match head.get(3) {
        Some(1) => 4,
        Some(4) => 16,
        Some(3) => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        _ => return Err(Error::Argument("proxy reply malformed".into())),
    };
    let mut bound = vec![0u8; bound_len.saturating_add(2)];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

/// Handshakes, then pumps messages both ways until either side closes.
async fn run_connection(accepted: Accepted, events: mpsc::Sender<Event>) {
    let Accepted {
        stream,
        role,
        direction,
        id,
        addr,
        target,
        permit,
        handshake_timeout,
    } = accepted;
    let established = establish_within(stream, role, handshake_timeout).await;
    drop(permit);
    let Ok((writer, reader)) = established else {
        let _ = events.send(Event::DialFailed { id, target }).await;
        return;
    };
    let (outbox, inbox) = mpsc::channel::<Message>(OUTBOX_CAPACITY);
    if events
        .send(Event::Connected {
            id,
            direction,
            addr,
            target,
            outbox,
        })
        .await
        .is_err()
    {
        return;
    }
    let mut writer_task = tokio::spawn(write_loop(writer, inbox));
    // Reading ends when the peer closes; writing ends when the node drops
    // the outbox. Either way the connection is over.
    tokio::select! {
        () = read_loop(reader, id, &events) => writer_task.abort(),
        _ = &mut writer_task => {}
    }
    let _ = events.send(Event::Disconnected { id }).await;
}

async fn write_loop(mut writer: ConnectionWriter, mut inbox: mpsc::Receiver<Message>) {
    while let Some(message) = inbox.recv().await {
        if writer.send(&message).await.is_err() {
            break;
        }
    }
}

async fn read_loop(mut reader: ConnectionReader, id: PeerId, events: &mpsc::Sender<Event>) {
    while let Ok(message) = reader.recv().await {
        if events
            .send(Event::Message {
                id,
                message: Box::new(message),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// With one pending slot, a silent client blocks the next accept until
    /// its handshake deadline passes; then a real client gets through.
    #[tokio::test]
    async fn silent_clients_hold_a_pending_slot_only_until_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events, mut inbox) = mpsc::channel(8);
        let limits = AcceptLimits {
            pending: 1,
            handshake_timeout: Duration::from_millis(200),
        };
        tokio::spawn(listen_within(listener, events, 0, limits));

        let _silent = TcpStream::connect(addr).await.unwrap();
        let honest = TcpStream::connect(addr).await.unwrap();
        let client = tokio::spawn(establish_within(
            honest,
            Role::Initiator,
            Duration::from_secs(5),
        ));

        assert!(matches!(
            inbox.recv().await,
            Some(Event::DialFailed { id: 0, .. })
        ));
        assert!(matches!(
            inbox.recv().await,
            Some(Event::Connected { id: 1, .. })
        ));
        assert!(client.await.unwrap().is_ok());
    }

    /// A minimal SOCKS5 server that accepts one CONNECT to any host and
    /// then echoes bytes, so the client side can be tested end to end.
    async fn fake_proxy(listener: TcpListener) -> Vec<u8> {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..4], &[5, 1, 0, 3]);
        let mut host = vec![0u8; usize::from(head[4])];
        stream.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        host
    }

    #[tokio::test]
    async fn socks5_connect_sends_the_hostname_and_returns_a_usable_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(listener));
        let mut stream = socks5_connect(proxy, "example.onion:8333").await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        assert_eq!(server.await.unwrap(), b"example.onion");
    }

    #[tokio::test]
    async fn socks5_connect_rejects_bad_targets_and_refusals() {
        assert!(socks5_connect("127.0.0.1:1".parse().unwrap(), "no-port")
            .await
            .is_err());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0xff]).await.unwrap();
        });
        assert!(socks5_connect(proxy, "host:1").await.is_err());
    }
}
