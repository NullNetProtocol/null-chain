//! A TCP connection running the Noise session and message framing, split
//! into a reader and a writer so a connection task can do both at once.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::codec::{frame, Framer};
use crate::message::Message;
use crate::noise::{Handshake, Role, SessionReader, SessionWriter};
use crate::{Error, Result};

/// Bytes read from the socket at a time.
const READ_CHUNK: usize = 64 * 1024;
/// Largest handshake message on the wire.
const HANDSHAKE_MAX: usize = 1024;
/// How long a peer has to complete the handshake. A silent peer holds
/// a socket and a task for no longer than this.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The sending half of a connection.
#[derive(Debug)]
pub struct ConnectionWriter {
    stream: OwnedWriteHalf,
    session: SessionWriter,
}

/// The receiving half of a connection.
#[derive(Debug)]
pub struct ConnectionReader {
    stream: OwnedReadHalf,
    session: SessionReader,
    framer: Framer,
}

/// Runs the handshake over `stream` in `role` within
/// [`HANDSHAKE_TIMEOUT`] and splits the connection.
///
/// # Errors
/// Fails on a socket error, a rejected handshake message, or
/// [`Error::HandshakeTimeout`].
pub async fn establish(
    stream: TcpStream,
    role: Role,
) -> Result<(ConnectionWriter, ConnectionReader)> {
    establish_within(stream, role, HANDSHAKE_TIMEOUT).await
}

/// [`establish`] with an explicit deadline.
///
/// # Errors
/// As [`establish`].
pub async fn establish_within(
    stream: TcpStream,
    role: Role,
    deadline: Duration,
) -> Result<(ConnectionWriter, ConnectionReader)> {
    tokio::time::timeout(deadline, handshake(stream, role))
        .await
        .map_err(|_| Error::HandshakeTimeout)?
}

async fn handshake(
    mut stream: TcpStream,
    role: Role,
) -> Result<(ConnectionWriter, ConnectionReader)> {
    let mut handshake = Handshake::new(role)?;
    match role {
        Role::Initiator => {
            write_handshake(&mut stream, &handshake.write()?).await?;
            handshake.read(&read_handshake(&mut stream).await?)?;
        }
        Role::Responder => {
            handshake.read(&read_handshake(&mut stream).await?)?;
            write_handshake(&mut stream, &handshake.write()?).await?;
        }
    }
    let (writer, reader) = handshake.into_session()?;
    let (read_half, write_half) = stream.into_split();
    Ok((
        ConnectionWriter {
            stream: write_half,
            session: writer,
        },
        ConnectionReader {
            stream: read_half,
            session: reader,
            framer: Framer::new(),
        },
    ))
}

impl ConnectionWriter {
    /// Sends one message.
    ///
    /// # Errors
    /// Fails on a socket or session error.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        let wire = self.session.seal(&frame(message))?;
        self.stream.write_all(&wire).await?;
        Ok(())
    }
}

impl ConnectionReader {
    /// Receives the next message, reading from the socket as needed.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] at end of stream, or a socket, session
    /// or decode error.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            if let Some(message) = self.framer.next_message()? {
                return Ok(message);
            }
            let mut buffer = vec![0u8; READ_CHUNK];
            let n = self.stream.read(&mut buffer).await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            let plaintext = self.session.open(buffer.get(..n).unwrap_or(&[]))?;
            self.framer.push(&plaintext);
        }
    }
}

async fn write_handshake(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    let len = u16::try_from(message.len()).map_err(|_| Error::TooLarge(message.len()))?;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(message).await?;
    Ok(())
}

async fn read_handshake(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    let len = usize::from(u16::from_le_bytes(prefix));
    if len > HANDSHAKE_MAX {
        return Err(Error::TooLarge(len));
    }
    let mut message = vec![0u8; len];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use null_protocol::block::BlockHash;
    use null_protocol::transaction::TxId;
    use tokio::net::TcpListener;

    use super::*;
    use crate::message::Inventory;
    use crate::peer::version_info;

    fn big_inventory() -> Message {
        Message::Inv(
            (0..20_000u64)
                .map(|i| {
                    let mut b = [0u8; 32];
                    b[..8].copy_from_slice(&i.to_le_bytes());
                    Inventory::Tx(TxId::from_bytes(b))
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn messages_cross_a_loopback_connection_both_ways_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut w, mut r) = establish(stream, Role::Responder).await.unwrap();
            let first = r.recv().await.unwrap();
            w.send(&Message::Verack).await.unwrap();
            let second = r.recv().await.unwrap();
            (first, second)
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut w, mut r) = establish(stream, Role::Initiator).await.unwrap();
        let version = Message::Version(version_info(1, 2, BlockHash::ZERO, 3));
        w.send(&version).await.unwrap();
        assert_eq!(r.recv().await.unwrap(), Message::Verack);
        let big = big_inventory();
        w.send(&big).await.unwrap();
        drop((w, r));
        let (first, second) = server.await.unwrap();
        assert_eq!(first, version);
        assert_eq!(second, big);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out_of_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _silent = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        // Paused time advances as soon as every task is waiting, so the
        // full deadline passes without a real wait.
        assert!(matches!(
            establish(stream, Role::Responder).await,
            Err(Error::HandshakeTimeout)
        ));
    }

    #[tokio::test]
    async fn a_closed_socket_reports_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let halves = establish(stream, Role::Responder).await.unwrap();
            drop(halves);
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let (_w, mut r) = establish(stream, Role::Initiator).await.unwrap();
        server.await.unwrap();
        assert!(matches!(r.recv().await, Err(Error::Closed)));
    }
}
