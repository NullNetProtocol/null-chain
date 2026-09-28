//! I2P support through a router's SAM v3 bridge.
//!
//! A node with `--i2p <sam address>` creates one transient SAM session at
//! startup and opens a stream through it for each `.i2p` peer, the way the
//! SOCKS5 path reaches `.onion` peers. The session's control socket is
//! held open for the node's lifetime; dropping it ends the session.
//!
//! SAM is a line protocol. Only the three commands a stream client needs
//! are implemented: `HELLO VERSION`, `SESSION CREATE` and `STREAM
//! CONNECT`. Replies are parsed for `RESULT=OK`; anything else is an
//! error carrying the reply.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Error, Result};

/// The router's SAM bridge address, when none is given.
pub const DEFAULT_SAM: &str = "127.0.0.1:7656";
/// SAM protocol versions this client accepts.
const VERSION_RANGE: &str = "MIN=3.0 MAX=3.3";
/// Longest reply line read, in bytes, so a hostile bridge cannot make the
/// node read forever.
const MAX_REPLY: usize = 4096;

/// Counter for unique session nicknames within a process.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A live SAM session. Holds the control socket so the session stays open;
/// each [`Self::connect`] opens a fresh stream against it.
#[derive(Debug)]
pub struct SamSession {
    sam_addr: SocketAddr,
    id: String,
    // Kept open for the session's lifetime; never read or written again.
    _control: TcpStream,
}

impl SamSession {
    /// Creates a transient SAM session on `sam_addr`.
    ///
    /// # Errors
    /// Fails if the bridge is unreachable or rejects the handshake.
    pub async fn create(sam_addr: SocketAddr) -> Result<Self> {
        let mut control = TcpStream::connect(sam_addr).await?;
        hello(&mut control).await?;
        let id = format!("coin{}", SESSION_COUNTER.fetch_add(1, Ordering::Relaxed));
        let reply = command(
            &mut control,
            &format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION=TRANSIENT SIGNATURE_TYPE=7"),
        )
        .await?;
        check_ok(&reply, "SESSION STATUS")?;
        Ok(Self {
            sam_addr,
            id,
            _control: control,
        })
    }

    /// Opens a stream to an I2P destination, a `.i2p` hostname or a full
    /// base64 destination. The returned stream carries application data.
    ///
    /// # Errors
    /// Fails if the bridge is unreachable or refuses the connection.
    pub async fn connect(&self, destination: &str) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(self.sam_addr).await?;
        hello(&mut stream).await?;
        let reply = command(
            &mut stream,
            &format!(
                "STREAM CONNECT ID={} DESTINATION={destination} SILENT=false",
                self.id
            ),
        )
        .await?;
        check_ok(&reply, "STREAM STATUS")?;
        Ok(stream)
    }
}

/// The I2P destination of a peer target: the host part, dropping any
/// `:port`, since I2P streams are not addressed by TCP port.
#[must_use]
pub fn destination_of(target: &str) -> &str {
    match target.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => target,
    }
}

/// Whether a peer target is an I2P address.
#[must_use]
pub fn is_i2p(target: &str) -> bool {
    let dest = destination_of(target);
    matches!(dest.len().checked_sub(4), Some(cut) if dest[cut..].eq_ignore_ascii_case(".i2p"))
}

async fn hello(stream: &mut TcpStream) -> Result<()> {
    let reply = command(stream, &format!("HELLO VERSION {VERSION_RANGE}")).await?;
    check_ok(&reply, "HELLO REPLY")
}

/// Writes one command line and reads one reply line.
async fn command(stream: &mut TcpStream, line: &str) -> Result<String> {
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    read_line(stream).await
}

/// Reads one `\n`-terminated line without buffering past it, so the
/// socket is left exactly at the start of the stream data.
async fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(Error::Argument("SAM bridge closed the connection".into()));
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_REPLY {
            return Err(Error::Argument("SAM reply too long".into()));
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).map_err(|_| Error::Argument("SAM reply not UTF-8".into()))
}

/// Checks a reply begins with `prefix` and carries `RESULT=OK`.
fn check_ok(reply: &str, prefix: &str) -> Result<()> {
    let rest = reply
        .strip_prefix(prefix)
        .ok_or_else(|| Error::Argument(format!("unexpected SAM reply: {reply}")))?;
    if rest.split_whitespace().any(|field| field == "RESULT=OK") {
        Ok(())
    } else {
        Err(Error::Argument(format!("SAM refused: {}", reply.trim())))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn targets_are_classified_and_stripped() {
        assert!(is_i2p("abcd.b32.i2p:0"));
        assert!(is_i2p("name.i2p"));
        assert!(!is_i2p("example.onion:8333"));
        assert!(!is_i2p("127.0.0.1:19000"));
        assert_eq!(destination_of("abcd.b32.i2p:0"), "abcd.b32.i2p");
        assert_eq!(destination_of("name.i2p"), "name.i2p");
    }

    #[test]
    fn replies_are_checked_for_ok() {
        assert!(check_ok("HELLO REPLY RESULT=OK VERSION=3.1", "HELLO REPLY").is_ok());
        assert!(check_ok("STREAM STATUS RESULT=OK", "STREAM STATUS").is_ok());
        assert!(check_ok("STREAM STATUS RESULT=CANT_REACH_PEER", "STREAM STATUS").is_err());
        assert!(check_ok("SESSION STATUS RESULT=OK", "HELLO REPLY").is_err());
    }

    /// A fake SAM bridge that speaks the handshake and then echoes the
    /// stream. Returns the destination it was asked to connect to.
    async fn fake_bridge(listener: TcpListener) -> String {
        // Session control socket.
        let (mut control, _) = listener.accept().await.unwrap();
        expect_line(&mut control, "HELLO VERSION").await;
        control
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            .await
            .unwrap();
        expect_line(&mut control, "SESSION CREATE STYLE=STREAM").await;
        control
            .write_all(b"SESSION STATUS RESULT=OK DESTINATION=abcdef\n")
            .await
            .unwrap();

        // Stream socket.
        let (mut stream, _) = listener.accept().await.unwrap();
        expect_line(&mut stream, "HELLO VERSION").await;
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            .await
            .unwrap();
        let connect = read_line(&mut stream).await.unwrap();
        stream
            .write_all(b"STREAM STATUS RESULT=OK\n")
            .await
            .unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        // Hold the control socket until the stream is done.
        drop(control);
        connect
            .split_whitespace()
            .find_map(|f| f.strip_prefix("DESTINATION="))
            .unwrap()
            .to_string()
    }

    async fn expect_line(stream: &mut TcpStream, prefix: &str) {
        let line = read_line(stream).await.unwrap();
        assert!(line.starts_with(prefix), "got {line:?}");
    }

    #[tokio::test]
    async fn a_session_connects_a_stream_and_carries_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sam = listener.local_addr().unwrap();
        let bridge = tokio::spawn(fake_bridge(listener));

        let session = SamSession::create(sam).await.unwrap();
        let mut stream = session.connect("peer.b32.i2p").await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        assert_eq!(bridge.await.unwrap(), "peer.b32.i2p");
    }

    #[tokio::test]
    async fn a_refused_bridge_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sam = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            while control.read_exact(&mut byte).await.is_ok() {
                if byte[0] == b'\n' {
                    break;
                }
            }
            control
                .write_all(b"HELLO REPLY RESULT=I2P_ERROR MESSAGE=nope\n")
                .await
                .unwrap();
        });
        assert!(SamSession::create(sam).await.is_err());
    }
}
