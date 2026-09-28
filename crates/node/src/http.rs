//! The smallest HTTP/1.1 server the JSON-RPC, faucet and metrics
//! endpoints need: read one request, answer one response, close.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Error, Result};

/// Largest request head (request line plus headers) accepted, in bytes.
pub const MAX_HEAD: usize = 8 * 1024;
/// Largest request accepted by the `GET`-only endpoints, in bytes.
pub const MAX_REQUEST: usize = 4096;

/// Header names lowercased, values trimmed, in arrival order.
pub type Headers = Vec<(String, String)>;

/// One parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `GET`, `POST`, ...
    pub method: String,
    /// The request target, such as `/metrics`.
    pub path: String,
    /// The headers.
    pub headers: Headers,
    /// The body, at most the caller's limit.
    pub body: Vec<u8>,
}

impl Request {
    /// The first header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Reads one request whose body may be up to `max_body` bytes.
///
/// # Errors
/// Fails on a socket error, a head over [`MAX_HEAD`], a malformed
/// request line, or a body over `max_body`.
pub async fn read_request(stream: &mut TcpStream, max_body: usize) -> Result<Request> {
    let mut buffer = Vec::new();
    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() >= MAX_HEAD {
            return Err(Error::Argument("request head too large".into()));
        }
        let mut chunk = vec![0u8; MAX_HEAD.saturating_sub(buffer.len()).min(1024)];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Argument("connection closed".into()));
        }
        buffer.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    };
    let head = String::from_utf8_lossy(buffer.get(..head_end).unwrap_or(&[])).into_owned();
    let (method, path, headers) = parse_head(&head)?;
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map(|(_, v)| v.parse())
        .transpose()
        .map_err(|_| Error::Argument("bad content length".into()))?
        .unwrap_or(0);
    if length > max_body {
        return Err(Error::Argument("request body too large".into()));
    }
    let mut body: Vec<u8> = buffer
        .get(head_end.saturating_add(4)..)
        .unwrap_or(&[])
        .to_vec();
    if body.len() > length {
        body.truncate(length);
    }
    while body.len() < length {
        let mut chunk = vec![0u8; length.saturating_sub(body.len()).min(64 * 1024)];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Argument("connection closed".into()));
        }
        body.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

/// Where the blank line ending the head starts, if it has arrived.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Splits the request line and headers.
fn parse_head(head: &str) -> Result<(String, String, Headers)> {
    let mut lines = head.lines();
    let line = lines
        .next()
        .ok_or_else(|| Error::Argument("empty request".into()))?;
    let mut words = line.split(' ');
    let method = words
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| Error::Argument("bad request line".into()))?;
    let path = words
        .next()
        .ok_or_else(|| Error::Argument("bad request line".into()))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok((method.to_string(), path.to_string(), headers))
}

/// Reads one request and returns the path of its `GET` line, if any.
///
/// # Errors
/// Fails on a socket error.
pub async fn read_get_path(stream: &mut TcpStream) -> Result<Option<String>> {
    match read_request(stream, MAX_REQUEST).await {
        Ok(request) => Ok((request.method == "GET").then_some(request.path)),
        Err(Error::Io(error)) => Err(Error::Io(error)),
        Err(_) => Ok(None),
    }
}

/// Writes a plain-text response and closes.
///
/// # Errors
/// Fails on a socket error.
pub async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    respond_with(stream, status, "text/plain; version=0.0.4", body.as_bytes()).await
}

/// Writes a response with the given content type and closes.
///
/// # Errors
/// Fails on a socket error.
pub async fn respond_with(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn heads_parse_into_method_path_and_lowercased_headers() {
        let (method, path, headers) =
            parse_head("POST /rpc HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n").unwrap();
        assert_eq!((method.as_str(), path.as_str()), ("POST", "/rpc"));
        assert_eq!(headers[1], ("content-length".to_string(), "12".to_string()));
        assert!(parse_head("").is_err());
        assert!(parse_head("GET").is_err());
    }

    #[tokio::test]
    async fn requests_with_bodies_are_read_whole_and_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_request(&mut stream, 16).await;
            respond(&mut stream, "200 OK", "hi").await.unwrap();
            first
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"POST /rpc HTTP/1.1\r\nAuthorization: Bearer t\r\nContent-Length: 5\r\n\r\nhel",
            )
            .await
            .unwrap();
        client.write_all(b"lo").await.unwrap();
        let request = server.await.unwrap().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.header("authorization"), Some("Bearer t"));
        assert_eq!(request.body, b"hello");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(reply.ends_with("\r\n\r\nhi"));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream, 4).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();
        assert!(server.await.unwrap().is_err(), "body over the limit");
    }

    #[tokio::test]
    async fn get_paths_come_from_get_lines_only() {
        for (raw, expected) in [
            (
                &b"GET /pay/coin1abc HTTP/1.1\r\nHost: x\r\n\r\n"[..],
                Some("/pay/coin1abc"),
            ),
            (&b"POST /pay/x HTTP/1.1\r\n\r\n"[..], None),
            (&b"garbage"[..], None),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_get_path(&mut stream).await.unwrap()
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(raw).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(server.await.unwrap().as_deref(), expected);
        }
    }
}
