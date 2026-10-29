//! Destination names from the first bytes of a connection (SPEC §10.3): the server
//! name of a TLS ClientHello or the `Host` header of an HTTP request. The TUN uses
//! them for routing when an app connects to a real IP it resolved on its own
//! (browser DoH, AdGuard or an antivirus filtering DNS, cached answers), so domain
//! rules still apply.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::net::PrefixedStream;
use crate::outbound::BoxStream;

/// How long to wait for the client's first bytes.
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

/// The most read while looking for a name; a ClientHello with ECH and a
/// post-quantum key share fits well within it.
const MAX_SNIFF: usize = 16 * 1024;

/// Ports where the server speaks first (FTP, SMTP, POP3, IMAP, MySQL, VNC):
/// waiting for the client there would only add a delay.
const SERVER_FIRST: &[u16] = &[21, 25, 110, 143, 587, 3306, 5900];

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
];

/// What the bytes read so far tell.
#[derive(Debug, PartialEq, Eq)]
pub enum Sniff {
    /// A destination name.
    Name(String),
    /// Looks like TLS or HTTP, but the name is further on.
    Incomplete,
    /// Not TLS or HTTP, or no usable name.
    NotFound,
}

/// Looks for a destination name at the start of a client's stream.
pub fn sniff(buf: &[u8]) -> Sniff {
    match buf.first() {
        None => Sniff::Incomplete,
        Some(0x16) => tls_server_name(buf),
        Some(b) if b.is_ascii_uppercase() => http_host(buf),
        Some(_) => Sniff::NotFound,
    }
}

/// Reads the first bytes of `stream` (for at most [`SNIFF_TIMEOUT`]) and returns
/// the name found together with a stream that yields those bytes again.
pub async fn peek(mut stream: BoxStream, port: u16) -> (Option<String>, BoxStream) {
    if SERVER_FIRST.contains(&port) {
        return (None, stream);
    }
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let mut name = None;
    while buf.len() < MAX_SNIFF {
        let want = chunk.len().min(MAX_SNIFF - buf.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want])).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            // EOF, an error or silence: the relay sees the same when it reads on.
            _ => break,
        }
        match sniff(&buf) {
            Sniff::Name(n) => {
                name = Some(n);
                break;
            }
            Sniff::NotFound => break,
            Sniff::Incomplete => {}
        }
    }
    if buf.is_empty() {
        return (name, stream);
    }
    (name, Box::new(PrefixedStream::new(buf, stream)))
}

/// A usable host name: ASCII, not an IP literal, lowercased, without a trailing dot.
fn host_name(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?.trim().trim_end_matches('.');
    if s.is_empty()
        || s.len() > 253
        || s.parse::<IpAddr>().is_ok()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Splits `n` bytes off the front of `buf`.
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if buf.len() < n {
        return None;
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Some(head)
}

fn u8_len(buf: &mut &[u8]) -> Option<usize> {
    take(buf, 1).map(|b| usize::from(b[0]))
}

fn u16_len(buf: &mut &[u8]) -> Option<usize> {
    take(buf, 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
}

/// The server name of a ClientHello, which may span several TLS records.
fn tls_server_name(buf: &[u8]) -> Sniff {
    let mut handshake = Vec::new();
    let mut rest = buf;
    while rest.len() >= 5 {
        if rest[0] != 0x16 || rest[1] != 3 {
            break;
        }
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let end = (5 + len).min(rest.len());
        handshake.extend_from_slice(&rest[5..end]);
        rest = &rest[end..];
    }
    if handshake.len() < 4 {
        return if buf.len() < 5 || buf[1] == 3 {
            Sniff::Incomplete
        } else {
            Sniff::NotFound
        };
    }
    if handshake[0] != 1 {
        return Sniff::NotFound;
    }
    let len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if handshake.len() < 4 + len {
        return Sniff::Incomplete;
    }
    client_hello_name(&handshake[4..4 + len]).map_or(Sniff::NotFound, Sniff::Name)
}

fn client_hello_name(mut body: &[u8]) -> Option<String> {
    let buf = &mut body;
    take(buf, 2 + 32)?; // version, random
    let n = u8_len(buf)?;
    take(buf, n)?; // session id
    let n = u16_len(buf)?;
    take(buf, n)?; // cipher suites
    let n = u8_len(buf)?;
    take(buf, n)?; // compression methods
    let n = u16_len(buf)?;
    let mut exts = take(buf, n)?;
    while !exts.is_empty() {
        let kind = u16_len(&mut exts)?;
        let n = u16_len(&mut exts)?;
        let mut ext = take(&mut exts, n)?;
        if kind != 0 {
            continue;
        }
        let n = u16_len(&mut ext)?;
        let mut names = take(&mut ext, n)?;
        while !names.is_empty() {
            let name_type = u8_len(&mut names)?;
            let n = u16_len(&mut names)?;
            let name = take(&mut names, n)?;
            if name_type == 0 {
                return host_name(name);
            }
        }
    }
    None
}

/// The `Host` header of an HTTP/1.x request, without the port.
fn http_host(buf: &[u8]) -> Sniff {
    let method_ok = HTTP_METHODS.iter().any(|m| buf.starts_with(m));
    if !method_ok {
        let partial = HTTP_METHODS.iter().any(|m| m.starts_with(buf));
        return if partial { Sniff::Incomplete } else { Sniff::NotFound };
    }
    let mut lines = buf.split(|&b| b == b'\n');
    lines.next(); // the request line
    // The last piece has no newline yet: it may be cut off.
    let complete = buf.iter().filter(|&&b| b == b'\n').count();
    for line in lines.take(complete.saturating_sub(1)) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Sniff::NotFound; // end of headers
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(b"host") {
            continue;
        }
        let value = line[colon + 1..].trim_ascii();
        if value.starts_with(b"[") {
            return Sniff::NotFound; // an IPv6 literal
        }
        let host = match value.iter().rposition(|&b| b == b':') {
            Some(i) if value[i + 1..].iter().all(u8::is_ascii_digit) => &value[..i],
            _ => value,
        };
        return host_name(host).map_or(Sniff::NotFound, Sniff::Name);
    }
    Sniff::Incomplete
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ClientHello record for `name` (or without SNI).
    fn client_hello(name: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        // An unrelated extension first (supported_versions).
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if let Some(n) = name {
            let n = n.as_bytes();
            let list_len = n.len() + 3;
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(list_len as u16).to_be_bytes());
            exts.push(0);
            exts.extend_from_slice(&(n.len() as u16).to_be_bytes());
            exts.extend_from_slice(n);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_server_name_is_found() {
        let hello = client_hello(Some("WWW.YouTube.com"));
        assert_eq!(sniff(&hello), Sniff::Name("www.youtube.com".into()));
        assert_eq!(sniff(&client_hello(None)), Sniff::NotFound);
        assert_eq!(sniff(&client_hello(Some("1.2.3.4"))), Sniff::NotFound);
        // Cut off anywhere before the end: more bytes are needed.
        for cut in [1, 3, 5, 20, hello.len() - 1] {
            assert_eq!(sniff(&hello[..cut]), Sniff::Incomplete, "cut at {cut}");
        }
    }

    #[test]
    fn a_hello_split_into_records_is_joined() {
        let hello = client_hello(Some("example.org"));
        let hs = &hello[5..];
        let mut split = Vec::new();
        for part in [&hs[..10], &hs[10..]] {
            split.extend_from_slice(&[0x16, 0x03, 0x01]);
            split.extend_from_slice(&(part.len() as u16).to_be_bytes());
            split.extend_from_slice(part);
        }
        assert_eq!(sniff(&split), Sniff::Name("example.org".into()));
    }

    #[test]
    fn http_host_is_found() {
        let req = b"GET /x HTTP/1.1\r\nUser-Agent: t\r\nHost: Example.COM:8080\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Name("example.com".into()));
        assert_eq!(sniff(b"GE"), Sniff::Incomplete);
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHo"), Sniff::Incomplete);
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"), Sniff::NotFound);
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"), Sniff::NotFound);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n"), Sniff::NotFound);
        assert_eq!(sniff(&[0x00, 0x01, 0x02]), Sniff::NotFound);
    }

    #[tokio::test]
    async fn peeked_bytes_are_replayed() {
        let (mut app, ours) = tokio::io::duplex(64 * 1024);
        let hello = client_hello(Some("rutracker.org"));
        tokio::io::AsyncWriteExt::write_all(&mut app, &hello).await.unwrap();
        let (name, mut stream) = peek(Box::new(ours), 443).await;
        assert_eq!(name.as_deref(), Some("rutracker.org"));
        let mut again = vec![0; hello.len()];
        stream.read_exact(&mut again).await.unwrap();
        assert_eq!(again, hello);
    }

    #[tokio::test]
    async fn a_silent_client_costs_only_the_timeout() {
        let (_app, ours) = tokio::io::duplex(1024);
        let start = std::time::Instant::now();
        let (name, _) = peek(Box::new(ours), 443).await;
        assert!(name.is_none());
        assert!(start.elapsed() < SNIFF_TIMEOUT * 3);
        let (_app, ours) = tokio::io::duplex(1024);
        let start = std::time::Instant::now();
        let (name, _) = peek(Box::new(ours), 25).await;
        assert!(name.is_none());
        assert!(start.elapsed() < SNIFF_TIMEOUT / 2);
    }
}
