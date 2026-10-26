//! The small part of HTTP/1.1 that XHTTP needs: requests with a fixed-size
//! body, and responses with a fixed-size, chunked or close-delimited body.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

const MAX_HEAD: usize = 16 * 1024;

/// Writes a request head (and body, if any).
pub async fn write_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    method: &str,
    target: &str,
    host: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<()> {
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    if let Some(b) = body {
        out.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if let Some(b) = body {
        bytes.extend_from_slice(b);
    }
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// How a response body ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyKind {
    /// `Content-Length`.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Until the connection closes.
    Close,
}

/// A parsed response head.
#[derive(Debug)]
pub struct Head {
    /// Status code.
    pub status: u16,
    /// Body framing.
    pub body: BodyKind,
    /// The server will close the connection.
    pub close: bool,
}

async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, total: &mut usize) -> Result<String> {
    let mut line = Vec::new();
    let n = r.read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(Error::protocol("xhttp: connection closed"));
    }
    *total += n;
    if *total > MAX_HEAD {
        return Err(Error::protocol("xhttp: response head too large"));
    }
    while line.last().is_some_and(|c| *c == b'\n' || *c == b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| Error::protocol("xhttp: bad response head"))
}

/// Reads a response head.
pub async fn read_head<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<Head> {
    let mut total = 0;
    let status_line = read_line(r, &mut total).await?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(Error::protocol("xhttp: not an HTTP/1.1 response"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::protocol("xhttp: bad status line"))?;
    let mut body = BodyKind::Close;
    let mut close = version == "HTTP/1.0";
    loop {
        let line = read_line(r, &mut total).await?;
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(Error::protocol("xhttp: bad header line"));
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            if body != BodyKind::Chunked {
                let n = v
                    .parse()
                    .map_err(|_| Error::protocol("xhttp: bad Content-Length"))?;
                body = BodyKind::Length(n);
            }
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            if v.to_ascii_lowercase().contains("chunked") {
                body = BodyKind::Chunked;
            }
        } else if k.eq_ignore_ascii_case("connection") {
            close = v.eq_ignore_ascii_case("close");
        }
    }
    // 1xx, 204 and 304 have no body.
    if status < 200 || status == 204 || status == 304 {
        body = BodyKind::Length(0);
    }
    if body == BodyKind::Close {
        close = true;
    }
    Ok(Head { status, body, close })
}

async fn put<W: AsyncWrite + Unpin>(w: &mut Option<&mut W>, data: &[u8]) -> Result<()> {
    if let Some(w) = w.as_mut() {
        w.write_all(data).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Streams a body into `w` (`w = None` discards it).
pub async fn copy_body<R, W>(r: &mut R, kind: BodyKind, mut w: Option<&mut W>) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    match kind {
        BodyKind::Length(mut left) => {
            while left > 0 {
                let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                let n = r.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(Error::protocol("xhttp: body cut short"));
                }
                put(&mut w, &buf[..n]).await?;
                left -= n as u64;
            }
        }
        BodyKind::Close => loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            put(&mut w, &buf[..n]).await?;
        },
        BodyKind::Chunked => loop {
            let mut total = 0;
            let line = read_line(r, &mut total).await?;
            let size_hex = line.split(';').next().unwrap_or_default().trim();
            let mut left = u64::from_str_radix(size_hex, 16)
                .map_err(|_| Error::protocol("xhttp: bad chunk size"))?;
            if left == 0 {
                // Trailers, then an empty line.
                while !read_line(r, &mut total).await?.is_empty() {}
                break;
            }
            while left > 0 {
                let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                let n = r.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(Error::protocol("xhttp: chunk cut short"));
                }
                put(&mut w, &buf[..n]).await?;
                left -= n as u64;
            }
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(Error::protocol("xhttp: bad chunk end"));
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn chunked_and_length_bodies() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: y\r\n\r\n3\r\nabc\r\n2;ext\r\nde\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 400 Bad\r\nConnection: close\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let h = read_head(&mut r).await.unwrap();
        assert_eq!((h.status, h.body, h.close), (200, BodyKind::Chunked, false));
        let mut out = Vec::new();
        copy_body(&mut r, h.body, Some(&mut out)).await.unwrap();
        assert_eq!(out, b"abcde");
        let h = read_head(&mut r).await.unwrap();
        assert_eq!(h.body, BodyKind::Length(2));
        copy_body::<_, Vec<u8>>(&mut r, h.body, None).await.unwrap();
        let h = read_head(&mut r).await.unwrap();
        assert_eq!((h.status, h.close), (400, true));

        let mut w = Vec::new();
        write_request(&mut w, "POST", "/p/1/0", "h", &[("A".into(), "b".into())], Some(b"xy"))
            .await
            .unwrap();
        assert_eq!(w, b"POST /p/1/0 HTTP/1.1\r\nHost: h\r\nA: b\r\nContent-Length: 2\r\n\r\nxy");
    }
}
