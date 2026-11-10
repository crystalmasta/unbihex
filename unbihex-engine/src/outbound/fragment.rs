//! TLS ClientHello fragmentation.
//!
//! The first flight (the ClientHello record) is cut into several TLS records of
//! random size, and each record goes out in its own TCP write (with TCP_NODELAY, so
//! each is its own segment) after a short pause, as `fragment` of Xray's freedom
//! does; with no pause (`interval` 0) they go out in one write, as Xray's `tlshello`
//! does. DPI that looks for the server name in the first segment or the first record
//! then sees only part of it. With `sni_split` one record boundary falls in the
//! middle of the server name (the records before it are still small, whatever the
//! browser's extension order puts in front of the name), so no record holds the
//! whole name. TLS allows a handshake
//! message to span records, so servers accept it.

use std::time::Duration;

use rand::Rng;
use serde::Deserialize;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// Fragmentation settings: sizes and pauses as `"from-to"` ranges.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FragmentConfig {
    /// Record payload sizes in bytes, e.g. `"100-200"`.
    #[serde(default = "default_length")]
    pub length: String,
    /// Pause between writes in milliseconds, e.g. `"10-20"`.
    #[serde(default = "default_interval")]
    pub interval: String,
    /// One record boundary falls exactly in the middle of the server name (SNI); the
    /// pieces around it are still cut by `length`. Without an SNI (a server by IP)
    /// the cut is as usual.
    #[serde(default)]
    pub sni_split: bool,
}

fn default_length() -> String {
    "100-200".into()
}

fn default_interval() -> String {
    "10-20".into()
}

impl Default for FragmentConfig {
    fn default() -> Self {
        FragmentConfig {
            length: default_length(),
            interval: default_interval(),
            sni_split: false,
        }
    }
}

fn range(s: &str, what: &str) -> Result<(u64, u64)> {
    let bad = || Error::config(format!("fragment {what}: expected \"from-to\", got {s:?}"));
    let (a, b) = match s.split_once('-') {
        Some((a, b)) => (a.trim().parse().map_err(|_| bad())?, b.trim().parse().map_err(|_| bad())?),
        None => {
            let v = s.trim().parse().map_err(|_| bad())?;
            (v, v)
        }
    };
    if a > b {
        return Err(bad());
    }
    Ok((a, b))
}

/// Offset, within a handshake record's body, of the middle of the server name of the
/// ClientHello it starts (at least one byte of the name on each side).
fn sni_middle(body: &[u8]) -> Option<usize> {
    let u16_at = |i: usize| -> Option<usize> {
        Some(usize::from(u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?])))
    };
    if *body.first()? != 0x01 {
        return None;
    }
    // type, length (3), version (2), random (32), session id.
    let mut p = 4 + 2 + 32;
    p += 1 + usize::from(*body.get(p)?);
    p += 2 + u16_at(p)?; // cipher suites
    p += 1 + usize::from(*body.get(p)?); // compression
    let end = (p + 2 + u16_at(p)?).min(body.len());
    p += 2;
    while p + 4 <= end {
        let (kind, len) = (u16_at(p)?, u16_at(p + 2)?);
        if kind == 0 {
            // server_name: list length (2), name type (1), name length (2), name.
            let name_len = u16_at(p + 4 + 3)?;
            let start = p + 4 + 5;
            if name_len < 2 || start + name_len > body.len() {
                return None;
            }
            return Some(start + name_len / 2);
        }
        p += 4 + len;
    }
    None
}

impl FragmentConfig {
    /// Checks the ranges.
    pub fn validate(&self) -> Result<()> {
        let (a, _) = range(&self.length, "length")?;
        if a == 0 {
            return Err(Error::config("fragment length must be at least 1"));
        }
        let (_, b) = range(&self.interval, "interval")?;
        if b > 5000 {
            return Err(Error::config("fragment interval must not exceed 5000 ms"));
        }
        Ok(())
    }

    /// Splits TLS records into smaller records (only handshake records are cut).
    pub fn split_records(&self, flight: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (min, max) = range(&self.length, "length")?;
        let mut rng = rand::thread_rng();
        let mut out = Vec::new();
        let mut rest = flight;
        let mut first = true;
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let Some(body) = rest.get(5..5 + len) else { break };
            let header = &rest[..3];
            if rest[0] != 0x16 {
                out.push(rest[..5 + len].to_vec());
            } else {
                // With `sni_split` the piece that would cross the middle of the
                // server name ends there.
                let cut = if first && self.sni_split { sni_middle(body) } else { None };
                first = false;
                let mut b = body;
                let mut at = 0;
                while !b.is_empty() {
                    let mut n = (rng.gen_range(min..=max) as usize).clamp(1, b.len());
                    if let Some(c) = cut.filter(|&c| at < c && c < at + n) {
                        n = c - at;
                    }
                    at += n;
                    let mut rec = Vec::with_capacity(5 + n);
                    rec.extend_from_slice(header);
                    rec.extend_from_slice(&(n as u16).to_be_bytes());
                    rec.extend_from_slice(&b[..n]);
                    out.push(rec);
                    b = &b[n..];
                }
            }
            rest = &rest[5 + len..];
        }
        if !rest.is_empty() {
            out.push(rest.to_vec());
        }
        Ok(out)
    }

    /// Writes the first flight in pieces, each its own TCP segment.
    pub async fn send(&self, tcp: &mut TcpStream, flight: &[u8]) -> Result<()> {
        // Without it the kernel may join the pieces into one segment.
        let _ = tcp.set_nodelay(true);
        self.write_pieces(tcp, flight).await
    }

    /// [`FragmentConfig::send`] over any writer: one write and flush per piece, a
    /// random pause from `interval` between them; with `interval` 0 one write.
    pub async fn write_pieces<W: AsyncWrite + Unpin>(&self, w: &mut W, flight: &[u8]) -> Result<()> {
        let (lo, hi) = range(&self.interval, "interval")?;
        let pieces = self.split_records(flight)?;
        if hi == 0 {
            w.write_all(&pieces.concat()).await?;
            w.flush().await?;
            return Ok(());
        }
        let last = pieces.len().saturating_sub(1);
        for (i, p) in pieces.iter().enumerate() {
            w.write_all(p).await?;
            w.flush().await?;
            if i < last {
                let ms = rand::thread_rng().gen_range(lo..=hi);
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn frag(length: &str, interval: &str, sni_split: bool) -> FragmentConfig {
        FragmentConfig { length: length.into(), interval: interval.into(), sni_split }
    }

    /// Payloads of the records, checking each header.
    fn bodies(parts: &[Vec<u8>]) -> Vec<&[u8]> {
        parts
            .iter()
            .map(|p| {
                assert_eq!(p[0], 0x16);
                let n = usize::from(u16::from_be_bytes([p[3], p[4]]));
                assert_eq!(p.len(), 5 + n);
                &p[5..]
            })
            .collect()
    }

    /// A real ClientHello for `name` (rustls's own, or a browser's).
    fn client_hello(name: &str, fingerprint: Option<&str>) -> Vec<u8> {
        let cfg = crate::config::TlsConfig {
            enabled: true,
            sni: Some(name.into()),
            alpn: Vec::new(),
            pinned_sha256: Vec::new(),
            allow_insecure: false,
            fingerprint: Some(fingerprint.unwrap_or("none").into()),
        };
        let client = super::super::tls::TlsClient::new(&cfg, name).unwrap();
        let server = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(client.client_config(), server).unwrap();
        let mut hello = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut hello).unwrap();
        }
        hello
    }

    #[test]
    fn records_are_split_and_rejoin() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x01, 0x2c];
        hello.extend((0..300u32).map(|i| i as u8));
        let parts = frag("40-60", "0", false).split_records(&hello).unwrap();
        assert!(parts.len() >= 5);
        let b = bodies(&parts);
        assert!(b.iter().all(|b| (1..=60).contains(&b.len())));
        assert_eq!(b.concat(), &hello[5..]);
        assert!(frag("0-5", "1", false).validate().is_err());
        assert!(frag("9-5", "1", false).validate().is_err());
        assert!(FragmentConfig::default().validate().is_ok());
    }

    /// `sni_split`: every piece is cut by `length`, and one boundary falls exactly in
    /// the middle of the name, wherever the browser put the extension.
    #[test]
    fn a_record_boundary_cuts_the_server_name() {
        let name = "very-long-server-name.example.com";
        for fp in [None, Some("chrome"), Some("firefox")] {
            for _ in 0..20 {
                let hello = client_hello(name, fp);
                let mid = hello.windows(name.len()).position(|w| w == name.as_bytes()).unwrap()
                    + name.len() / 2;
                let parts = frag("10-100", "0", true).split_records(&hello).unwrap();
                let b = bodies(&parts);
                assert_eq!(b.concat(), &hello[5..], "{fp:?}");
                assert!(b.iter().all(|b| (1..=100).contains(&b.len())), "{fp:?}");
                // The ends of the records, as offsets in the flight.
                let ends: Vec<usize> = b
                    .iter()
                    .scan(5, |end, b| {
                        *end += b.len();
                        Some(*end)
                    })
                    .collect();
                assert!(ends.contains(&mid), "{fp:?}: no boundary at {mid}");
                assert!(!b.iter().any(|b| b.windows(name.len()).any(|w| w == name.as_bytes())));
            }
        }
        // Without an SNI (a server by IP) the cut is the usual one.
        let hello = client_hello("192.0.2.1", None);
        let b = frag("10-20", "0", true).split_records(&hello).unwrap();
        assert!(bodies(&b).iter().all(|b| (1..=20).contains(&b.len())));
        // Not a ClientHello: nothing to find.
        assert_eq!(sni_middle(&[0x02, 0, 0, 1]), None);
        assert_eq!(sni_middle(&[]), None);
    }

    /// Records every write and flush with the (paused) clock.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<(tokio::time::Instant, Vec<u8>)>,
        flushes: usize,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes.push((tokio::time::Instant::now(), buf.to_vec()));
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.flushes += 1;
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// One write and flush per record, pauses from `interval` between them, none
    /// after the last; `interval` 0 is one write without a pause.
    #[tokio::test(start_paused = true)]
    async fn pieces_go_out_one_by_one_with_pauses() {
        let hello = client_hello("pause.example", Some("chrome"));
        let mut w = Recorder::default();
        let start = tokio::time::Instant::now();
        frag("10-100", "10-20", true).write_pieces(&mut w, &hello).await.unwrap();
        assert!(w.writes.len() > 10, "{} writes", w.writes.len());
        assert_eq!(w.flushes, w.writes.len());
        assert_eq!(w.writes[0].0, start, "the first piece goes at once");
        for pair in w.writes.windows(2) {
            let gap = pair[1].0 - pair[0].0;
            assert!((10..=20).contains(&gap.as_millis()), "{gap:?}");
        }
        let b: Vec<Vec<u8>> = w.writes.iter().map(|(_, b)| b.clone()).collect();
        assert_eq!(bodies(&b).concat(), &hello[5..]);
        assert_eq!(tokio::time::Instant::now(), w.writes.last().unwrap().0, "no pause after the last");

        let before = tokio::time::Instant::now();
        let mut w = Recorder::default();
        frag("10-100", "0", false).write_pieces(&mut w, &hello).await.unwrap();
        assert_eq!((w.writes.len(), w.flushes), (1, 1));
        assert_eq!(tokio::time::Instant::now(), before);
    }
}
