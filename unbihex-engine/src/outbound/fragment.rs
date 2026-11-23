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
            if rest[0] != 0x16 || body.is_empty() {
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
            trusted_sha256: Vec::new(),
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

    // ---- property-based tests (fixed seed) ----

    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    fn runner(cases: u32) -> TestRunner {
        let cfg = Config { cases, failure_persistence: None, ..Config::default() };
        TestRunner::new_with_rng(cfg, TestRng::from_seed(RngAlgorithm::ChaCha, &[7u8; 32]))
    }

    /// A synthetic ClientHello handshake body (no record header) with an SNI
    /// extension in the middle (`name` None: no SNI extension).
    fn hello_body(name: Option<&[u8]>, session_id: usize, pad_before: usize, pad_after: usize) -> Vec<u8> {
        let mut b = vec![0x01, 0, 0, 0, 0x03, 0x03];
        b.extend([0x11; 32]);
        b.push(session_id as u8);
        b.extend(vec![0x22; session_id]);
        b.extend([0, 4, 0x13, 0x01, 0x13, 0x02]);
        b.extend([1, 0]);
        let mut ext = Vec::new();
        ext.extend([0x00, 0x0a, (pad_before >> 8) as u8, pad_before as u8]);
        ext.extend(vec![0x33; pad_before]);
        if let Some(n) = name {
            let l = n.len();
            ext.extend([0, 0, ((l + 5) >> 8) as u8, (l + 5) as u8]);
            ext.extend([((l + 3) >> 8) as u8, (l + 3) as u8, 0, (l >> 8) as u8, l as u8]);
            ext.extend(n);
        }
        ext.extend([0x00, 0x15, (pad_after >> 8) as u8, pad_after as u8]);
        ext.extend(vec![0x44; pad_after]);
        b.extend([(ext.len() >> 8) as u8, ext.len() as u8]);
        b.extend(ext);
        let l = b.len() - 4;
        b[1..4].copy_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        b
    }

    fn record(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![ty, 0x03, 0x01, (body.len() >> 8) as u8, body.len() as u8];
        r.extend(body);
        r
    }

    type Rec = (u8, [u8; 2], Vec<u8>);

    /// Parses a flight into (type, version, body) records plus a tail.
    fn parse(mut f: &[u8]) -> (Vec<Rec>, Vec<u8>) {
        let mut v = Vec::new();
        while f.len() >= 5 {
            let n = usize::from(u16::from_be_bytes([f[3], f[4]]));
            if f.len() < 5 + n {
                break;
            }
            v.push((f[0], [f[1], f[2]], f[5..5 + n].to_vec()));
            f = &f[5 + n..];
        }
        (v, f.to_vec())
    }

    /// Merges neighbouring records with the same type and version.
    fn collapse(v: Vec<Rec>) -> Vec<Rec> {
        let mut out: Vec<Rec> = Vec::new();
        for r in v {
            match out.last_mut() {
                Some(l) if l.0 == r.0 && l.1 == r.1 => l.2.extend(r.2),
                _ => out.push(r),
            }
        }
        out
    }

    fn payload(parts: &[Vec<u8>]) -> Vec<u8> {
        parse(&parts.concat()).0.into_iter().flat_map(|r| r.2).collect()
    }

    fn length_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            (1u32..300, 0u32..300).prop_map(|(a, d)| format!("{a}-{}", a + d)),
            (1u32..20000).prop_map(|a| a.to_string()),
            (1u32..40, 0u32..70000).prop_map(|(a, d)| format!("{a}-{}", a + d)),
        ]
    }

    /// Any flight of records (handshake and others, 1..=16384 bytes) splits
    /// into records that, merged per type, give the original bytes; headers are
    /// valid and no record exceeds 2^14.
    #[test]
    fn prop_split_rejoins_and_headers_valid() {
        let strat = (
            length_strategy(),
            any::<bool>(),
            proptest::collection::vec(
                (prop_oneof![Just(0x16u8), Just(0x16u8), Just(0x14u8), Just(0x17u8)], 1usize..16385, any::<u8>()),
                0..4,
            ),
            proptest::collection::vec(any::<u8>(), 0..8),
        );
        runner(300)
            .run(&strat, |(length, sni_split, recs, tail)| {
                let mut flight = Vec::new();
                for (ty, n, seed) in &recs {
                    let body: Vec<u8> = (0..*n).map(|i| (i as u8).wrapping_add(*seed)).collect();
                    flight.extend(record(*ty, &body));
                }
                flight.extend(tail.iter().take(4));
                let parts = frag(&length, "0", sni_split).split_records(&flight).unwrap();
                let (orig, otail) = parse(&flight);
                let (got, gtail) = parse(&parts.concat());
                prop_assert_eq!(otail, gtail.clone());
                prop_assert_eq!(collapse(orig), collapse(got));
                let whole = parts.len() - usize::from(!gtail.is_empty());
                for p in &parts[..whole] {
                    prop_assert!(p.len() >= 5);
                    let n = usize::from(u16::from_be_bytes([p[3], p[4]]));
                    prop_assert_eq!(p.len(), 5 + n);
                    prop_assert!(n <= 1 << 14);
                    prop_assert_eq!(&p[1..3], &[0x03, 0x01][..]);
                }
                Ok(())
            })
            .unwrap();
    }

    /// `sni_split` over synthetic hellos with names of 2..=253 chars: the
    /// payload is intact and a boundary is exactly in the middle of the name.
    #[test]
    fn prop_sni_split_cuts_inside_name() {
        let strat = (
            proptest::collection::vec(prop_oneof![97u8..123, Just(b'.'), Just(b'-')], 2..=253),
            0usize..33,
            0usize..600,
            0usize..600,
            (1u32..200, 0u32..200),
        );
        runner(400)
            .run(&strat, |(name, sid, before, after, (a, d))| {
                let body = hello_body(Some(&name), sid, before, after);
                let flight = record(0x16, &body);
                let mid = flight.windows(name.len()).position(|w| w == &name[..]).unwrap() + name.len() / 2;
                let parts = frag(&format!("{a}-{}", a + d), "0", true).split_records(&flight).unwrap();
                prop_assert_eq!(payload(&parts), body);
                let mut end = 5;
                let mut cut = false;
                for p in &parts {
                    end += p.len() - 5;
                    cut |= end == mid;
                    prop_assert!(!p[5..].windows(name.len()).any(|w| w == &name[..]));
                }
                prop_assert!(cut, "no boundary at {}", mid);
                Ok(())
            })
            .unwrap();
    }

    /// Short names (1-3 chars), no SNI, empty name, IP-like name: no panic,
    /// bytes preserved, a boundary inside the name when it has 2+ chars.
    #[test]
    fn sni_edge_cases() {
        let cases: Vec<Option<Vec<u8>>> = vec![
            None,
            Some(b"a".to_vec()),
            Some(b"ab".to_vec()),
            Some(b"abc".to_vec()),
            Some(b"192.0.2.1".to_vec()),
            Some(vec![b'x'; 253]),
            Some(Vec::new()),
        ];
        for name in cases {
            let body = hello_body(name.as_deref(), 32, 10, 10);
            let flight = record(0x16, &body);
            for len in ["1", "1-3", "100-200", "20000"] {
                let parts = frag(len, "0", true).split_records(&flight).unwrap();
                assert_eq!(payload(&parts), body);
                if let Some(n) = name.as_ref().filter(|n| n.len() >= 2) {
                    let mid = flight.windows(n.len()).position(|w| w == &n[..]).unwrap() + n.len() / 2;
                    let mut end = 5;
                    let hit = parts.iter().any(|p| {
                        end += p.len() - 5;
                        end == mid
                    });
                    assert!(hit, "{len}: no boundary in {:?}", String::from_utf8_lossy(n));
                }
            }
        }
    }

    /// Garbage and mutated ClientHellos never panic; unparseable tails are
    /// returned unchanged.
    #[test]
    fn prop_garbage_never_panics() {
        let strat = (
            proptest::collection::vec(any::<u8>(), 0..400),
            any::<bool>(),
            any::<usize>(),
            any::<u8>(),
            0usize..700,
        );
        runner(1500)
            .run(&strat, |(raw, sni_split, pos, val, trunc)| {
                let f = frag("1-50", "0", sni_split);
                let _ = sni_middle(&raw);
                let parts = f.split_records(&raw).unwrap();
                let (o, ot) = parse(&raw);
                let (g, gt) = parse(&parts.concat());
                prop_assert_eq!(ot, gt);
                if !o.iter().any(|r| r.2.is_empty()) {
                    prop_assert_eq!(collapse(o), collapse(g));
                }
                let mut hello = record(0x16, &hello_body(Some(b"mutate.example"), 32, 5, 5));
                let i = pos % hello.len();
                hello[i] = val;
                hello.truncate(hello.len().saturating_sub(trunc % 64));
                let _ = sni_middle(&hello[5.min(hello.len())..]);
                let _ = f.split_records(&hello).unwrap();
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn truncated_record_is_passed_as_is() {
        let hello = record(0x16, &hello_body(Some(b"trunc.example"), 32, 5, 5));
        for cut in 0..hello.len() {
            let parts = frag("5-10", "0", true).split_records(&hello[..cut]).unwrap();
            assert_eq!(parts.concat(), &hello[..cut], "cut {cut}");
        }
    }

    /// A ClientHello across several records: all are cut, order is kept.
    #[test]
    fn multi_record_hello_keeps_all_bytes() {
        let body = hello_body(Some(b"multi.example.com"), 32, 20000, 10);
        let flight: Vec<u8> = body.chunks(16384).flat_map(|c| record(0x16, c)).collect();
        let parts = frag("100-300", "0", true).split_records(&flight).unwrap();
        let (recs, tail) = parse(&parts.concat());
        assert!(tail.is_empty());
        assert_eq!(payload(&parts), body);
        assert!(recs.iter().all(|r| r.0 == 0x16 && r.2.len() <= 300));
    }

    /// An empty handshake record is valid TLS framing and must not vanish.
    #[test]
    fn zero_length_handshake_record_is_kept() {
        let flight = [0x16, 0x03, 0x01, 0x00, 0x00];
        let parts = frag("10-20", "0", false).split_records(&flight).unwrap();
        assert_eq!(parts.concat(), flight);
    }

    /// The pauses are async sleeps: other tasks on the same single-thread
    /// runtime keep running while pieces are being sent.
    #[tokio::test(flavor = "current_thread")]
    async fn pauses_do_not_block_the_runtime() {
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                t.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let hello = record(0x16, &hello_body(Some(b"block.example"), 32, 0, 0));
        let mut w = Recorder::default();
        let start = std::time::Instant::now();
        frag("10-20", "10-10", false).write_pieces(&mut w, &hello).await.unwrap();
        let spent = start.elapsed();
        ticker.abort();
        let n = ticks.load(std::sync::atomic::Ordering::Relaxed);
        assert!(w.writes.len() >= 4);
        assert!(spent >= Duration::from_millis(10 * (w.writes.len() as u64 - 1)));
        // Windows timers tick at ~15 ms, so only demand a few ticks (a blocked
        // runtime gives none).
        assert!(n >= 3, "only {n} ticks in {spent:?}");
    }
}
