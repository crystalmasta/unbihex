//! TLS ClientHello fragmentation.
//!
//! The first flight (the ClientHello record) is cut into several TLS records of
//! random size, and each record goes out in its own TCP write after a short pause.
//! DPI that looks for the server name in the first segment or the first record
//! then sees only part of it. TLS allows a handshake message to span records, so
//! servers accept it.

use std::time::Duration;

use rand::Rng;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
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
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let Some(body) = rest.get(5..5 + len) else { break };
            let header = &rest[..3];
            if rest[0] != 0x16 {
                out.push(rest[..5 + len].to_vec());
            } else {
                let mut b = body;
                while !b.is_empty() {
                    let n = (rng.gen_range(min..=max) as usize).clamp(1, b.len());
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

    /// Writes the first flight in pieces.
    pub async fn send(&self, tcp: &mut TcpStream, flight: &[u8]) -> Result<()> {
        let (lo, hi) = range(&self.interval, "interval")?;
        let pieces = self.split_records(flight)?;
        let last = pieces.len().saturating_sub(1);
        for (i, p) in pieces.iter().enumerate() {
            tcp.write_all(p).await?;
            tcp.flush().await?;
            if i < last && hi > 0 {
                let ms = rand::thread_rng().gen_range(lo..=hi);
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_split_and_rejoin() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x01, 0x2c];
        hello.extend((0..300u32).map(|i| i as u8));
        let f = FragmentConfig {
            length: "40-60".into(),
            interval: "0".into(),
        };
        let parts = f.split_records(&hello).unwrap();
        assert!(parts.len() >= 5);
        let mut joined = Vec::new();
        for p in &parts {
            assert_eq!(&p[..3], &[0x16, 0x03, 0x01]);
            let n = usize::from(u16::from_be_bytes([p[3], p[4]]));
            assert!((1..=60).contains(&n));
            assert_eq!(p.len(), 5 + n);
            joined.extend_from_slice(&p[5..]);
        }
        assert_eq!(joined, &hello[5..]);
        assert!(FragmentConfig { length: "0-5".into(), interval: "1".into() }.validate().is_err());
        assert!(FragmentConfig { length: "9-5".into(), interval: "1".into() }.validate().is_err());
        assert!(FragmentConfig::default().validate().is_ok());
    }
}
