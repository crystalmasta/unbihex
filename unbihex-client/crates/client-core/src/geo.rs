//! Rule databases (`geosite.dat`, `geoip.dat`): download, check and paths for the
//! engine config.

use std::path::{Path, PathBuf};
use std::time::Duration;

use unbihex_engine::rules::geodata::list_codes;

use crate::error::{ClientError, Result};
use crate::model::{GeoStatus, Settings, now_secs};
use tokio::io::AsyncWriteExt;

use crate::subscription::{is_safe_url, redirect_policy, request_error};

/// Lists maintained for Russia (based on v2fly, plus blocked/inside-only lists).
pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat";
/// Matching geoip database.
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat";

/// Refresh interval for automatic updates.
pub const UPDATE_EVERY: u64 = 7 * 24 * 3600;

/// Where the databases live and what they contain.
#[derive(Clone, Debug, Default)]
pub struct Geo {
    /// `geosite.dat`, when downloaded.
    pub geosite: Option<PathBuf>,
    /// `geoip.dat`, when downloaded.
    pub geoip: Option<PathBuf>,
    /// Available categories (lowercase).
    pub sites: Vec<String>,
    /// Available codes (lowercase).
    pub ips: Vec<String>,
}

impl Geo {
    /// Paths in `dir` plus the recorded contents.
    pub fn from_status(dir: &Path, status: &GeoStatus) -> Geo {
        let site = dir.join("geosite.dat");
        let ip = dir.join("geoip.dat");
        Geo {
            geosite: site.exists().then_some(site),
            geoip: ip.exists().then_some(ip),
            sites: status.sites.clone(),
            ips: status.ips.clone(),
        }
    }

    /// Whether the geosite file has `name` (ignoring an `@attr` suffix).
    pub fn has_site(&self, name: &str) -> bool {
        let base = name.split('@').next().unwrap_or(name).to_ascii_lowercase();
        self.geosite.is_some() && self.sites.contains(&base)
    }

    /// Whether the geoip file has `code`.
    pub fn has_ip(&self, code: &str) -> bool {
        self.geoip.is_some() && self.ips.contains(&code.to_ascii_lowercase())
    }
}

/// Largest database file (runetfreedom's geosite.dat was about 74 MB in October 2026).
const MAX_FILE: u64 = 256 << 20;

async fn download(url: &str, dest: &Path) -> Result<()> {
    let parsed = url::Url::parse(url.trim())
        .map_err(|_| ClientError::Subscription(format!("{url}: неверный адрес")))?;
    if !is_safe_url(&parsed) {
        return Err(ClientError::Subscription(format!(
            "{url}: базы правил можно скачивать только по https://"
        )));
    }
    let client = reqwest::Client::builder()
        // HTTP(S)_PROXY or system proxies may point at our own or a dead local port; TUN captures us when connected.
        .no_proxy()
        // A stalled transfer fails; a slow one may take its time over a large file.
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30 * 60))
        .connect_timeout(Duration::from_secs(15))
        .user_agent(crate::model::DEFAULT_USER_AGENT)
        .redirect(redirect_policy())
        .build()
        .map_err(|e| ClientError::Subscription(e.to_string()))?;
    let mut resp = client
        .get(parsed)
        .send()
        .await
        .map_err(|e| ClientError::Subscription(format!("{url}: {}", request_error(&e))))?;
    if !resp.status().is_success() {
        return Err(ClientError::Subscription(format!("{url}: HTTP {}", resp.status())));
    }
    let too_large = || ClientError::Subscription(format!("{url}: файл больше {} МБ", MAX_FILE >> 20));
    if resp.content_length().is_some_and(|n| n > MAX_FILE) {
        return Err(too_large());
    }
    // Straight to disk: the file is large, and phones should not hold it in memory.
    let mut file = tokio::fs::File::create(dest).await?;
    let mut written = 0u64;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ClientError::Subscription(format!("{url}: {e}")))?
    {
        written += chunk.len() as u64;
        if written > MAX_FILE {
            return Err(too_large());
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    if written < 16 {
        return Err(ClientError::Subscription(format!("{url}: пустой файл")));
    }
    Ok(())
}

/// Downloads both files, checks them and replaces the old ones atomically.
pub async fn update(dir: &Path, settings: &Settings) -> Result<GeoStatus> {
    let site_tmp = dir.join("geosite.dat.part");
    let ip_tmp = dir.join("geoip.dat.part");
    download(&settings.geosite_url, &site_tmp).await?;
    download(&settings.geoip_url, &ip_tmp).await?;
    let (sites, ips) = {
        let (s, i) = (site_tmp.clone(), ip_tmp.clone());
        tokio::task::spawn_blocking(move || -> Result<(Vec<String>, Vec<String>)> {
            let sites = list_codes(&s).map_err(|e| ClientError::Subscription(format!("geosite.dat: {e}")))?;
            let ips = list_codes(&i).map_err(|e| ClientError::Subscription(format!("geoip.dat: {e}")))?;
            Ok((sites, ips))
        })
        .await
        .map_err(|e| ClientError::State(e.to_string()))??
    };
    if sites.is_empty() || ips.is_empty() {
        return Err(ClientError::Subscription("базы правил пустые или повреждены".into()));
    }
    tokio::fs::rename(&site_tmp, dir.join("geosite.dat")).await?;
    tokio::fs::rename(&ip_tmp, dir.join("geoip.dat")).await?;
    Ok(GeoStatus {
        updated_at: Some(now_secs()),
        sites,
        ips,
        last_error: None,
    })
}

/// Whether an automatic update is due.
pub fn is_due(status: &GeoStatus, now: u64) -> bool {
    status
        .updated_at
        .is_none_or(|t| now.saturating_sub(t) >= UPDATE_EVERY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_http_is_refused() {
        let dest = std::env::temp_dir().join(format!("unbihex-geo-{}", uuid::Uuid::new_v4()));
        let e = download("http://example.com/geosite.dat", &dest).await.unwrap_err();
        assert!(e.to_string().contains("только по https://"), "{e}");
        assert!(!dest.exists());
    }
}
