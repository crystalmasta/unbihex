//! Updates from inside the app (issue #54): the latest release of
//! `crystalmasta/unbihex` on GitHub (HTTPS only), compared with this build by
//! semver; the installer for this device is downloaded only on request and
//! checked against `SHA256SUMS.txt` of the same release before use.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ClientError, Result};

/// The only release source.
pub const LATEST_URL: &str = "https://api.github.com/repos/crystalmasta/unbihex/releases/latest";
/// Where release files may be downloaded from (GitHub redirects them further,
/// over HTTPS only).
const DOWNLOAD_PREFIX: &str = "https://github.com/crystalmasta/unbihex/releases/download/";
/// The automatic check runs at most this often.
pub const CHECK_EVERY: u64 = 24 * 3600;
/// Changelog shown in the app, characters.
const NOTES_MAX: usize = 6000;
/// The largest installer accepted.
const FILE_MAX: usize = 300 << 20;

/// This build's version.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A release as the app shows it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Release {
    /// Version without the leading `v`.
    pub version: String,
    /// Release page.
    pub url: String,
    /// The changelog as plain text (HTML tags removed).
    pub notes: String,
    /// Files of the release.
    #[serde(skip)]
    pub assets: Vec<Asset>,
}

/// A release file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Asset {
    /// File name.
    pub name: String,
    /// Download address.
    pub url: String,
}

/// The result of a check.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateInfo {
    /// This build.
    pub current: String,
    /// The latest release.
    pub latest: Release,
    /// The latest release is newer than this build.
    pub newer: bool,
    /// The installer for this device is in the release: "Обновить" can install it.
    pub installable: bool,
}

/// What the last successful check found, kept in `update.json` next to
/// `state.json`: the automatic check runs at most once a day across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    /// Unix seconds of the last successful check.
    pub checked_at: u64,
    /// What it found.
    pub info: Option<UpdateInfo>,
}

impl Cache {
    const FILE: &str = "update.json";

    /// The saved check; "newer" is compared again with this build (it may have
    /// been updated since).
    pub fn load(dir: &Path) -> Cache {
        let mut c: Cache = std::fs::read(dir.join(Self::FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if let Some(info) = &mut c.info {
            info.current = CURRENT.into();
            info.newer = compare(&info.latest.version, CURRENT) == Some(Ordering::Greater);
            info.installable &= info.newer;
        }
        c
    }

    /// Writes the check next to `state.json`; a failure only costs an extra check.
    pub fn save(&self, dir: &Path) {
        if let Ok(json) = serde_json::to_vec_pretty(self)
            && let Err(e) = std::fs::write(dir.join(Self::FILE), json)
        {
            tracing::debug!("update.json: {e}");
        }
    }

    /// Whether the automatic check is due at `now` (Unix seconds).
    pub fn due(&self, now: u64) -> bool {
        self.checked_at > now || now - self.checked_at >= CHECK_EVERY
    }
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// What this device installs: the file name suffix in the release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Package {
    /// `…-android-arm64.apk`.
    AndroidArm64,
    /// `…-android-armv7.apk`.
    AndroidArmv7,
    /// `…-windows-setup.exe`.
    WindowsSetup,
}

impl Package {
    /// The package for this build, if the app can install it itself.
    pub fn this_device() -> Option<Package> {
        if cfg!(target_os = "android") {
            if cfg!(target_arch = "aarch64") {
                Some(Package::AndroidArm64)
            } else if cfg!(target_arch = "arm") {
                Some(Package::AndroidArmv7)
            } else {
                None
            }
        } else if cfg!(windows) {
            Some(Package::WindowsSetup)
        } else {
            None
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Package::AndroidArm64 => "-android-arm64.apk",
            Package::AndroidArmv7 => "-android-armv7.apk",
            Package::WindowsSetup => "-windows-setup.exe",
        }
    }

    /// The file of this package in `release`.
    pub fn asset(self, release: &Release) -> Option<&Asset> {
        release.assets.iter().find(|a| a.name.ends_with(self.suffix()) && a.name.starts_with("Unbihex-"))
    }
}

/// Parses the GitHub answer.
pub fn parse_release(json: &[u8]) -> Result<Release> {
    let r: GhRelease = serde_json::from_slice(json).map_err(|e| ClientError::Update(format!("ответ GitHub не разобран: {e}")))?;
    if r.draft || r.prerelease {
        return Err(ClientError::Update("последний релиз — черновик или предварительный".into()));
    }
    let version = r.tag_name.trim().trim_start_matches(['v', 'V']).to_owned();
    if parse_version(&version).is_none() {
        return Err(ClientError::Update(format!("непонятная версия релиза «{}»", r.tag_name)));
    }
    Ok(Release {
        version,
        url: if r.html_url.starts_with("https://github.com/crystalmasta/unbihex/") { r.html_url } else { String::new() },
        notes: plain_text(r.body.as_deref().unwrap_or_default()),
        assets: r
            .assets
            .into_iter()
            .filter(|a| a.browser_download_url.starts_with(DOWNLOAD_PREFIX))
            .map(|a| Asset { name: a.name, url: a.browser_download_url })
            .collect(),
    })
}

/// `(major, minor, patch, pre-release)`; `None` for anything else.
fn parse_version(v: &str) -> Option<(u64, u64, u64, Option<String>)> {
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) if !p.is_empty() => (c, Some(p.to_owned())),
        Some(_) => return None,
        None => (v, None),
    };
    let mut parts = core.split('.');
    let mut num = || -> Option<u64> { parts.next().map_or(Some(0), |p| p.parse().ok()) };
    let (a, b, c) = (num()?, num()?, num()?);
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, pre))
}

/// Semver order of `a` and `b`; `None` when one is not a version.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (parse_version(a)?, parse_version(b)?);
    let core = (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2));
    if core != Ordering::Equal {
        return Some(core);
    }
    Some(match (&a.3, &b.3) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => compare_pre(x, y),
    })
}

fn compare_pre(a: &str, b: &str) -> Ordering {
    let mut x = a.split('.');
    let mut y = b.split('.');
    loop {
        match (x.next(), y.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(p), Some(q)) => {
                let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    _ => p.cmp(q),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

/// The changelog without HTML: tags dropped, the common entities decoded,
/// runs of blank lines collapsed, cut to [`NOTES_MAX`] characters.
pub fn plain_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_tag = false;
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("\r\n", "\n");
    let mut text = String::new();
    let mut blank = 0;
    for line in out.lines() {
        if line.trim().is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    let text = text.trim();
    match text.char_indices().nth(NOTES_MAX) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_owned(),
    }
}

/// The SHA-256 of `name` in a `SHA256SUMS.txt` (`<hex>  <name>` or `<hex> *<name>`).
pub fn sum_for(sums: &str, name: &str) -> Option<[u8; 32]> {
    sums.lines().find_map(|line| {
        let (hex, file) = line.trim().split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        if file != name || hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(out)
    })
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("unbihex-client/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::custom(|a| {
            if a.previous().len() >= 5 {
                a.error("слишком много перенаправлений")
            } else if a.url().scheme() != "https" {
                a.error("перенаправление не по HTTPS")
            } else {
                a.follow()
            }
        }))
        .build()
        .map_err(|e| ClientError::Update(e.to_string()))
}

async fn get(client: &reqwest::Client, url: &str, max: usize, timeout: Duration) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json, application/octet-stream, */*")
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| ClientError::Update(format!("нет связи с GitHub: {}", crate::subscription::request_error(&e))))?;
    if !resp.status().is_success() {
        return Err(ClientError::Update(format!("GitHub ответил {}", resp.status())));
    }
    crate::subscription::read_limited(resp, max).await.map_err(|e| match e {
        crate::subscription::BodyError::TooLarge => ClientError::Update("файл слишком большой".into()),
        crate::subscription::BodyError::Read(e) => ClientError::Update(format!("загрузка прервалась: {e}")),
    })
}

/// Asks GitHub for the latest release and compares it with this build.
pub async fn check() -> Result<UpdateInfo> {
    let client = http()?;
    let body = get(&client, LATEST_URL, 1 << 20, Duration::from_secs(30)).await?;
    let latest = parse_release(&body)?;
    let newer = compare(&latest.version, CURRENT) == Some(Ordering::Greater);
    let installable = Package::this_device().is_some_and(|p| p.asset(&latest).is_some());
    Ok(UpdateInfo { current: CURRENT.into(), latest, newer, installable })
}

/// Downloads the installer of `package` from `release` into `dir` and checks
/// it against the release's `SHA256SUMS.txt`; the verified file's path.
pub async fn download(release: &Release, package: Package, dir: &Path) -> Result<PathBuf> {
    let asset = package.asset(release).ok_or_else(|| ClientError::Update("в релизе нет файла для этого устройства".into()))?;
    let sums = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .ok_or_else(|| ClientError::Update("в релизе нет SHA256SUMS.txt".into()))?;
    let client = http()?;
    let sums = get(&client, &sums.url, 1 << 20, Duration::from_secs(30)).await?;
    let want = sum_for(&String::from_utf8_lossy(&sums), &asset.name)
        .ok_or_else(|| ClientError::Update(format!("в SHA256SUMS.txt нет {}", asset.name)))?;
    let file = get(&client, &asset.url, FILE_MAX, Duration::from_secs(15 * 60)).await?;
    if Sha256::digest(&file).as_slice() != want {
        return Err(ClientError::Update("контрольная сумма файла не совпала — файл не установлен".into()));
    }
    std::fs::create_dir_all(dir).map_err(|e| ClientError::Update(format!("папка загрузки: {e}")))?;
    // Only a plain file name from our own release: no path parts.
    let name = Path::new(&asset.name).file_name().ok_or_else(|| ClientError::Update("неверное имя файла".into()))?;
    let path = dir.join(name);
    std::fs::write(&path, &file).map_err(|e| ClientError::Update(format!("файл не сохранён: {e}")))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_semver() {
        assert_eq!(compare("0.2.11", "0.2.10"), Some(Ordering::Greater));
        assert_eq!(compare("0.10.0", "0.9.9"), Some(Ordering::Greater));
        assert_eq!(compare("0.2.10", "0.2.10"), Some(Ordering::Equal));
        assert_eq!(compare("1.0.0-beta.2", "1.0.0-beta.10"), Some(Ordering::Less));
        assert_eq!(compare("1.0.0", "1.0.0-rc.1"), Some(Ordering::Greater));
        assert_eq!(compare("0.3", "0.2.99"), Some(Ordering::Greater));
        assert_eq!(compare("x.1", "0.1.0"), None);
        assert_eq!(compare("0.2.10.1", "0.2.10"), None);
    }

    #[test]
    fn release_json_is_parsed_and_filtered() {
        let json = r#"{"tag_name":"v0.2.12","html_url":"https://github.com/crystalmasta/unbihex/releases/tag/v0.2.12",
            "body":"<b>Новое</b>\r\n\r\n\r\n- fix &amp; more <script>x</script>","draft":false,"prerelease":false,
            "assets":[
              {"name":"Unbihex-0.2.12-android-arm64.apk","browser_download_url":"https://github.com/crystalmasta/unbihex/releases/download/v0.2.12/Unbihex-0.2.12-android-arm64.apk"},
              {"name":"Unbihex-0.2.12-windows-setup.exe","browser_download_url":"https://evil.example/Unbihex-0.2.12-windows-setup.exe"},
              {"name":"SHA256SUMS.txt","browser_download_url":"https://github.com/crystalmasta/unbihex/releases/download/v0.2.12/SHA256SUMS.txt"}]}"#.as_bytes();
        let r = parse_release(json).unwrap();
        assert_eq!(r.version, "0.2.12");
        assert_eq!(r.notes, "Новое\n\n- fix & more x");
        assert!(Package::AndroidArm64.asset(&r).is_some());
        assert!(Package::AndroidArmv7.asset(&r).is_none());
        // Files from anywhere but our release downloads are dropped.
        assert!(Package::WindowsSetup.asset(&r).is_none());
        let pre = br#"{"tag_name":"v0.3.0-rc.1","prerelease":true}"#;
        assert!(parse_release(pre).is_err());
    }

    #[test]
    fn the_cache_is_due_once_a_day_and_rechecks_newer() {
        let dir = std::env::temp_dir().join(format!("unbihex-update-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = UpdateInfo {
            current: "0.0.1".into(),
            latest: Release { version: "0.0.2".into(), ..Release::default() },
            newer: true,
            installable: true,
        };
        Cache { checked_at: 1000, info: Some(old) }.save(&dir);
        let c = Cache::load(&dir);
        // This build is newer than the cached release: nothing to offer.
        let info = c.info.as_ref().unwrap();
        assert!(!info.newer && !info.installable);
        assert_eq!(info.current, CURRENT);
        assert!(!c.due(1000 + CHECK_EVERY - 1));
        assert!(c.due(1000 + CHECK_EVERY));
        assert!(c.due(10));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checksums_are_found_by_name() {
        let sums = "c1d68802fb304f977aec7ce7c56c61fdcd2deba114c6920f85da8277ef158400  Unbihex-0.2.10-android-arm64.apk\n\
                    ae9af90a2394510c2d7a06472fe01fdcd93b115ce8c6417409805e66122a9ce1 *Unbihex-0.2.10-windows-setup.exe\n";
        let a = sum_for(sums, "Unbihex-0.2.10-android-arm64.apk").unwrap();
        assert_eq!(a[0], 0xc1);
        assert_eq!(a[31], 0x00);
        assert!(sum_for(sums, "Unbihex-0.2.10-windows-setup.exe").is_some());
        assert!(sum_for(sums, "Unbihex-0.2.10-android-armv7.apk").is_none());
    }
}
