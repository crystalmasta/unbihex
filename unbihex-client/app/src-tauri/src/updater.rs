use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

const RELEASE_ROOT: &str = "https://github.com/crystalmasta/unbihex/releases";
const RELEASE_API: &str = "https://api.github.com/repos/crystalmasta/unbihex/releases/latest";
const MAX_RELEASE_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PackageKind {
    Setup,
    Portable,
}

impl PackageKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Setup => "windows-setup.exe",
            Self::Portable => "windows-portable.zip",
        }
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    state: String,
    size: u64,
    digest: Option<String>,
}

pub(super) struct Artifact {
    pub kind: PackageKind,
    url: String,
    size: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Serialize)]
pub(super) struct ReleaseView {
    pub version: String,
    pub url: String,
    pub can_install: bool,
}

pub(super) struct Update {
    pub view: ReleaseView,
    pub artifact: Option<Artifact>,
}

fn select_update(release: Release, current: &Version, kind: Option<PackageKind>) -> Option<Update> {
    let tag = release.tag_name;
    let version = Version::parse(tag.strip_prefix('v').unwrap_or(&tag)).ok()?;
    if release.draft
        || release.prerelease
        || !version.pre.is_empty()
        || version.cmp_precedence(current).is_le()
        || !release.assets.iter().any(|asset| asset.state == "uploaded")
    {
        return None;
    }
    let artifact = kind.and_then(|kind| {
        let name = format!("Unbihex-{version}-{}", kind.suffix());
        let asset = release.assets.iter().find(|asset| {
            asset.name == name && asset.state == "uploaded" && (1..=MAX_ARTIFACT_BYTES).contains(&asset.size)
        })?;
        let mut sha256 = [0; 32];
        hex::decode_to_slice(asset.digest.as_deref()?.strip_prefix("sha256:")?, &mut sha256).ok()?;
        Some(Artifact {
            kind,
            url: format!("{RELEASE_ROOT}/download/{tag}/{name}"),
            size: asset.size,
            sha256,
        })
    });
    Some(Update {
        view: ReleaseView {
            version: version.to_string(),
            url: format!("{RELEASE_ROOT}/tag/{tag}"),
            can_install: artifact.is_some(),
        },
        artifact,
    })
}

fn github_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(
            url.host_str(),
            Some("api.github.com" | "github.com" | "release-assets.githubusercontent.com" | "objects.githubusercontent.com")
        )
}

fn http_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("Unbihex/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 5 && github_url(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("unexpected GitHub redirect")
            }
        }))
        .build()
        .map_err(|e| e.to_string())
}

pub(super) async fn latest(kind: Option<PackageKind>) -> Result<Option<Update>, String> {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
    let client = http_client(Duration::from_secs(20))?;
    let mut response = client
        .get(RELEASE_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    response = response.error_for_status().map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > MAX_RELEASE_BYTES - body.len() {
            return Err("ответ GitHub о релизе слишком большой".into());
        }
        body.extend_from_slice(&chunk);
    }
    let release = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(select_update(release, &current, kind))
}

#[cfg(any(windows, test))]
async fn download(
    request: reqwest::RequestBuilder,
    artifact: &Artifact,
    destination: &std::path::Path,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    let mut response = request.send().await.map_err(|e| e.to_string())?
        .error_for_status().map_err(|e| e.to_string())?;
    if response.content_length().is_some_and(|length| length != artifact.size) {
        return Err("размер файла обновления отличается от указанного GitHub".into());
    }
    let mut file = tokio::fs::File::create_new(destination).await.map_err(|e| e.to_string())?;
    let mut remaining = artifact.size;
    let mut hash = Sha256::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        remaining = remaining.checked_sub(chunk.len() as u64)
            .ok_or("файл обновления превышает заявленный размер")?;
        hash.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| e.to_string())?;
    }
    let digest: [u8; 32] = hash.finalize().into();
    if remaining != 0 || digest != artifact.sha256 {
        return Err("контрольная сумма файла обновления не совпадает с данными GitHub".into());
    }
    file.sync_all().await.map_err(|e| e.to_string())
}

pub(super) fn package_kind() -> Option<PackageKind> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    if !exe.file_name()?.to_str()?.eq_ignore_ascii_case("Unbihex.exe") {
        // A developer build or an unknown packaging method.
        return None;
    }
    let dir = exe.parent()?;
    if registered_install(dir) {
        Some(PackageKind::Setup)
    } else if dir.join("wintun.dll").is_file() {
        Some(PackageKind::Portable)
    } else {
        None
    }
}

#[cfg(windows)]
fn registered_install(dir: &std::path::Path) -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    if !dir.join("uninstall.exe").is_file() {
        return false;
    }
    let install_dir: std::io::Result<String> = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"Software\Unbihex", KEY_READ | KEY_WOW64_64KEY)
        .and_then(|key| key.get_value("InstallDir"));
    install_dir
        .and_then(std::fs::canonicalize)
        .is_ok_and(|installed| dir.canonicalize().is_ok_and(|dir| installed == dir))
}

#[cfg(not(windows))]
fn registered_install(_dir: &std::path::Path) -> bool {
    false
}

#[cfg(windows)]
pub(super) async fn prepare(
    artifact: Artifact,
    profile: &std::path::Path,
) -> Result<PreparedUpdate, String> {
    let dir = tempfile::Builder::new().prefix("unbihex-update-").tempdir_in(profile)
        .map_err(|e| e.to_string())?;
    let path = dir.path().join(match artifact.kind {
        PackageKind::Setup => "update.exe",
        PackageKind::Portable => "update.zip",
    });
    let client = http_client(Duration::from_secs(5 * 60))?;
    download(client.get(&artifact.url), &artifact, &path).await?;
    Ok(PreparedUpdate { dir, artifact })
}

#[cfg(windows)]
pub(super) struct PreparedUpdate {
    dir: tempfile::TempDir,
    artifact: Artifact,
}

#[cfg(windows)]
impl PreparedUpdate {
    pub(super) fn launch(self, profile: &std::path::Path) -> Result<(), String> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use unbihex_client_core::platform::{hide_window, system_program};

        let script = concat!(include_str!("windows-update.ps1"), "\nInvoke-UnbihexUpdate\n");
        let encoded = STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut command = std::process::Command::new(system_program("powershell").map_err(|e| e.to_string())?);
        hide_window(&mut command);
        command
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .env("UNBIHEX_UPDATE_PID", std::process::id().to_string())
            .env("UNBIHEX_UPDATE_MODE", match self.artifact.kind {
                PackageKind::Setup => "setup",
                PackageKind::Portable => "portable",
            })
            .env("UNBIHEX_UPDATE_EXE", exe)
            .env("UNBIHEX_UPDATE_STAGE", self.dir.path())
            .env("UNBIHEX_UPDATE_PROFILE", profile)
            .env("UNBIHEX_UPDATE_SHA256", hex::encode(self.artifact.sha256))
            .spawn()
            .map_err(|e| e.to_string())?;
        // The helper owns the downloaded package from now on.
        let _ = self.dir.keep();
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn take_install_error(profile: &std::path::Path) -> Option<String> {
    let path = profile.join("update-error.txt");
    let message = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(path);
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> Release {
        let version = tag.trim_start_matches('v');
        Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: [PackageKind::Setup, PackageKind::Portable].into_iter().map(|kind| ReleaseAsset {
                name: format!("Unbihex-{version}-{}", kind.suffix()),
                state: "uploaded".into(),
                size: 123,
                digest: Some(format!("sha256:{}", "a3".repeat(32))),
            }).collect(),
        }
    }

    #[test]
    fn selects_only_new_stable_builds_and_the_right_package() {
        let current = Version::parse("0.2.11").unwrap();
        for tag in ["v0.2.10", "v0.2.11", "v0.3.0-beta.1", "v0.2.11+rebuild", "branch"] {
            assert!(select_update(release(tag), &current, Some(PackageKind::Setup)).is_none(), "{tag}");
        }
        let mut draft = release("v0.2.12");
        draft.draft = true;
        assert!(select_update(draft, &current, None).is_none());

        for kind in [PackageKind::Setup, PackageKind::Portable] {
            let update = select_update(release("v0.2.12"), &current, Some(kind)).unwrap();
            assert!(update.view.can_install);
            assert_eq!(update.view.version, "0.2.12");
            let artifact = update.artifact.unwrap();
            assert_eq!(artifact.kind, kind);
            assert_eq!(artifact.sha256, [0xa3; 32]);
            assert!(artifact.url.ends_with(kind.suffix()));
        }
    }

    #[test]
    fn missing_or_invalid_artifacts_keep_the_release_link_only() {
        let current = Version::parse("0.2.11").unwrap();
        let mut newer = release("v0.2.12");
        newer.assets[0].digest = Some("sha256:broken".into());
        let update = select_update(newer, &current, Some(PackageKind::Setup)).unwrap();
        assert!(!update.view.can_install);
        assert_eq!(update.view.url, format!("{RELEASE_ROOT}/tag/v0.2.12"));
        let mut newer = release("v0.2.12");
        newer.assets.clear();
        assert!(select_update(newer, &current, None).is_none());
    }

    #[test]
    fn downloads_cannot_redirect_to_other_origins() {
        for url in [
            "http://github.com/file",
            "https://github.com.bad.example/file",
            "https://github.com:444/file",
            "https://user@github.com/file",
        ] {
            assert!(!github_url(&url.parse().unwrap()), "{url}");
        }
        assert!(github_url(&"https://release-assets.githubusercontent.com/file".parse().unwrap()));
    }

    #[tokio::test]
    async fn accepts_only_the_expected_size_and_hash() {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        for (body, size, success) in [
            (&b"fixture"[..], 7, true),
            (&b"badfile"[..], 7, false),
            (&b"fixture"[..], 6, false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(socket.read_u8().await.unwrap());
                }
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
            });
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.exe");
            let artifact = Artifact {
                kind: PackageKind::Setup,
                url: url.clone(),
                size,
                sha256: Sha256::digest(b"fixture").into(),
            };
            let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
            let result = download(client.get(url), &artifact, &path).await;
            assert_eq!(result.is_ok(), success, "{result:?}");
            if success {
                assert_eq!(std::fs::read(&path).unwrap(), body);
            }
            server.await.unwrap();
        }
    }
}
