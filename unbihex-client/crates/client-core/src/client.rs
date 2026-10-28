//! The client facade used by the app: persistent data plus the controller.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::controller::{Controller, Status};
use crate::error::{ClientError, Result};
use crate::geo::Geo;
use crate::links::{b64_decode, is_share_link, parse_server};
use crate::model::{AppData, Server, Settings, Subscription, now_secs};
use crate::ping::{describe_error, measure};
use crate::subscription::{FetchOptions, fallback_name, fetch};

const STATE_FILE: &str = "state.json";
/// Shortest LAN proxy password a user may set (generated ones are 32 characters).
const MIN_LAN_PASSWORD: usize = 8;
/// Delay tests running at the same time.
const PING_PARALLEL: usize = 12;

/// Result of [`Client::add_input`].
#[derive(Clone, Debug, Default, Serialize)]
pub struct AddReport {
    /// New subscriptions.
    pub subscriptions: usize,
    /// Servers added (manual links or from the new subscriptions).
    pub servers: usize,
    /// Problems with individual lines.
    pub errors: Vec<String>,
}

/// One delay test result.
#[derive(Clone, Debug, Serialize)]
pub struct PingResult {
    /// Server id.
    pub id: Uuid,
    /// Delay in ms.
    pub ms: Option<u32>,
    /// Error text.
    pub error: Option<String>,
}

/// Client state shared by the UI commands.
pub struct Client {
    dir: PathBuf,
    data: parking_lot::RwLock<AppData>,
    /// The engine controller.
    pub controller: Arc<Controller>,
}

/// The saved state, and whether it lacked the LAN password (a new one was generated
/// and must be saved so LAN devices keep working after a restart).
fn load(path: &Path) -> (AppData, bool) {
    let parsed = std::fs::read(path).map(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).and_then(|v| {
            let fresh = v.pointer("/settings/lan_password").is_none();
            serde_json::from_value::<AppData>(v).map(|d| (d, fresh))
        })
    });
    match parsed {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            tracing::error!("state file is damaged ({e}); a backup is kept as state.json.bak");
            let _ = std::fs::copy(path, path.with_extension("json.bak"));
            (AppData::default(), false)
        }
        Err(_) => (AppData::default(), false),
    }
}

impl Client {
    /// Loads `dir/state.json` and rolls back system changes left by a crash.
    pub fn open(dir: impl Into<PathBuf>) -> Client {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        crate::platform::recover(&dir);
        let (data, fresh) = load(&dir.join(STATE_FILE));
        let client = Client {
            controller: Arc::new(Controller::new(dir.clone())),
            data: parking_lot::RwLock::new(data),
            dir,
        };
        if fresh && let Err(e) = client.save() {
            tracing::warn!("cannot save state: {e}");
        }
        client
    }

    /// The data folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A copy of everything for the UI.
    pub fn snapshot(&self) -> AppData {
        self.data.read().clone()
    }

    /// Current settings.
    pub fn settings(&self) -> Settings {
        self.data.read().settings.clone()
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&*self.data.read())?;
        let path = self.dir.join(STATE_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn mutate<T>(&self, f: impl FnOnce(&mut AppData) -> T) -> Result<T> {
        let r = f(&mut self.data.write());
        self.save()?;
        Ok(r)
    }

    /// Adds subscription URLs and/or share links pasted by the user.
    pub async fn add_input(&self, text: &str) -> Result<AddReport> {
        let mut text = text.trim().to_string();
        // A whole base64 subscription body pasted as is.
        if !text.contains("://")
            && let Some(decoded) = b64_decode(&text).and_then(|b| String::from_utf8(b).ok())
            && decoded.contains("://")
        {
            text = decoded;
        }
        let mut report = AddReport::default();
        let mut sub_urls = Vec::new();
        let mut manual = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                sub_urls.push(line.to_string());
            } else if is_share_link(line) {
                match parse_server(line) {
                    Ok(s) => manual.push(s),
                    Err(e) => report.errors.push(e.to_string()),
                }
            } else {
                report.errors.push(format!("не распознано: {}", shorten(line)));
            }
        }
        if sub_urls.is_empty() && manual.is_empty() {
            return Err(ClientError::Input(
                "не найдено ни ссылки на подписку (https://…), ни ссылок на серверы".into(),
            ));
        }
        if !manual.is_empty() {
            report.servers += manual.len();
            self.mutate(|d| {
                for s in manual {
                    if !d.servers.iter().any(|o| o.subscription_id.is_none() && o.link == s.link) {
                        d.servers.push(s);
                    }
                }
                d.ensure_selection();
            })?;
        }
        for url in sub_urls {
            let exists = self.data.read().subscriptions.iter().any(|s| s.url == url);
            if exists {
                report.errors.push("эта подписка уже добавлена".into());
                continue;
            }
            let sub = Subscription {
                name: fallback_name(&url),
                url,
                ..Default::default()
            };
            let id = sub.id;
            self.mutate(|d| d.subscriptions.push(sub))?;
            report.subscriptions += 1;
            match self.update_subscription(id).await {
                Ok(n) => report.servers += n,
                Err(e) => report.errors.push(e.to_string()),
            }
        }
        Ok(report)
    }

    /// Downloads a subscription again; returns the number of servers.
    pub async fn update_subscription(&self, id: Uuid) -> Result<usize> {
        let (url, opts) = {
            let d = self.data.read();
            let sub = d
                .subscriptions
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| ClientError::NotFound("подписка".into()))?;
            let ua = sub
                .user_agent
                .clone()
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| d.settings.user_agent.clone());
            let hwid = d.settings.send_hwid.then(|| d.settings.hwid.clone());
            (sub.url.clone(), FetchOptions { user_agent: ua, hwid })
        };
        match fetch(&url, &opts).await {
            Ok(f) => {
                let mut servers = Vec::new();
                for link in &f.links {
                    match parse_server(link) {
                        Ok(s) => servers.push(s),
                        Err(e) => tracing::debug!("skipped a subscription line: {e}"),
                    }
                }
                let n = servers.len();
                self.mutate(|d| {
                    d.replace_servers(id, servers);
                    if let Some(sub) = d.subscription_mut(id) {
                        if let Some(t) = f.title.filter(|_| !sub.custom_name) {
                            sub.name = t;
                        }
                        sub.info = f.info;
                        if let Some(h) = f.update_interval_hours {
                            sub.update_interval_hours = h;
                        }
                        sub.support_url = f.support_url;
                        sub.web_page_url = f.web_page_url;
                        sub.updated_at = Some(now_secs());
                        sub.last_error = None;
                    }
                    d.ensure_selection();
                })?;
                Ok(n)
            }
            Err(e) => {
                let msg = e.to_string();
                self.mutate(|d| {
                    if let Some(sub) = d.subscription_mut(id) {
                        sub.last_error = Some(msg);
                    }
                })?;
                Err(e)
            }
        }
    }

    /// Updates every subscription whose interval has passed (or all with `force`).
    pub async fn update_all(&self, force: bool) -> Vec<(Uuid, Result<usize>)> {
        let now = now_secs();
        let ids: Vec<Uuid> = self
            .data
            .read()
            .subscriptions
            .iter()
            .filter(|s| force || s.is_due(now))
            .map(|s| s.id)
            .collect();
        let mut out = Vec::new();
        for id in ids {
            out.push((id, self.update_subscription(id).await));
        }
        out
    }

    /// Renames a subscription and/or changes its URL or User-Agent.
    pub fn edit_subscription(
        &self,
        id: Uuid,
        name: Option<String>,
        url: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.mutate(|d| {
            let sub = d
                .subscription_mut(id)
                .ok_or_else(|| ClientError::NotFound("подписка".into()))?;
            if let Some(n) = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()) {
                sub.name = n;
                sub.custom_name = true;
            }
            if let Some(u) = url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) {
                sub.url = u;
            }
            if let Some(ua) = user_agent {
                sub.user_agent = Some(ua.trim().to_string()).filter(|u| !u.is_empty());
            }
            Ok(())
        })?
    }

    /// Removes a subscription with its servers.
    pub fn remove_subscription(&self, id: Uuid) -> Result<()> {
        self.mutate(|d| {
            d.subscriptions.retain(|s| s.id != id);
            d.servers.retain(|s| s.subscription_id != Some(id));
            d.ensure_selection();
        })
    }

    /// Removes one server.
    pub fn remove_server(&self, id: Uuid) -> Result<()> {
        self.mutate(|d| {
            d.servers.retain(|s| s.id != id);
            d.ensure_selection();
        })
    }

    /// Selects a server for the next connection.
    pub fn select(&self, id: Uuid) -> Result<Server> {
        self.mutate(|d| {
            let s = d
                .server(id)
                .cloned()
                .ok_or_else(|| ClientError::NotFound("сервер".into()))?;
            d.selected = Some(id);
            Ok(s)
        })?
    }

    /// Replaces the settings (keeps the device id and the LAN password).
    pub fn set_settings(&self, mut s: Settings) -> Result<()> {
        // The LAN proxy is open to the whole network: no guessable passwords.
        let pass = s.lan_password.trim();
        if !pass.is_empty() && pass.chars().count() < MIN_LAN_PASSWORD {
            return Err(ClientError::Input(format!(
                "пароль для доступа из сети — не короче {MIN_LAN_PASSWORD} символов"
            )));
        }
        self.mutate(|d| {
            if s.hwid.trim().is_empty() {
                s.hwid = d.settings.hwid.clone();
            }
            if s.user_agent.trim().is_empty() {
                s.user_agent = crate::model::DEFAULT_USER_AGENT.into();
            }
            if s.lan_password.trim().is_empty() {
                s.lan_password = d.settings.lan_password.clone();
            }
            s.lan_username = s.lan_username.trim().to_string();
            if s.lan_username.is_empty() {
                s.lan_username = crate::model::DEFAULT_LAN_USERNAME.into();
            }
            d.settings = s;
        })
    }

    /// The selected server, checked for engine support.
    pub fn selected_server(&self) -> Result<Server> {
        let d = self.data.read();
        let s = d
            .selected_server()
            .cloned()
            .ok_or_else(|| ClientError::State("выберите сервер".into()))?;
        if let Some(why) = &s.unsupported {
            return Err(ClientError::Unsupported(why.clone()));
        }
        Ok(s)
    }

    /// Tests the delay of `ids` (all supported servers when empty), reporting
    /// each result through `on_result` as soon as it is known.
    pub async fn ping(
        &self,
        ids: &[Uuid],
        on_result: impl Fn(PingResult) + Send + Sync + 'static,
    ) -> Vec<PingResult> {
        let servers: Vec<Server> = {
            let d = self.data.read();
            d.servers
                .iter()
                .filter(|s| ids.is_empty() || ids.contains(&s.id))
                .cloned()
                .collect()
        };
        let env = self.controller.ping_env();
        let method = self.settings().ping_method;
        let sem = Arc::new(tokio::sync::Semaphore::new(PING_PARALLEL));
        let on_result = Arc::new(on_result);
        let mut set = tokio::task::JoinSet::new();
        for s in servers {
            let (env, sem, cb) = (env.clone(), sem.clone(), on_result.clone());
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                // TCP and ICMP only need the address, so they also test servers whose
                // protocol the engine lacks.
                let r = match &s.unsupported {
                    Some(_) if method.uses_protocol() => PingResult {
                        id: s.id,
                        ms: None,
                        error: Some("не поддерживается".into()),
                    },
                    _ => match measure(&s, method, &env).await {
                        Ok(ms) => PingResult {
                            id: s.id,
                            ms: Some(ms),
                            error: None,
                        },
                        Err(e) => {
                            tracing::debug!("ping {}: {e}", s.name);
                            PingResult {
                                id: s.id,
                                ms: None,
                                error: Some(describe_error(&e)),
                            }
                        }
                    },
                };
                cb(r.clone());
                r
            });
        }
        let mut results = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Ok(r) = r {
                results.push(r);
            }
        }
        let _ = self.mutate(|d| {
            for r in &results {
                if let Some(s) = d.servers.iter_mut().find(|s| s.id == r.id) {
                    s.ping_ms = r.ms;
                    s.ping_error = r.error.clone();
                }
            }
        });
        results
    }

    /// Desktop: connects to the selected server.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub async fn connect(&self) -> Result<crate::controller::ConnectionInfo> {
        let server = self.selected_server()?;
        let settings = self.settings();
        self.controller
            .connect_desktop(&server, &settings, &self.geo())
            .await
    }

    /// The rule databases for engine configs.
    pub fn geo(&self) -> Geo {
        Geo::from_status(&self.dir, &self.data.read().geo)
    }

    /// Applies the selected server and current settings to the running engine
    /// without dropping connections. `Ok(None)`: not connected.
    pub async fn reload(&self) -> Result<Option<crate::controller::ConnectionInfo>> {
        if !self.controller.is_connected().await {
            return Ok(None);
        }
        let server = self.selected_server()?;
        let settings = self.settings();
        self.controller.reload(&server, &settings, &self.geo()).await
    }

    /// Downloads the rule databases.
    pub async fn update_geodata(&self) -> Result<crate::model::GeoStatus> {
        let settings = self.settings();
        match crate::geo::update(&self.dir, &settings).await {
            Ok(status) => {
                self.mutate(|d| d.geo = status.clone())?;
                Ok(status)
            }
            Err(e) => {
                let msg = e.to_string();
                self.mutate(|d| d.geo.last_error = Some(msg))?;
                Err(e)
            }
        }
    }

    /// Downloads the databases when automatic updates are on and a week has passed.
    pub async fn update_geodata_if_due(&self) -> Option<Result<crate::model::GeoStatus>> {
        let (auto, due) = {
            let d = self.data.read();
            (d.settings.geo_auto_update, crate::geo::is_due(&d.geo, now_secs()))
        };
        if auto && due {
            Some(self.update_geodata().await)
        } else {
            None
        }
    }

    /// Disconnects.
    pub async fn disconnect(&self) {
        self.controller.disconnect().await;
    }

    /// Connection state.
    pub async fn status(&self) -> Status {
        self.controller.status().await
    }
}

fn shorten(s: &str) -> String {
    let mut out: String = s.chars().take(40).collect();
    if s.chars().count() > 40 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("unbihex-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn manual_links_persist_and_select() {
        let dir = tmp();
        let c = Client::open(&dir);
        let r = c
            .add_input(&format!(
                "vless://{UUID}@a.com:443?security=tls#A\ntrojan://p@b.com:443#B\nnonsense"
            ))
            .await
            .unwrap();
        assert_eq!(r.servers, 2);
        assert_eq!(r.errors.len(), 1);
        let d = c.snapshot();
        assert_eq!(d.selected_server().unwrap().name, "A");
        drop(c);
        let c = Client::open(&dir);
        assert_eq!(c.snapshot().servers.len(), 2);
        let b = c.snapshot().servers[1].id;
        c.select(b).unwrap();
        assert!(matches!(c.selected_server(), Err(ClientError::Unsupported(_))));
        assert!(c.add_input("hello").await.is_err());
    }

    #[test]
    fn replace_keeps_ids() {
        let mut d = AppData::default();
        let sub = Uuid::new_v4();
        let a = parse_server(&format!("vless://{UUID}@a.com:443?security=tls#A")).unwrap();
        d.replace_servers(sub, vec![a.clone()]);
        let id = d.servers[0].id;
        d.selected = Some(id);
        d.servers[0].ping_ms = Some(50);
        let again = parse_server(&format!("vless://{UUID}@a.com:443?security=tls#A")).unwrap();
        let other = parse_server(&format!("vless://{UUID}@c.com:443?security=tls#C")).unwrap();
        d.replace_servers(sub, vec![other, again]);
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.selected, Some(id));
        assert_eq!(d.server(id).unwrap().ping_ms, Some(50));
        d.replace_servers(sub, vec![]);
        assert_eq!(d.selected, None);
    }

    #[test]
    fn lan_credentials_survive_restarts_and_empty_input() {
        let dir = tmp();
        // A state file from a version without LAN credentials.
        std::fs::write(dir.join(STATE_FILE), r#"{"settings":{"allow_lan":true}}"#).unwrap();
        let pass = Client::open(&dir).settings().lan_password;
        assert_eq!(pass.len(), 32);
        let c = Client::open(&dir);
        assert_eq!(c.settings().lan_password, pass);
        c.set_settings(Settings {
            lan_username: " ".into(),
            lan_password: String::new(),
            ..c.settings()
        })
        .unwrap();
        let s = Client::open(&dir).settings();
        assert_eq!((s.lan_username.as_str(), s.lan_password), ("unbihex", pass));
    }
}
