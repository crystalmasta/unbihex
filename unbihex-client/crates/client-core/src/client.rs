//! The client facade used by the app: persistent data plus the controller.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::controller::{Controller, Status};
use crate::error::{ClientError, Result};
use crate::geo::Geo;
use crate::links::{b64_decode, is_share_link, parse_server};
use crate::model::{AppData, AutoTemplate, Server, Settings, Subscription, now_secs};
use crate::ping::{describe_error, measure};
use crate::trust;
use crate::subscription::{Device, FetchOptions, JSON_USER_AGENT, fallback_name, fetch_with};

const STATE_FILE: &str = "state.json";
/// Shortest LAN proxy password a user may set (generated ones are 32 characters).
const MIN_LAN_PASSWORD: usize = 8;
/// Delay tests running at the same time.
/// What trusting a subscription's certificates came to.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct TrustReport {
    /// Servers whose certificate was pinned.
    pub pinned: usize,
    /// Eligible servers that could not be probed.
    pub failed: usize,
}

const PING_PARALLEL: usize = 12;
/// Longest auto-select template name, in characters.
const MAX_TEMPLATE_NAME: usize = 60;

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
    pub(crate) data: parking_lot::RwLock<AppData>,
    /// The engine controller.
    pub controller: Arc<Controller>,
    /// Operator whitelist detection (checks, their history, wake-ups).
    pub whitelist: crate::whitelist::Watch,
}

/// The saved state, and whether it must be saved right away: it lacked the LAN
/// password (a new one was generated, LAN devices must keep working after a
/// restart) or had the old auto-select marks (now a template).
fn load(path: &Path) -> (AppData, bool) {
    let parsed = std::fs::read(path).map(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).and_then(|v| {
            let fresh = v.pointer("/settings/lan_password").is_none();
            serde_json::from_value::<AppData>(v.clone()).map(|mut d| {
                let migrated = d.migrate_marks(&v) | d.settings.migrate_fragment();
                (d, fresh || migrated)
            })
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
        let (mut data, mut fresh) = load(&dir.join(STATE_FILE));
        // By dubr1k (github.com/dubr1k), PR #32.
        for server in &mut data.servers {
            fresh |= crate::links::refresh_support(server);
        }
        let client = Client {
            controller: Arc::new(Controller::new(dir.clone())),
            data: parking_lot::RwLock::new(data),
            dir,
            whitelist: crate::whitelist::Watch::default(),
        };
        client.sync_journal();
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
        let mut d = self.data.read().clone();
        for s in &mut d.servers {
            s.can_trust = trust::can_hold_pin(s);
        }
        d
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

    pub(crate) fn mutate<T>(&self, f: impl FnOnce(&mut AppData) -> T) -> Result<T> {
        let r = f(&mut self.data.write());
        self.sync_journal();
        self.save()?;
        Ok(r)
    }

    /// Tells the connection journal what it needs of the saved data.
    fn sync_journal(&self) {
        let d = self.data.read();
        let s = &d.settings;
        self.controller.journal.set_context(crate::devlog::JournalContext {
            enabled: s.dev_mode,
            keep: s.report_keep,
            dir: s.report_dir.clone(),
            routing: crate::whitelist::routing_label(s.routing).into(),
            template: if s.auto_select == crate::model::AutoSelect::Off {
                None
            } else {
                d.active_template().map(|t| t.name.clone())
            },
            secrets: if s.dev_mode { crate::redact::secrets(&d) } else { Vec::new() },
        });
    }

    /// Developer mode on or off; a running connection starts or stops being journaled.
    pub async fn set_dev_mode(&self, on: bool) -> Result<()> {
        self.mutate(|d| d.settings.dev_mode = on)?;
        if !on {
            self.controller.journal.clear();
        }
        self.controller.sync_journal().await;
        Ok(())
    }

    /// The folder for connection reports (a path or an Android tree); empty: the app's own.
    pub fn set_report_dir(&self, dir: &str) -> Result<()> {
        self.mutate(|d| d.settings.report_dir = dir.trim().to_string())
    }

    /// Adds subscription URLs and/or share links pasted by the user.
    pub async fn add_input(&self, text: &str) -> Result<AddReport> {
        let mut text = text.trim().to_string();
        // A config pasted from another client: Xray or sing-box JSON (issue #12).
        if text.starts_with('{') || text.starts_with('[') {
            match crate::jsonsub::links_from_json(&text) {
                Some(links) if !links.is_empty() => text = links.join("\n"),
                _ => {
                    return Err(ClientError::Input(
                        "в JSON нет серверов: нужен конфиг Xray или sing-box с outbounds".into(),
                    ));
                }
            }
        }
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
        let (url, opts, as_json) = {
            let d = self.data.read();
            let sub = d
                .subscriptions
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| ClientError::NotFound("подписка".into()))?;
            let own = sub.user_agent.clone().filter(|u| !u.trim().is_empty());
            // An own User-Agent is sent as is; otherwise links that lack WebSocket
            // settings make us ask for the panel's JSON (remembered once it works).
            let as_json = own.is_none() && sub.json_user_agent;
            let ua = match own.clone() {
                Some(ua) => ua,
                None if as_json => JSON_USER_AGENT.to_string(),
                None => d.settings.user_agent.clone(),
            };
            let device = d.settings.send_hwid.then(|| Device {
                hwid: d.settings.hwid.clone(),
                name: d.settings.device_name.clone(),
            });
            let retry_as_json = own.is_none() && !as_json;
            (sub.url.clone(), FetchOptions { user_agent: ua, device, retry_as_json }, as_json)
        };
        // Mobile whitelists may let through only the VPN server: then the panel is
        // asked again through it.
        let tunnel = self.controller.tunnel().await;
        match fetch_with(&url, &opts, tunnel.as_ref()).await {
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
                        // Remembered when the retry got JSON; forgotten when the
                        // panel stops giving it.
                        if f.json || as_json {
                            sub.json_user_agent = f.json && sub.user_agent.is_none();
                        }
                    }
                    d.ensure_selection();
                })?;
                // New eligible servers of a trusting subscription get their pin.
                let trusting = self.data.read().subscriptions.iter().any(|s| s.id == id && s.trust_certs);
                if trusting {
                    let ids = self
                        .data
                        .read()
                        .servers
                        .iter()
                        .filter(|s| s.subscription_id == Some(id))
                        .map(|s| s.id)
                        .collect();
                    self.pin_servers(ids).await;
                }
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
                sub.json_user_agent = false;
            }
            Ok(())
        })?
    }

    /// Removes a subscription with its servers.
    pub fn remove_subscription(&self, id: Uuid) -> Result<()> {
        self.mutate(|d| {
            d.subscriptions.retain(|s| s.id != id);
            d.servers.retain(|s| s.subscription_id != Some(id));
            d.prune_templates();
            d.ensure_selection();
        })
    }

    /// Removes one server.
    pub fn remove_server(&self, id: Uuid) -> Result<()> {
        self.mutate(|d| {
            d.servers.retain(|s| s.id != id);
            d.prune_templates();
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
        let fp = s.tls_fingerprint.trim().to_ascii_lowercase();
        if !fp.is_empty() {
            check_fingerprint(&fp)?;
        }
        s.tls_fingerprint = fp;
        // A mistyped DNS server would be dropped silently when connecting.
        for dns in s.dns_upstream.iter().chain(&s.dns_direct).filter(|d| !d.trim().is_empty()) {
            if let Err(e) = dns.trim().parse::<unbihex_engine::config::DnsUpstream>() {
                return Err(ClientError::Input(format!(
                    "DNS-сервер «{dns}» не распознан: нужен ip, ip:порт, udp://ip:порт, tcp://ip:порт, tls://сервер или https://сервер/путь ({e})"
                )));
            }
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
            // A template deleted meanwhile (another window): all servers.
            if let Some(t) = s.auto_template
                && !d.auto_templates.iter().any(|x| x.id == t)
            {
                s.auto_template = None;
            }
            if let Some(t) = s.whitelist_template
                && !d.auto_templates.iter().any(|x| x.id == t)
            {
                s.whitelist_template = None;
            }
            for list in [&mut s.whitelist_allowed, &mut s.whitelist_blocked] {
                list.retain(|h| !h.trim().is_empty());
                list.iter_mut().for_each(|h| *h = h.trim().to_string());
            }
            // Changed by their own commands only (seven taps, the folder dialog).
            s.dev_mode = d.settings.dev_mode;
            s.report_dir = d.settings.report_dir.clone();
            s.report_keep = s.report_keep.clamp(*crate::devlog::KEEP_RANGE.start(), *crate::devlog::KEEP_RANGE.end());
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
            // The delay is measured with the fingerprint a connection would send.
            let fp = Some(d.settings.tls_fingerprint.trim().to_string()).filter(|f| !f.is_empty());
            d.servers
                .iter()
                .filter(|s| ids.is_empty() || ids.contains(&s.id))
                .cloned()
                .map(|mut s| {
                    s.fingerprint = s.fingerprint.or_else(|| fp.clone());
                    s
                })
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

    /// The selected server and, with auto-select on, the rest of its group the
    /// engine supports, in list order, up to `plan::MAX_GROUP` in all. The group
    /// is the servers of the active template (any subscriptions), or without one
    /// the other servers of its subscription (manual servers: the other manual
    /// ones) except the excluded ones. The selected server always comes first,
    /// even when it is excluded or not in the template.
    pub fn connect_servers(&self) -> Result<Vec<Server>> {
        let first = self.selected_server()?;
        let mut out = vec![first.clone()];
        let d = self.data.read();
        if d.settings.auto_select != crate::model::AutoSelect::Off {
            let template = d.active_template();
            out.extend(
                d.servers
                    .iter()
                    .filter(|s| s.id != first.id && s.is_supported())
                    .filter(|s| match template {
                        Some(t) => t.servers.contains(&s.id),
                        None => s.subscription_id == first.subscription_id && !s.auto_excluded,
                    })
                    .take(crate::plan::MAX_GROUP - 1)
                    .cloned(),
            );
        }
        Ok(out)
    }

    /// Excludes a server from the auto-select group of its subscription (used
    /// while no template is active) or takes it back.
    pub fn set_server_auto(&self, id: Uuid, excluded: bool) -> Result<Server> {
        self.mutate(|d| {
            let s = d
                .servers
                .iter_mut()
                .find(|s| s.id == id)
                .ok_or_else(|| ClientError::NotFound("сервер".into()))?;
            s.auto_excluded = excluded;
            Ok(s.clone())
        })?
    }

    /// Creates an auto-select template; servers that do not exist are left out.
    pub fn create_template(&self, name: &str, servers: Vec<Uuid>) -> Result<AutoTemplate> {
        self.mutate(|d| {
            let name = template_name(d, name, None)?;
            let servers = known_servers(d, servers);
            let t = AutoTemplate { id: Uuid::new_v4(), name, servers };
            d.auto_templates.push(t.clone());
            Ok(t)
        })?
    }

    /// Renames a template and/or replaces its servers; `None` leaves that as it is.
    pub fn update_template(&self, id: Uuid, name: Option<String>, servers: Option<Vec<Uuid>>) -> Result<AutoTemplate> {
        self.mutate(|d| {
            let name = name.map(|n| template_name(d, &n, Some(id))).transpose()?;
            let servers = servers.map(|s| known_servers(d, s));
            let t = template_mut(d, id)?;
            if let Some(n) = name {
                t.name = n;
            }
            if let Some(s) = servers {
                t.servers = s;
            }
            Ok(t.clone())
        })?
    }

    /// Adds a server to a template or takes it out.
    pub fn set_template_server(&self, id: Uuid, server: Uuid, member: bool) -> Result<AutoTemplate> {
        self.mutate(|d| {
            if d.server(server).is_none() {
                return Err(ClientError::NotFound("сервер".into()));
            }
            let t = template_mut(d, id)?;
            let at = t.servers.iter().position(|s| *s == server);
            match (member, at) {
                (true, None) => t.servers.push(server),
                (false, Some(i)) => {
                    t.servers.remove(i);
                }
                _ => {}
            }
            Ok(t.clone())
        })?
    }

    /// Deletes a template; when it was the active one, "all servers" takes over.
    pub fn delete_template(&self, id: Uuid) -> Result<()> {
        self.mutate(|d| {
            let before = d.auto_templates.len();
            d.auto_templates.retain(|t| t.id != id);
            if d.auto_templates.len() == before {
                return Err(ClientError::NotFound("шаблон".into()));
            }
            if d.settings.auto_template == Some(id) {
                d.settings.auto_template = None;
            }
            if d.settings.whitelist_template == Some(id) {
                d.settings.whitelist_template = None;
            }
            Ok(())
        })?
    }

    /// Sets the TLS fingerprint of one server (`None` or empty: the one from the
    /// settings or the link).
    pub fn set_server_fingerprint(&self, id: Uuid, fingerprint: Option<String>) -> Result<Server> {
        let fingerprint = fingerprint.map(|f| f.trim().to_ascii_lowercase()).filter(|f| !f.is_empty());
        if let Some(f) = &fingerprint {
            check_fingerprint(f)?;
        }
        self.mutate(|d| {
            let s = d
                .servers
                .iter_mut()
                .find(|s| s.id == id)
                .ok_or_else(|| ClientError::NotFound("сервер".into()))?;
            s.fingerprint = fingerprint;
            Ok(s.clone())
        })?
    }

    /// Reads the leaf certificate hash of a server (hex SHA-256) the way a ping reaches
    /// it. Saves nothing: the user confirms it, then `set_server_trust` pins it.
    pub async fn probe_server_cert(&self, id: Uuid) -> Result<String> {
        let (server, fp) = {
            let d = self.data.read();
            let s = d.servers.iter().find(|s| s.id == id).ok_or_else(|| ClientError::NotFound("сервер".into()))?;
            let fp = s.fingerprint.clone().or_else(|| Some(d.settings.tls_fingerprint.clone()));
            (s.clone(), fp)
        };
        trust::probe(&server, fp.as_deref(), &self.controller.ping_env())
            .await
            .map_err(|e| {
                tracing::debug!("cert probe {}: {e}", server.name);
                e
            })
    }

    /// Pins the certificate of one server (`None`: removes the pin). A pinned
    /// connection accepts only that certificate; it applies from the next connect.
    pub fn set_server_trust(&self, id: Uuid, sha256: Option<String>) -> Result<Server> {
        let sha256 = sha256.filter(|h| !h.trim().is_empty()).map(|h| trust::normalize_hash(&h)).transpose()?;
        self.mutate(|d| {
            let s = d
                .servers
                .iter_mut()
                .find(|s| s.id == id)
                .ok_or_else(|| ClientError::NotFound("сервер".into()))?;
            if sha256.is_some() && !trust::can_hold_pin(s) {
                return Err(ClientError::Input("для этого сервера нельзя доверять сертификату".into()));
            }
            s.trusted_sha256 = sha256;
            Ok(s.clone())
        })?
    }

    /// Probes `ids` (at most [`trust::PROBE_PARALLEL`] at once) and pins what was
    /// read. A server that got a pin meanwhile, or changed its address, is left alone.
    async fn pin_servers(&self, ids: Vec<Uuid>) -> TrustReport {
        let (servers, fp, env) = {
            let d = self.data.read();
            let servers: Vec<Server> =
                d.servers.iter().filter(|s| ids.contains(&s.id) && trust::is_trust_candidate(s)).cloned().collect();
            (servers, d.settings.tls_fingerprint.clone(), self.controller.ping_env())
        };
        let sem = Arc::new(tokio::sync::Semaphore::new(trust::PROBE_PARALLEL));
        let mut set = tokio::task::JoinSet::new();
        for s in servers {
            let (sem, env, fp) = (sem.clone(), env.clone(), fp.clone());
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                let own = s.fingerprint.clone().or(Some(fp));
                let r = trust::probe(&s, own.as_deref(), &env).await;
                (s.id, s.host, s.port, r)
            });
        }
        let mut found = Vec::new();
        let mut failed = 0;
        while let Some(done) = set.join_next().await {
            match done {
                Ok((id, host, port, Ok(h))) => found.push((id, host, port, h)),
                Ok((_, _, _, Err(e))) => {
                    tracing::debug!("cert probe: {e}");
                    failed += 1;
                }
                Err(_) => failed += 1,
            }
        }
        let mut pinned = 0;
        let saved = self.mutate(|d| {
            for (id, host, port, h) in found {
                if let Some(s) = d.servers.iter_mut().find(|s| s.id == id)
                    && s.trusted_sha256.is_none()
                    && s.host == host
                    && s.port == port
                {
                    s.trusted_sha256 = Some(h);
                    pinned += 1;
                }
            }
        });
        if let Err(e) = saved {
            tracing::warn!("saving pins: {e}");
            return TrustReport { pinned: 0, failed: failed + pinned };
        }
        TrustReport { pinned, failed }
    }

    /// Turns trust in a subscription's server certificates on or off. On: every
    /// eligible server is probed and pinned; off: the pins of its servers are removed.
    /// Connections pick the change up the next time they are made.
    pub async fn set_subscription_trust(&self, sub_id: Uuid, on: bool) -> Result<TrustReport> {
        let ids: Vec<Uuid> = self.mutate(|d| {
            let sub = d
                .subscription_mut(sub_id)
                .ok_or_else(|| ClientError::NotFound("подписка".into()))?;
            sub.trust_certs = on;
            let ids = d.servers.iter().filter(|s| s.subscription_id == Some(sub_id)).map(|s| s.id).collect();
            if !on {
                for s in d.servers.iter_mut().filter(|s| s.subscription_id == Some(sub_id)) {
                    s.trusted_sha256 = None;
                }
            }
            Ok::<_, ClientError>(ids)
        })??;
        if on { Ok(self.pin_servers(ids).await) } else { Ok(TrustReport::default()) }
    }

    /// Desktop: connects to the selected server (or its auto-select group).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub async fn connect(&self) -> Result<crate::controller::ConnectionInfo> {
        let servers = self.connect_servers()?;
        let settings = self.settings();
        self.controller
            .connect_desktop(&servers, &settings, &self.geo())
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
        let servers = self.connect_servers()?;
        let settings = self.settings();
        self.controller.reload(&servers, &settings, &self.geo()).await
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

    /// Downloads the ad-blocking lists.
    pub async fn update_adblock(&self) -> Result<crate::model::AdblockStatus> {
        let settings = self.settings();
        match crate::adblock::update(&self.dir, &settings).await {
            Ok(status) => {
                self.mutate(|d| d.adblock = status.clone())?;
                Ok(status)
            }
            Err(e) => {
                let msg = e.to_string();
                self.mutate(|d| d.adblock.last_error = Some(msg))?;
                Err(e)
            }
        }
    }

    /// Downloads the lists when ad blocking is on and they are missing, a week old
    /// or other lists were picked.
    pub async fn update_adblock_if_due(&self) -> Option<Result<crate::model::AdblockStatus>> {
        let due = {
            let d = self.data.read();
            d.settings.adblock && crate::adblock::is_due(&d.adblock, &d.settings, now_secs())
        };
        if due { Some(self.update_adblock().await) } else { None }
    }

    /// Disconnects.
    pub async fn disconnect(&self) {
        self.controller.disconnect().await;
    }

    /// Connection state.
    pub async fn status(&self) -> Status {
        self.controller.status().await
    }

    /// The server in use while connected ([`Status::current_server`]).
    pub async fn current_server(&self) -> Option<String> {
        self.status().await.current_server().map(str::to_owned)
    }

    /// The quick settings tile's label: the server in use (with auto-select, the
    /// one working now), else the selected one, else "Unbihex"; see [`short_label`].
    pub async fn tile_label(&self) -> String {
        let name = self
            .current_server()
            .await
            .or_else(|| self.data.read().selected_server().map(|s| s.name.clone()))
            .unwrap_or_default();
        let label = short_label(&name);
        if label.is_empty() { "Unbihex".into() } else { label }
    }
}

/// A server name for a narrow label (the tile has no running text): leading
/// flags, emoji and separators go, so the start of the real name fits; spaces
/// are collapsed. A name of symbols only stays as it is.
pub fn short_label(name: &str) -> String {
    let words = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let rest = name.trim_start_matches(|c: char| !c.is_alphanumeric());
    if rest.is_empty() { words(name) } else { words(rest) }
}

/// TLS fingerprints the client offers (`fp` as in Xray).
pub const FINGERPRINTS: &[&str] =
    &["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];

fn check_fingerprint(fp: &str) -> Result<()> {
    if FINGERPRINTS.contains(&fp) {
        Ok(())
    } else {
        Err(ClientError::Input(format!("неизвестный отпечаток TLS «{fp}»: {}", FINGERPRINTS.join(", "))))
    }
}

/// A template name: trimmed, not empty, not too long, not taken by another one.
fn template_name(d: &AppData, name: &str, id: Option<Uuid>) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ClientError::Input("введите название шаблона".into()));
    }
    if name.chars().count() > MAX_TEMPLATE_NAME {
        return Err(ClientError::Input(format!("название шаблона — не длиннее {MAX_TEMPLATE_NAME} символов")));
    }
    if d.auto_templates.iter().any(|t| Some(t.id) != id && t.name == name) {
        return Err(ClientError::Input(format!("шаблон «{name}» уже есть")));
    }
    Ok(name.to_string())
}

/// `servers` without unknown ids and repeats, in the given order.
fn known_servers(d: &AppData, servers: Vec<Uuid>) -> Vec<Uuid> {
    let mut seen = std::collections::HashSet::new();
    servers.into_iter().filter(|id| d.server(*id).is_some() && seen.insert(*id)).collect()
}

fn template_mut(d: &mut AppData, id: Uuid) -> Result<&mut AutoTemplate> {
    d.auto_templates.iter_mut().find(|t| t.id == id).ok_or_else(|| ClientError::NotFound("шаблон".into()))
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

    // By dubr1k (github.com/dubr1k), PR #32.
    #[tokio::test]
    async fn saved_unsupported_cdn_is_rechecked_without_losing_identity() {
        let dir = tmp();
        let c = Client::open(&dir);
        let extra = serde_json::json!({"seqPlacement":"query", "seqKey":"offset", "uplinkHTTPMethod":"GET"});
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("extra", &extra.to_string())
            .finish();
        c.add_input(&format!(
            "vless://{UUID}@cdn.example:443?type=xhttp&mode=packet-up&security=tls&{query}"
        ))
        .await
        .unwrap();
        let id = c.snapshot().servers[0].id;
        {
            let mut data = c.data.write();
            data.servers[0].unsupported = Some("XHTTP unsupported".into());
            data.servers[0].ping_error = Some("не поддерживается".into());
            data.servers[0].name = "User label".into();
        }
        c.save().unwrap();
        drop(c);
        let c = Client::open(&dir);
        let s = c.snapshot().servers.remove(0);
        assert_eq!(s.id, id);
        assert_eq!(s.name, "User label");
        assert!(s.is_supported());
        assert!(s.ping_error.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tile_labels_lose_leading_flags_and_emoji() {
        assert_eq!(short_label("🇩🇪 Германия | Обход"), "Германия | Обход");
        assert_eq!(short_label("🔥⚡️  NL-1   fast"), "NL-1 fast");
        assert_eq!(short_label("| 🇫🇮 Finland"), "Finland");
        assert_eq!(short_label("1️⃣ Server"), "1️⃣ Server");
        assert_eq!(short_label("🚀"), "🚀");
        assert_eq!(short_label("  "), "");
    }

    #[tokio::test]
    async fn tile_label_is_the_selected_server_or_the_app_name() {
        let c = Client::open(tmp());
        assert_eq!(c.tile_label().await, "Unbihex");
        c.add_input(&format!("vless://{UUID}@a.example:443?security=tls#%F0%9F%87%A9%F0%9F%87%AA%20Berlin"))
            .await
            .unwrap();
        assert_eq!(c.tile_label().await, "Berlin");
    }

    #[tokio::test]
    async fn pasted_json_configs_become_servers() {
        let c = Client::open(tmp());
        // The example from issue #12: sing-box, no TLS block.
        let sing_box = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"uuid":"{UUID}"}}]}}"#
        );
        let r = c.add_input(&sing_box).await.unwrap();
        assert_eq!(r.servers, 1);
        let s = &c.snapshot().servers[0];
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port), ("proxy", "example.com", 443));
        let xray = format!(
            r#"{{"remarks":"DE","outbounds":[{{"tag":"proxy","protocol":"vless","settings":{{"vnext":[{{"address":"de.example","port":443,"users":[{{"id":"{UUID}","encryption":"none"}}]}}]}}}}]}}"#
        );
        assert_eq!(c.add_input(&xray).await.unwrap().servers, 1);
        assert_eq!(c.snapshot().servers[1].name, "DE");
        assert!(c.add_input(r#"{"log":{"level":"info"}}"#).await.is_err());
    }

    #[tokio::test]
    async fn manual_links_persist_and_select() {
        let dir = tmp();
        let c = Client::open(&dir);
        let r = c
            .add_input(&format!(
                "vless://{UUID}@a.com:443?security=tls#A\nhysteria://p@b.com:443#B\nnonsense"
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
    fn a_pin_survives_updates_at_the_same_address_only() {
        let mut d = AppData::default();
        let sub = Uuid::new_v4();
        let link = |host: &str, port: u16| {
            parse_server(&format!("vless://{UUID}@{host}:{port}?security=tls&type=tcp#A")).unwrap()
        };
        d.replace_servers(sub, vec![link("a.com", 443)]);
        let id = d.servers[0].id;
        d.servers[0].trusted_sha256 = Some("ab".repeat(32));
        d.replace_servers(sub, vec![link("a.com", 443)]);
        assert_eq!((d.servers[0].id, d.servers[0].trusted_sha256.clone()), (id, Some("ab".repeat(32))));
        // The panel moved the server: the same id may stay, the pin does not.
        d.replace_servers(sub, vec![link("a.com", 8443)]);
        assert_eq!(d.servers[0].trusted_sha256, None);
        d.servers[0].trusted_sha256 = Some("cd".repeat(32));
        d.replace_servers(sub, vec![link("b.com", 8443)]);
        assert_eq!(d.servers[0].trusted_sha256, None);
    }

    #[test]
    fn old_state_loads_without_trust_fields() {
        let sub = serde_json::to_value(Subscription::default()).unwrap();
        let mut sub = sub;
        sub.as_object_mut().unwrap().remove("trust_certs");
        assert!(!serde_json::from_value::<Subscription>(sub).unwrap().trust_certs);
        let s = parse_server(&format!("vless://{UUID}@a.com:443?security=tls#A")).unwrap();
        let mut v = serde_json::to_value(&s).unwrap();
        v.as_object_mut().unwrap().remove("trusted_sha256");
        assert_eq!(serde_json::from_value::<Server>(v).unwrap().trusted_sha256, None);
    }

    #[tokio::test]
    async fn trust_commands_pin_reset_and_validate() {
        let c = Client::open(tmp());
        c.add_input(&format!("vless://{UUID}@a.com:443?security=tls#A")).await.unwrap();
        c.add_input(&format!("vless://{UUID}@b.com:443?security=none&type=tcp#B")).await.unwrap();
        let (a, b) = {
            let s = c.snapshot().servers;
            (s[0].id, s[1].id)
        };
        let s = c.set_server_trust(a, Some(format!(" {} ", "AB".repeat(32)))).unwrap();
        assert_eq!(s.trusted_sha256, Some("ab".repeat(32)));
        assert!(c.set_server_trust(a, Some("xyz".into())).is_err());
        assert!(c.set_server_trust(b, Some("ab".repeat(32))).is_err(), "no TLS: nothing to trust");
        assert_eq!(c.set_server_trust(a, None).unwrap().trusted_sha256, None);
        assert!(c.set_server_trust(Uuid::new_v4(), None).is_err());
    }

    #[tokio::test]
    async fn turning_subscription_trust_off_removes_its_pins() {
        let c = Client::open(tmp());
        let sub = Subscription::default();
        let sid = sub.id;
        c.mutate(|d| {
            d.subscriptions.push(sub);
            let mut s = parse_server(&format!("vless://{UUID}@a.com:443?security=tls#A")).unwrap();
            s.subscription_id = Some(sid);
            s.trusted_sha256 = Some("ab".repeat(32));
            let mut own = parse_server(&format!("vless://{UUID}@c.com:443?security=tls#C")).unwrap();
            own.trusted_sha256 = Some("cd".repeat(32));
            d.servers.push(s);
            d.servers.push(own);
        })
        .unwrap();
        c.set_subscription_trust(sid, false).await.unwrap();
        let snap = c.snapshot();
        assert!(!snap.subscriptions[0].trust_certs);
        assert_eq!(snap.servers[0].trusted_sha256, None);
        assert!(snap.servers[1].trusted_sha256.is_some(), "hand-added servers are not the subscription's");
        assert!(c.set_subscription_trust(Uuid::new_v4(), true).await.is_err());
    }

    // By dubr1k (github.com/dubr1k), PR #33.
    #[tokio::test]
    async fn saved_unsupported_hysteria2_is_rechecked_without_losing_identity() {
        let dir = tmp();
        let c = Client::open(&dir);
        c.add_input("hy2://pw@hy.example#My%20server")
            .await
            .unwrap();
        let id = c.snapshot().servers[0].id;
        {
            let mut data = c.data.write();
            data.servers[0].unsupported = Some("Hysteria пока не поддерживается ядром".into());
            data.servers[0].ping_error = Some("не поддерживается".into());
            data.servers[0].name = "User label".into();
        }
        c.save().unwrap();
        drop(c);
        let c = Client::open(&dir);
        let s = c.snapshot().servers.remove(0);
        assert_eq!(s.id, id);
        assert_eq!(s.name, "User label");
        assert!(s.is_supported());
        assert_eq!(s.port, 443);
        assert!(s.ping_error.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn replace_follows_rewritten_links() {
        // Issue #35: the panel changes sid/spx and names on every fetch.
        let link = |host: &str, path: &str, sid: &str, name: &str| {
            parse_server(&format!(
                "vless://{UUID}@{host}:443?security=tls&type=ws&path={path}&sid={sid}#{name}"
            ))
            .unwrap()
        };
        let mut d = AppData::default();
        let sub = Uuid::new_v4();
        d.replace_servers(
            sub,
            vec![
                link("a.com", "%2Fone", "1", "A"),
                link("b.com", "%2Fone", "1", "B1"),
                link("b.com", "%2Ftwo", "1", "B2"),
            ],
        );
        let ids: Vec<Uuid> = d.servers.iter().map(|s| s.id).collect();
        d.selected = Some(ids[2]);
        d.servers[2].ping_ms = Some(70);
        // Reordered, new sid everywhere, B2 renamed: the path still tells B1 from B2.
        d.replace_servers(
            sub,
            vec![
                link("b.com", "%2Ftwo", "2", "B2 🇩🇪"),
                link("b.com", "%2Fone", "2", "B1"),
                link("a.com", "%2Fone", "2", "A"),
            ],
        );
        assert_eq!(d.selected, Some(ids[2]));
        assert_eq!(d.servers[0].id, ids[2]);
        assert_eq!(d.servers[0].ping_ms, Some(70));
        assert_eq!(d.servers[1].id, ids[1]);
        assert_eq!(d.servers[2].id, ids[0]);
        // The selected server is gone: the selection is dropped, not moved to a neighbour.
        d.replace_servers(sub, vec![link("a.com", "%2Fone", "3", "A")]);
        assert_eq!(d.servers[0].id, ids[0]);
        assert_eq!(d.selected, None);
    }

    #[test]
    fn auto_group_follows_exclusions_and_templates() {
        let link = |host: &str| parse_server(&format!("vless://{UUID}@{host}:443?security=tls&sid=1#{host}")).unwrap();
        let c = Client::open(tmp());
        let (s1, s2) = (Uuid::new_v4(), Uuid::new_v4());
        let ids = c
            .mutate(|d| {
                d.replace_servers(s1, vec![link("a.com"), link("b.com"), link("c.com")]);
                let mut x = parse_server("hysteria://p@x.com:443#X").unwrap();
                x.subscription_id = Some(s2);
                d.servers.push(x);
                d.servers.push(Server { subscription_id: Some(s2), ..link("d.com") });
                d.settings.auto_select = crate::model::AutoSelect::LeastPing;
                d.servers.iter().map(|s| s.id).collect::<Vec<_>>()
            })
            .unwrap();
        let group = |c: &Client| c.connect_servers().unwrap().iter().map(|s| s.id).collect::<Vec<_>>();
        c.select(ids[1]).unwrap();
        assert_eq!(group(&c), [ids[1], ids[0], ids[2]]);
        // Excluded: out of the group, but still first while selected.
        c.set_server_auto(ids[0], true).unwrap();
        assert_eq!(group(&c), [ids[1], ids[2]]);
        c.set_server_auto(ids[1], true).unwrap();
        assert_eq!(group(&c), [ids[1], ids[2]]);
        // A template: across subscriptions, exclusions ignored, unsupported ones left out.
        let t = c.create_template(" Быстрые ", vec![ids[3], Uuid::new_v4(), ids[3]]).unwrap();
        assert_eq!((t.name.as_str(), t.servers.clone()), ("Быстрые", vec![ids[3]]));
        assert!(c.create_template("Быстрые", vec![]).is_err(), "names are unique");
        assert!(c.create_template("  ", vec![]).is_err());
        assert_eq!(group(&c), [ids[1], ids[2]], "not active yet");
        let mut s = c.settings();
        s.auto_template = Some(t.id);
        c.set_settings(s).unwrap();
        assert_eq!(group(&c), [ids[1]]);
        for i in [0, 4] {
            c.set_template_server(t.id, ids[i], true).unwrap();
        }
        c.set_template_server(t.id, ids[4], true).unwrap();
        assert_eq!(group(&c), [ids[1], ids[0], ids[4]]);
        assert!(c.set_template_server(t.id, Uuid::new_v4(), true).is_err());
        // Another template is not used while this one is active.
        let other = c.create_template("Другой", vec![ids[2]]).unwrap();
        assert!(c.update_template(other.id, Some("Быстрые".into()), None).is_err());
        let other = c.update_template(other.id, Some("Запасные".into()), Some(vec![ids[2], ids[4]])).unwrap();
        assert_eq!(other.servers, [ids[2], ids[4]]);
        assert_eq!(group(&c), [ids[1], ids[0], ids[4]]);
        // So does a server's own TLS fingerprint; an unknown one is refused.
        c.set_server_fingerprint(ids[0], Some(" Firefox ".into())).unwrap();
        assert!(c.set_server_fingerprint(ids[0], Some("netscape".into())).is_err());
        // The flags survive an update with rewritten links.
        let fresh = |host: &str| parse_server(&format!("vless://{UUID}@{host}:443?security=tls&sid=2#{host}")).unwrap();
        c.mutate(|d| d.replace_servers(s1, vec![fresh("c.com"), fresh("a.com"), fresh("b.com")])).unwrap();
        let d = c.snapshot();
        let a = d.server(ids[0]).unwrap();
        assert!(a.auto_excluded);
        assert_eq!(a.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(d.active_template().unwrap().servers, [ids[3], ids[0], ids[4]]);
        // Updated servers go after the other subscription's: list order.
        assert_eq!(group(&c), [ids[1], ids[4], ids[0]]);
        // A server gone from the subscription leaves the templates.
        c.mutate(|d| d.replace_servers(s1, vec![fresh("c.com"), fresh("b.com")])).unwrap();
        assert_eq!(c.snapshot().active_template().unwrap().servers, [ids[3], ids[4]]);
        c.set_template_server(t.id, ids[4], false).unwrap();
        assert_eq!(group(&c), [ids[1]]);
        // Deleting the active template: all servers of the subscription again.
        c.delete_template(t.id).unwrap();
        assert_eq!(c.settings().auto_template, None);
        assert_eq!(group(&c), [ids[1], ids[2]]);
        assert!(c.delete_template(t.id).is_err());
        // An unknown active template (deleted elsewhere) is dropped on save.
        let mut s = c.settings();
        s.auto_template = Some(t.id);
        c.set_settings(s).unwrap();
        assert_eq!(c.settings().auto_template, None);
        // Off: only the selected server.
        c.mutate(|d| d.settings.auto_select = crate::model::AutoSelect::Off).unwrap();
        assert_eq!(group(&c), [ids[1]]);
        assert!(c.set_server_auto(Uuid::new_v4(), true).is_err());
    }

    /// State files from before templates: the marks become the template
    /// "Отмеченные", active when "only the marked servers" was on.
    #[test]
    fn old_marks_become_a_template() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let srv = |id: Uuid, marked: bool| {
            format!(
                r#"{{"id":"{id}","subscription_id":null,"name":"x","link":"vless://{UUID}@x.com:443?security=tls#x","protocol":"vless",
                "host":"x.com","port":443,"transport":"tcp+tls","unsupported":null,"ping_ms":null,"ping_error":null,
                "auto_excluded":{marked},"auto_marked":{marked}}}"#
            )
        };
        let state = |group: &str| {
            format!(
                r#"{{"servers":[{},{},{}],"selected":"{a}","settings":{{"auto_select":"fallback","auto_group":"{group}","lan_password":"0123456789"}}}}"#,
                srv(a, true),
                srv(b, false),
                srv(c, true)
            )
        };
        // Marked mode: the template is active, the group stays the same.
        let dir = tmp();
        std::fs::write(dir.join(STATE_FILE), state("marked")).unwrap();
        let cl = Client::open(&dir);
        let d = cl.snapshot();
        assert_eq!(d.auto_templates.len(), 1);
        let t = &d.auto_templates[0];
        assert_eq!((t.name.as_str(), t.servers.clone()), (crate::model::MARKED_TEMPLATE, vec![a, c]));
        assert_eq!(d.settings.auto_template, Some(t.id));
        assert!(d.server(a).unwrap().auto_excluded, "exclusions stay");
        let group: Vec<Uuid> = cl.connect_servers().unwrap().iter().map(|s| s.id).collect();
        assert_eq!(group, [a, c]);
        // Saved at once and only once: opening again keeps the same template.
        let saved = std::fs::read_to_string(dir.join(STATE_FILE)).unwrap();
        assert!(!saved.contains("auto_marked") && !saved.contains("auto_group"), "{saved}");
        let again = Client::open(&dir).snapshot();
        assert_eq!(again.auto_templates, d.auto_templates);
        assert_eq!(again.settings.auto_template, Some(t.id));
        drop(cl);
        // Subscription mode: the marks are kept as a template, not active.
        let dir = tmp();
        std::fs::write(dir.join(STATE_FILE), state("subscription")).unwrap();
        let d = Client::open(&dir).snapshot();
        assert_eq!(d.auto_templates.len(), 1);
        assert_eq!(d.auto_templates[0].servers, [a, c]);
        assert_eq!(d.settings.auto_template, None);
        // Marked mode without marks: an empty active template, as the group was.
        let dir = tmp();
        let none = state("marked").replace(r#""auto_marked":true"#, r#""auto_marked":false"#);
        std::fs::write(dir.join(STATE_FILE), none).unwrap();
        let d = Client::open(&dir).snapshot();
        assert_eq!(d.auto_templates.len(), 1);
        assert!(d.auto_templates[0].servers.is_empty());
        assert_eq!(d.settings.auto_template, Some(d.auto_templates[0].id));
        // No marks, no marked mode: nothing to migrate.
        let dir = tmp();
        let plain = state("subscription").replace(r#""auto_marked":true"#, r#""auto_marked":false"#);
        std::fs::write(dir.join(STATE_FILE), plain).unwrap();
        assert!(Client::open(&dir).snapshot().auto_templates.is_empty());
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
