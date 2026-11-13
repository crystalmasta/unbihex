//! Developer mode: the connection journal. Engine events (SPEC §7, item 8) get
//! the owning application and the server names, stay in a ring of the last
//! [`CAPACITY`] records for the "Журнал → Соединения" view, and go into a report
//! per VPN session: JSON Lines with secrets masked, in the user's folder or the
//! app's own, the last N kept.
//!
//! Nothing runs while developer mode is off: the engine is not subscribed to.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Map, Value, json};
use unbihex_engine::events::{Event, Events, now_ms};

use crate::controller::ConnectionInfo;
use crate::error::{ClientError, Result};

/// Records kept in memory, and the engine channel's size.
pub const CAPACITY: usize = 20_000;
/// Reports kept by default.
pub const DEFAULT_KEEP: u32 = 10;
/// Allowed range of reports kept.
pub const KEEP_RANGE: std::ops::RangeInclusive<u32> = 1..=100;
/// Report files are `unbihex-report-*.jsonl`; only those are ever deleted.
pub const REPORT_PREFIX: &str = "unbihex-report-";
/// See [`REPORT_PREFIX`].
pub const REPORT_EXT: &str = ".jsonl";
/// How long an owner found for a local port is trusted.
const OWNER_TTL: Duration = Duration::from_secs(30);
/// Events taken from the engine in one go.
const BATCH: usize = 1024;

/// A connection whose owning application is asked for.
#[derive(Clone, Debug, Serialize)]
pub struct OwnerQuery {
    /// UDP (else TCP).
    pub udp: bool,
    /// The application's local address.
    pub src: SocketAddr,
    /// The address the application connected to (a fake IP in the TUN).
    pub dst: Option<SocketAddr>,
}

/// Finds the applications that own connections (per platform; may block).
pub trait OwnerLookup: Send + Sync {
    /// One answer per query: the application's name, `None` when unknown.
    fn owners(&self, queries: &[OwnerQuery]) -> Vec<Option<String>>;
}

/// Hands a finished report to the user's folder when the app cannot write
/// there itself (Android: a Storage Access Framework tree). Arguments: the
/// report file, the folder setting, how many reports to keep.
pub type ExportHook = Arc<dyn Fn(&Path, &str, u32) + Send + Sync>;

/// What the journal takes from the saved data.
#[derive(Clone, Debug, Default)]
pub struct JournalContext {
    /// Developer mode is on.
    pub enabled: bool,
    /// Reports to keep.
    pub keep: u32,
    /// The user's folder: a path, or (Android) a `content://` tree; empty: the app's own.
    pub dir: String,
    /// The routing preset, for the report header.
    pub routing: String,
    /// The auto-select template, for the report header.
    pub template: Option<String>,
    /// Secrets to mask in reports ([`crate::redact::secrets`]).
    pub secrets: Vec<String>,
}

/// New records for the view.
#[derive(Debug, Serialize)]
pub struct JournalPage {
    /// Records from the one asked for, oldest first; each has `seq`.
    pub records: Vec<Value>,
    /// The `seq` to ask from next time.
    pub next: u64,
    /// The records asked for are gone (cleared or pushed out): start over.
    pub reset: bool,
    /// Events lost: the engine's subscriber fell behind.
    pub lost: u64,
    /// The engine is being journaled now.
    pub active: bool,
}

/// A saved report.
#[derive(Debug, Serialize)]
pub struct ReportFile {
    /// File name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Last change, Unix seconds.
    pub modified: u64,
}

struct Session {
    file: std::io::BufWriter<std::fs::File>,
    path: PathBuf,
}

#[derive(Default)]
struct Inner {
    records: VecDeque<(u64, Value)>,
    /// `seq` of the next record.
    seq: u64,
    /// Owners found by connection number, until the connection closes.
    apps: HashMap<u64, String>,
    /// Owners found by (udp, local port).
    owners: HashMap<(bool, u16), (Option<String>, Instant)>,
    /// Outbound tag → server name.
    names: HashMap<String, String>,
    session: Option<Session>,
    /// The engine's lost-event counter of the attached instance.
    events: Option<Arc<Events>>,
}

struct Attached {
    events: Arc<Events>,
    task: tokio::task::JoinHandle<()>,
}

/// The connection journal of one app.
pub struct Journal {
    internal: PathBuf,
    ctx: Mutex<JournalContext>,
    inner: Mutex<Inner>,
    owner: Mutex<Option<Arc<dyn OwnerLookup>>>,
    export: Mutex<Option<ExportHook>>,
    attached: tokio::sync::Mutex<Option<Attached>>,
}

/// `unbihex-report-YYYY-MM-DD-HHMMSS.jsonl` (UTC) for the Unix time `secs`,
/// with `-tag` before the extension when given.
pub fn report_file_name(secs: u64, tag: &str) -> String {
    let base = crate::redact::log_file_name(secs);
    let stamp = base.trim_start_matches("unbihex-log-").trim_end_matches(".txt");
    let tag = if tag.is_empty() { String::new() } else { format!("-{tag}") };
    format!("{REPORT_PREFIX}{stamp}{:02}{tag}{REPORT_EXT}", secs % 60)
}

/// Whether `name` is one of our report files (and nothing else, no path).
pub fn is_report_name(name: &str) -> bool {
    name.starts_with(REPORT_PREFIX)
        && name.ends_with(REPORT_EXT)
        && !name.contains(['/', '\\', ':'])
        && !name.contains("..")
}

/// Deletes our oldest reports in `dir` beyond `keep`; other files stay.
pub fn prune(dir: &Path, keep: u32) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_report_name(n))
        .collect();
    names.sort();
    let keep = keep.clamp(*KEEP_RANGE.start(), *KEEP_RANGE.end()) as usize;
    let extra = names.len().saturating_sub(keep);
    for n in &names[..extra] {
        if let Err(e) = std::fs::remove_file(dir.join(n)) {
            tracing::debug!("report {n}: not removed: {e}");
        }
    }
}

/// The OS name and version for report headers.
pub fn os_version() -> String {
    let base = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/etc/os-release")
        && let Some(name) = text.lines().find_map(|l| l.strip_prefix("PRETTY_NAME="))
    {
        return format!("{base} ({})", name.trim_matches('"'));
    }
    #[cfg(target_os = "android")]
    if let Ok(out) = std::process::Command::new("getprop").arg("ro.build.version.release").output()
        && out.status.success()
    {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !v.is_empty() {
            return format!("{base} (Android {v})");
        }
    }
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
            let name: String = k.get_value("ProductName").unwrap_or_default();
            let display: String = k.get_value("DisplayVersion").unwrap_or_default();
            let build: String = k.get_value("CurrentBuild").unwrap_or_default();
            return format!("{base} ({name} {display}, build {build})");
        }
    }
    base
}

fn conn_of(v: &Map<String, Value>) -> Option<u64> {
    v.get("conn").and_then(Value::as_u64)
}

impl Journal {
    /// A journal whose own report folder is `internal`.
    pub fn new(internal: PathBuf) -> Journal {
        Journal {
            internal,
            ctx: Mutex::new(JournalContext { keep: DEFAULT_KEEP, ..Default::default() }),
            inner: Mutex::new(Inner::default()),
            owner: Mutex::new(None),
            export: Mutex::new(None),
            attached: tokio::sync::Mutex::new(None),
        }
    }

    /// Replaces what the journal knows of the saved data.
    pub fn set_context(&self, ctx: JournalContext) {
        *self.ctx.lock() = ctx;
    }

    /// Whether developer mode is on.
    pub fn enabled(&self) -> bool {
        self.ctx.lock().enabled
    }

    /// Sets how owning applications are found (per platform).
    pub fn set_owner_lookup(&self, lookup: Arc<dyn OwnerLookup>) {
        *self.owner.lock() = Some(lookup);
    }

    /// Sets the hand-over of finished reports to the user's folder (Android).
    pub fn set_export_hook(&self, hook: ExportHook) {
        *self.export.lock() = Some(hook);
    }

    /// Where reports are written: the user's folder when it is a path, else the app's own.
    pub fn report_dir(&self) -> PathBuf {
        let dir = self.ctx.lock().dir.clone();
        if dir.is_empty() || dir.contains("://") { self.internal.clone() } else { PathBuf::from(dir) }
    }

    /// Server names of the connection's outbound tags (`proxy`, `proxy-<n>`).
    fn set_names(&self, info: &ConnectionInfo) {
        let mut names = HashMap::new();
        names.insert("proxy".to_string(), info.server_name.clone());
        for (i, n) in info.group.iter().enumerate() {
            names.insert(format!("proxy-{i}"), n.clone());
        }
        self.inner.lock().names = names;
    }

    /// Starts journaling a just-started engine, with a session report, when
    /// developer mode is on.
    pub async fn attach(self: &Arc<Self>, events: Arc<Events>, info: &ConnectionInfo) {
        if !self.enabled() {
            return;
        }
        let mut attached = self.attached.lock().await;
        if attached.is_some() {
            return;
        }
        self.set_names(info);
        let rx = events.subscribe(CAPACITY);
        self.inner.lock().events = Some(events.clone());
        self.start_session(info);
        let this = self.clone();
        let task = tokio::spawn(async move { this.drain(rx).await });
        *attached = Some(Attached { events, task });
    }

    /// Stops journaling (disconnect, developer mode off) and finishes the report.
    pub async fn detach(&self) {
        let Some(a) = self.attached.lock().await.take() else { return };
        a.events.unsubscribe();
        let mut task = a.task;
        if tokio::time::timeout(Duration::from_secs(3), &mut task).await.is_err() {
            task.abort();
            self.finish_session();
        }
    }

    /// Whether an engine is journaled now.
    pub async fn active(&self) -> bool {
        self.attached.lock().await.is_some()
    }

    /// A hot reload: new server names and a line saying what changed.
    pub fn reloaded(&self, info: &ConnectionInfo) {
        if !self.enabled() {
            return;
        }
        self.set_names(info);
        let ctx = self.ctx.lock().clone();
        let template = ctx.template.map(|t| format!(", шаблон «{t}»")).unwrap_or_default();
        self.note("routing", &format!("Настройки применены без переподключения: сервер «{}», маршрутизация «{}»{template}", info.server_name, ctx.routing));
    }

    /// A line of the app into the journal (routing changed and the like).
    pub fn note(&self, category: &str, text: &str) {
        if !self.enabled() {
            return;
        }
        let events = self.inner.lock().events.clone();
        match events {
            Some(e) if e.enabled() => e.note(category, text),
            _ => {
                let v = json!({"ev": "note", "ts": now_ms(), "category": category, "text": text});
                self.push(vec![v]);
            }
        }
    }

    fn header(&self, kind: &str, info: Option<&ConnectionInfo>, filter: Option<&str>) -> Value {
        let ctx = self.ctx.lock().clone();
        let mut h = json!({
            "ev": "header",
            "format": 1,
            "kind": kind,
            "ts": now_ms(),
            "client": env!("CARGO_PKG_VERSION"),
            "engine": unbihex_engine::VERSION,
            "platform": std::env::consts::OS,
            "os": os_version(),
            "routing": ctx.routing,
            "template": ctx.template,
        });
        if let Some(i) = info {
            h["mode"] = json!(i.mode);
            h["server"] = json!(i.server_name);
            h["group"] = json!(i.group);
        }
        if let Some(f) = filter {
            h["filter"] = json!(f);
        }
        h
    }

    fn line(&self, v: &Value) -> String {
        let secrets = self.ctx.lock().secrets.clone();
        crate::redact::redact(&v.to_string(), &secrets)
    }

    fn start_session(&self, info: &ConnectionInfo) {
        let dir = self.report_dir();
        let name = report_file_name(now_ms() / 1000, "");
        let path = dir.join(&name);
        let header = self.line(&self.header("session", Some(info), None));
        let opened = std::fs::create_dir_all(&dir).and_then(|_| std::fs::File::create(&path)).and_then(|f| {
            let mut w = std::io::BufWriter::new(f);
            writeln!(w, "{header}")?;
            Ok(w)
        });
        match opened {
            Ok(file) => self.inner.lock().session = Some(Session { file, path }),
            Err(e) => tracing::warn!("connection report {}: {e}", path.display()),
        }
    }

    fn finish_session(&self) {
        let lost = self.lost();
        let Some(mut s) = self.inner.lock().session.take() else { return };
        let end = json!({"ev": "end", "ts": now_ms(), "lost": lost});
        let _ = writeln!(s.file, "{end}");
        if let Err(e) = s.file.flush() {
            tracing::warn!("connection report {}: {e}", s.path.display());
        }
        drop(s.file);
        self.saved(&s.path);
    }

    /// Prunes the folder of a written report and hands it on (Android).
    fn saved(&self, path: &Path) {
        let ctx = self.ctx.lock().clone();
        if let Some(dir) = path.parent() {
            prune(dir, ctx.keep);
        }
        let hook = self.export.lock().clone();
        if let Some(hook) = hook
            && ctx.dir.contains("://")
        {
            hook(path, &ctx.dir, ctx.keep);
        }
    }

    fn lost(&self) -> u64 {
        self.inner.lock().events.as_ref().map_or(0, |e| e.dropped())
    }

    async fn drain(self: Arc<Self>, mut rx: tokio::sync::mpsc::Receiver<Event>) {
        let mut batch = Vec::with_capacity(BATCH);
        loop {
            if rx.recv_many(&mut batch, BATCH).await == 0 {
                break;
            }
            let events = std::mem::take(&mut batch);
            self.ingest(events).await;
        }
        self.finish_session();
        self.inner.lock().events = None;
    }

    /// Engine events → records with server names and owners, into the ring and the report.
    async fn ingest(&self, events: Vec<Event>) {
        let mut records: Vec<Map<String, Value>> = Vec::with_capacity(events.len());
        let mut asks: Vec<(usize, OwnerQuery)> = Vec::new();
        {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            inner.owners.retain(|_, (_, at)| now.duration_since(*at) < OWNER_TTL);
            for ev in &events {
                let Ok(Value::Object(mut v)) = serde_json::to_value(ev) else { continue };
                self.name_servers(&inner.names, &mut v);
                let (src, udp, conn, open) = match ev {
                    Event::Open(o) => (o.src, o.net == "udp", o.conn, true),
                    Event::Close(c) => (c.src, c.net == "udp", c.conn, false),
                    _ => (None, false, 0, false),
                };
                if let Some(src) = src {
                    let known = match open {
                        true => None,
                        false => inner.apps.remove(&conn),
                    };
                    let cached = inner.owners.get(&(udp, src.port())).map(|(a, _)| a.clone());
                    match (known, cached) {
                        (Some(app), _) | (None, Some(Some(app))) => {
                            if open {
                                inner.apps.insert(conn, app.clone());
                            }
                            v.insert("app".into(), json!(app));
                        }
                        (None, Some(None)) => {}
                        (None, None) => {
                            let dst = v.get("dst").and_then(Value::as_str).and_then(|d| d.parse().ok());
                            asks.push((records.len(), OwnerQuery { udp, src, dst }));
                        }
                    }
                }
                records.push(v);
            }
        }
        let lookup = self.owner.lock().clone();
        if let (Some(lookup), false) = (lookup, asks.is_empty()) {
            let queries: Vec<OwnerQuery> = asks.iter().map(|(_, q)| q.clone()).collect();
            let answers = tokio::task::spawn_blocking(move || lookup.owners(&queries)).await.unwrap_or_default();
            let mut inner = self.inner.lock();
            let now = Instant::now();
            for ((i, q), app) in asks.iter().zip(answers) {
                inner.owners.insert((q.udp, q.src.port()), (app.clone(), now));
                let Some(app) = app else { continue };
                let rec = &mut records[*i];
                if rec.get("ev").and_then(Value::as_str) == Some("open")
                    && let Some(conn) = conn_of(rec)
                {
                    inner.apps.insert(conn, app.clone());
                }
                rec.insert("app".into(), json!(app));
            }
        }
        self.push(records.into_iter().map(Value::Object).collect());
    }

    /// `server` (and `from_server`/`to_server` of a switch): the server names of the tags.
    fn name_servers(&self, names: &HashMap<String, String>, v: &mut Map<String, Value>) {
        let name = |tag: Option<&Value>| tag.and_then(Value::as_str).and_then(|t| names.get(t)).cloned();
        if v.get("route").and_then(Value::as_str) == Some("proxy") {
            let server = name(v.get("member")).or_else(|| name(v.get("outbound")));
            if let Some(s) = server {
                v.insert("server".into(), json!(s));
            }
        }
        if v.get("ev").and_then(Value::as_str) == Some("switch") {
            if let Some(s) = name(v.get("from")) {
                v.insert("from_server".into(), json!(s));
            }
            if let Some(s) = name(v.get("to")) {
                v.insert("to_server".into(), json!(s));
            }
        }
    }

    /// Adds records to the ring and the session report.
    fn push(&self, records: Vec<Value>) {
        if records.is_empty() {
            return;
        }
        let lines: Vec<String> = records.iter().map(|r| self.line(r)).collect();
        let mut inner = self.inner.lock();
        if let Some(s) = inner.session.as_mut() {
            let mut ok = true;
            for l in &lines {
                ok &= writeln!(s.file, "{l}").is_ok();
            }
            if !(ok && s.file.flush().is_ok()) {
                tracing::warn!("connection report {}: write failed", s.path.display());
            }
        }
        for mut r in records {
            let seq = inner.seq;
            inner.seq += 1;
            r["seq"] = json!(seq);
            if inner.records.len() >= CAPACITY {
                inner.records.pop_front();
            }
            inner.records.push_back((seq, r));
        }
    }

    /// Records from `since` on (at most [`CAPACITY`]).
    pub async fn page(&self, since: u64) -> JournalPage {
        let active = self.active().await;
        let lost = self.lost();
        let inner = self.inner.lock();
        let first = inner.records.front().map_or(inner.seq, |(s, _)| *s);
        let reset = since < first || since > inner.seq;
        let from = if reset { first } else { since };
        let records = inner.records.iter().filter(|(s, _)| *s >= from).map(|(_, r)| r.clone()).collect();
        JournalPage { records, next: inner.seq, reset, lost, active }
    }

    /// Forgets the records in memory (the report goes on).
    pub fn clear(&self) {
        self.inner.lock().records.clear();
    }

    /// "Сохранить отчёт сейчас": the records `seqs` (the view's filter, described
    /// by `filter`) as a report file. Returns its path.
    pub fn save_snapshot(&self, seqs: &[u64], filter: &str) -> Result<PathBuf> {
        let wanted: HashSet<u64> = seqs.iter().copied().collect();
        let records: Vec<Value> = {
            let inner = self.inner.lock();
            inner.records.iter().filter(|(s, _)| wanted.contains(s)).map(|(_, r)| r.clone()).collect()
        };
        let dir = self.report_dir();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(report_file_name(now_ms() / 1000, "snapshot"));
        let mut text = self.line(&self.header("snapshot", None, Some(filter)));
        text.push('\n');
        for r in &records {
            text.push_str(&self.line(r));
            text.push('\n');
        }
        std::fs::write(&path, text).map_err(|e| ClientError::State(format!("отчёт не сохранён: {e}")))?;
        self.saved(&path);
        Ok(path)
    }

    /// The reports in the report folder, newest first.
    pub fn reports(&self) -> Vec<ReportFile> {
        let Ok(rd) = std::fs::read_dir(self.report_dir()) else { return Vec::new() };
        let mut out: Vec<ReportFile> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let meta = e.metadata().ok()?;
                (is_report_name(&name) && meta.is_file()).then(|| ReportFile {
                    name,
                    size: meta.len(),
                    modified: meta
                        .modified()
                        .ok()
                        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                        .map_or(0, |d| d.as_secs()),
                })
            })
            .collect();
        out.sort_by(|a, b| b.name.cmp(&a.name));
        out
    }

    /// The path of the report `name` in the report folder.
    pub fn report_path(&self, name: &str) -> Result<PathBuf> {
        if !is_report_name(name) {
            return Err(ClientError::Input(format!("не отчёт: {name}")));
        }
        Ok(self.report_dir().join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unbihex_engine::events::{ConnClose, ConnOpen};

    struct Owners;
    impl OwnerLookup for Owners {
        fn owners(&self, q: &[OwnerQuery]) -> Vec<Option<String>> {
            q.iter().map(|q| (q.src.port() == 5000).then(|| "Telegram".to_string())).collect()
        }
    }

    fn info() -> ConnectionInfo {
        ConnectionInfo {
            server_id: uuid::Uuid::nil(),
            server_name: "Сервер".into(),
            mode: "vpn".into(),
            since: 0,
            socks_port: None,
            http_port: None,
            external: false,
            group: vec!["A".into(), "B".into()],
        }
    }

    fn open(conn: u64, port: u16) -> Event {
        Event::Open(ConnOpen {
            conn,
            ts: 1,
            net: "tcp",
            inbound: "tun-in".into(),
            src: Some(SocketAddr::from(([10, 0, 0, 1], port))),
            dst: "198.18.0.5:443".into(),
            host: Some("max.ru".into()),
        })
    }

    fn close(conn: u64, port: u16) -> Event {
        Event::Close(ConnClose {
            conn,
            start: 1,
            end: 2,
            net: "tcp",
            inbound: "tun-in".into(),
            src: Some(SocketAddr::from(([10, 0, 0, 1], port))),
            dst: "198.18.0.5:443".into(),
            host: Some("max.ru".into()),
            rule: Some("#2 rule_set:ru-blocked".into()),
            outbound: Some("proxy".into()),
            route: "proxy",
            member: Some("proxy-1".into()),
            up: 10,
            down: 20,
            ms: 1,
            reason: "timeout",
            error: Some("connect timed out".into()),
        })
    }

    #[test]
    fn report_names_and_pruning_touch_only_our_files() {
        assert_eq!(report_file_name(0, ""), "unbihex-report-1970-01-01-000000.jsonl");
        assert_eq!(report_file_name(61, "snapshot"), "unbihex-report-1970-01-01-000101-snapshot.jsonl");
        assert!(!is_report_name("../unbihex-report-x.jsonl"));
        assert!(!is_report_name("unbihex-report-x.txt"));
        let dir = std::env::temp_dir().join(format!("unbihex-reports-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap_or_default();
        for i in 0..5 {
            std::fs::write(dir.join(report_file_name(i * 100, "")), "x").unwrap_or_default();
        }
        std::fs::write(dir.join("notes.jsonl"), "keep").unwrap_or_default();
        prune(&dir, 2);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
            .unwrap_or_default();
        left.sort();
        assert_eq!(left, vec!["notes.jsonl", &report_file_name(300, ""), &report_file_name(400, "")]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn events_get_owners_and_server_names_and_go_into_the_report() {
        let dir = std::env::temp_dir().join(format!("unbihex-journal-{}", uuid::Uuid::new_v4()));
        let j = Arc::new(Journal::new(dir.clone()));
        j.set_context(JournalContext {
            enabled: true,
            keep: 3,
            routing: "Только заблокированные".into(),
            secrets: vec!["supersecret-token".into()],
            ..Default::default()
        });
        j.set_owner_lookup(Arc::new(Owners));
        let events = Arc::new(Events::default());
        j.attach(events.clone(), &info()).await;
        assert!(j.active().await);
        events.emit(open(1, 5000));
        events.emit(open(2, 6000));
        j.note("routing", "path supersecret-token");
        // Wait for the drain task to take them.
        for _ in 0..100 {
            if j.page(0).await.records.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        events.emit(close(1, 5000));
        j.detach().await;
        assert!(!j.active().await);
        let page = j.page(0).await;
        assert_eq!(page.records.len(), 4, "{:?}", page.records);
        assert_eq!(page.records[0]["app"], "Telegram");
        assert!(page.records[1].get("app").is_none());
        let closed = &page.records[3];
        assert_eq!((closed["app"].as_str(), closed["server"].as_str()), (Some("Telegram"), Some("B")));
        assert_eq!(j.page(page.next).await.records.len(), 0);
        let reports = j.reports();
        assert_eq!(reports.len(), 1);
        let text = std::fs::read_to_string(dir.join(&reports[0].name)).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6, "{text}");
        assert!(lines[0].contains(r#""ev":"header""#) && lines[0].contains("Только заблокированные"));
        assert!(!text.contains("supersecret-token"));
        assert!(lines[5].contains(r#""ev":"end""#));
        let snap = j.save_snapshot(&[page.records[3]["seq"].as_u64().unwrap_or(0)], "только ошибки");
        let snap = std::fs::read_to_string(snap.unwrap_or_default()).unwrap_or_default();
        assert_eq!(snap.lines().count(), 2);
        assert!(snap.contains("только ошибки"));
        j.clear();
        assert!(j.page(0).await.records.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
