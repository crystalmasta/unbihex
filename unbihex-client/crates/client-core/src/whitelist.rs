//! Operator whitelists (issues #48, #57): a mobile network that lets through
//! only allowed sites and addresses. Direct checks around the tunnel tell it
//! apart: TCP to port 443 and a TLS ClientHello to sites from a whitelist and
//! to sites outside it, all at once, 3 s each. A state is taken after two
//! equal results in a row; "nothing works" changes nothing.
//!
//! While the mode is on, auto-select can move to its own template and routing
//! (the user's choice comes back when it ends, unless the user changed it in
//! the meantime), and the window, tray and notification show it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::address::{Address, TargetAddr};
use uuid::Uuid;

use crate::client::Client;
use crate::error::Result;
use crate::model::{AutoSelect, RoutingMode, Settings, WhitelistMode, WhitelistSaved};
use crate::subscription::Dial;

/// Sites a whitelist lets through.
pub const DEFAULT_ALLOWED: &[&str] = &["ya.ru", "vk.com", "gosuslugi.ru"];
/// Sites and addresses a whitelist blocks.
pub const DEFAULT_BLOCKED: &[&str] = &["google.com", "cloudflare.com", "1.1.1.1", "8.8.8.8", "9.9.9.9"];

/// One check of one host.
const TIMEOUT: Duration = Duration::from_secs(3);
/// Equal results in a row before the state changes.
const CONFIRM: u8 = 2;
/// How often the loop looks at the clock, the network and wake-ups.
const TICK: Duration = Duration::from_secs(10);
/// Checks while the window is open or the screen is on.
const FOREGROUND_EVERY: Duration = Duration::from_secs(60);
/// Checks in the background.
const BACKGROUND_EVERY: Duration = Duration::from_secs(300);
/// The confirming check after a changed result.
const CONFIRM_EVERY: Duration = Duration::from_secs(10);
/// Direct connections timing out in a row (within [`TIMEOUT_WINDOW`]) that
/// trigger a check out of turn.
const TIMEOUTS: usize = 3;
const TIMEOUT_WINDOW: Duration = Duration::from_secs(30);

/// What the checks see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetState {
    /// Sites outside the whitelist open too.
    Normal,
    /// Whitelisted sites open, most of the others do not.
    Whitelist,
    /// Whitelisted sites do not open either: no network, nothing to decide.
    Offline,
}

/// The result of one round of checks: `ok` of `total` hosts in each group.
pub fn classify(allowed_ok: usize, allowed_total: usize, blocked_ok: usize, blocked_total: usize) -> NetState {
    if allowed_total == 0 || allowed_ok == 0 {
        NetState::Offline
    } else if blocked_total > 0 && blocked_ok * 2 < blocked_total {
        NetState::Whitelist
    } else {
        NetState::Normal
    }
}

/// Hysteresis: a state is taken after [`CONFIRM`] equal results in a row;
/// [`NetState::Offline`] breaks a run and never becomes the state.
#[derive(Clone, Debug, Default)]
pub struct Detector {
    state: Option<NetState>,
    pending: Option<(NetState, u8)>,
}

impl Detector {
    /// The confirmed state; `None` until the first one.
    pub fn state(&self) -> Option<NetState> {
        self.state
    }

    /// A result differs from the state and waits for its confirmation.
    pub fn confirming(&self) -> bool {
        self.pending.is_some()
    }

    /// Records a result; the new state when it changed.
    pub fn observe(&mut self, r: NetState) -> Option<NetState> {
        if r == NetState::Offline || self.state == Some(r) {
            self.pending = None;
            return None;
        }
        let n = match self.pending {
            Some((p, n)) if p == r => n + 1,
            _ => 1,
        };
        if n >= CONFIRM {
            self.state = Some(r);
            self.pending = None;
            Some(r)
        } else {
            self.pending = Some((r, n));
            None
        }
    }
}

/// What the window shows about the checks.
#[derive(Clone, Debug, Default, Serialize)]
pub struct WatchView {
    /// The last result.
    pub last: Option<NetState>,
    /// The confirmed state.
    pub confirmed: Option<NetState>,
    /// Unix seconds of the last check.
    pub checked_at: Option<u64>,
}

#[derive(Default)]
struct WatchState {
    detector: Detector,
    last: Option<NetState>,
    checked_at: Option<u64>,
    timeouts: Vec<Instant>,
    last_wake: Option<Instant>,
}

/// The detection's run-time state, owned by the [`Client`].
#[derive(Default)]
pub struct Watch {
    state: parking_lot::Mutex<WatchState>,
    wake: tokio::sync::Notify,
    /// Unix seconds until which the app counts as in the foreground.
    foreground_until: AtomicU64,
    /// [`Client::run_whitelist`] runs.
    running: AtomicBool,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Watch {
    /// Check now: the network changed.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// The window is open (its status polls call this): checks once a minute
    /// for the next 15 s.
    pub fn touch_foreground(&self) {
        self.foreground_until.store(unix_now() + 15, Ordering::Relaxed);
    }

    /// The screen went on (`true`, checks once a minute) or off.
    pub fn set_foreground(&self, on: bool) {
        self.foreground_until.store(if on { u64::MAX } else { 0 }, Ordering::Relaxed);
    }

    fn foreground(&self) -> bool {
        self.foreground_until.load(Ordering::Relaxed) > unix_now()
    }

    /// A direct connection timed out: a few in a row make a check out of turn
    /// (at most once per [`TIMEOUT_WINDOW`]).
    pub fn note_timeout(&self) {
        let now = Instant::now();
        let mut s = self.state.lock();
        s.timeouts.retain(|t| now.duration_since(*t) < TIMEOUT_WINDOW);
        s.timeouts.push(now);
        if s.timeouts.len() >= TIMEOUTS && s.last_wake.is_none_or(|w| now.duration_since(w) >= TIMEOUT_WINDOW) {
            s.timeouts.clear();
            s.last_wake = Some(now);
            drop(s);
            self.wake();
        }
    }

    /// For the window.
    pub fn view(&self) -> WatchView {
        let s = self.state.lock();
        WatchView { last: s.last, confirmed: s.detector.state(), checked_at: s.checked_at }
    }

    fn record(&self, r: NetState) {
        let mut s = self.state.lock();
        s.last = Some(r);
        s.checked_at = Some(unix_now());
        if let Some(changed) = s.detector.observe(r) {
            tracing::info!("network: {changed:?} (whitelist check)");
        }
    }
}

/// A host to check: `host`, `host:port`, `ip`, `ip:port` or `[ipv6]:port`;
/// port 443 when none is given. IPs get no SNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Where to connect.
    pub addr: TargetAddr,
    /// The server name for the ClientHello.
    pub sni: Option<String>,
}

/// Parses a [`Target`]; `None` for nonsense.
pub fn parse_target(s: &str) -> Option<Target> {
    let s = s.trim();
    let s = s.strip_prefix("https://").unwrap_or(s).trim_end_matches('/');
    if s.is_empty() || s.contains(['/', ' ']) {
        return None;
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        (h, p.strip_prefix(':').map_or(Some(443), |p| p.parse().ok())?)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p.parse().ok()?),
            Some(_) => (s, 443), // a bare IPv6
            None => (s, 443),
        }
    };
    let addr = Address::parse_host(host).ok()?;
    let sni = match &addr {
        Address::Domain(d) => Some(d.clone()),
        Address::Ip(_) => None,
    };
    Some(Target { addr: TargetAddr::new(addr, port), sni })
}

fn targets(list: &[String], defaults: &[&str]) -> Vec<Target> {
    let list: Vec<&str> = if list.is_empty() { defaults.to_vec() } else { list.iter().map(String::as_str).collect() };
    list.into_iter().filter_map(parse_target).collect()
}

/// A TLS 1.3 ClientHello (TLS 1.2 offered too) with `sni`, as a browser sends
/// it in one record: what a whitelist filter looks at.
pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
    fn u16b(v: usize) -> [u8; 2] {
        (v as u16).to_be_bytes()
    }
    fn ext(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend(kind.to_be_bytes());
        out.extend(u16b(body.len()));
        out.extend(body);
    }
    let random: Vec<u8> = (0..6).flat_map(|_| *Uuid::new_v4().as_bytes()).collect();
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let mut b = Vec::new();
        b.extend(u16b(name.len() + 3));
        b.push(0);
        b.extend(u16b(name.len()));
        b.extend(name.as_bytes());
        ext(&mut exts, 0x0000, &b);
    }
    ext(&mut exts, 0x000a, &[0, 6, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]); // x25519, P-256, P-384
    ext(&mut exts, 0x000b, &[1, 0]);
    let sigs = [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
    let mut b = u16b(sigs.len() * 2).to_vec();
    sigs.iter().for_each(|s| b.extend(s.to_be_bytes()));
    ext(&mut exts, 0x000d, &b);
    ext(&mut exts, 0x0010, b"\x00\x0c\x02h2\x08http/1.1");
    ext(&mut exts, 0x002b, &[4, 0x03, 0x04, 0x03, 0x03]);
    ext(&mut exts, 0x002d, &[1, 1]);
    let mut b = u16b(36).to_vec();
    b.extend([0x00, 0x1d, 0x00, 0x20]);
    b.extend(&random[64..96]); // any 32 bytes are an X25519 public key
    ext(&mut exts, 0x0033, &b);

    let suites = [0x1301u16, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8];
    let mut hello = vec![0x03, 0x03];
    hello.extend(&random[..32]);
    hello.push(32);
    hello.extend(&random[32..64]);
    hello.extend(u16b(suites.len() * 2));
    suites.iter().for_each(|s| hello.extend(s.to_be_bytes()));
    hello.extend([1, 0]);
    hello.extend(u16b(exts.len()));
    hello.extend(exts);

    let mut hs = vec![1, 0];
    hs.extend(u16b(hello.len()));
    hs.extend(hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend(u16b(hs.len()));
    record.extend(hs);
    record
}

/// Whether `target` answers a ClientHello with a TLS record (a ServerHello or
/// an alert) within [`TIMEOUT`]; a timeout, a reset or silence is a failure.
async fn probe(dial: Option<Dial>, target: Target) -> bool {
    let attempt = async {
        let mut stream: unbihex_engine::outbound::BoxStream = match dial {
            Some(d) => d(target.addr.clone()).await.ok()?,
            None => Box::new(tokio::net::TcpStream::connect((target.addr.addr.to_string(), target.addr.port)).await.ok()?),
        };
        stream.write_all(&client_hello(target.sni.as_deref())).await.ok()?;
        let mut b = [0u8; 1];
        let n = stream.read(&mut b).await.ok()?;
        (n == 1 && matches!(b[0], 0x15 | 0x16)).then_some(())
    };
    tokio::time::timeout(TIMEOUT, attempt).await.ok().flatten().is_some()
}

/// How many of `targets` answer, all checked at once.
async fn probe_all(dial: &Option<Dial>, targets: Vec<Target>) -> (usize, usize) {
    let total = targets.len();
    let mut set = tokio::task::JoinSet::new();
    for t in targets {
        set.spawn(probe(dial.clone(), t));
    }
    let mut ok = 0;
    while let Some(r) = set.join_next().await {
        ok += usize::from(r.unwrap_or(false));
    }
    (ok, total)
}

/// Switches `s` to the whitelist template and routing; what to give back on
/// leaving, `None` when the settings name neither (only the indicator).
pub fn enter(s: &mut Settings) -> Option<WhitelistSaved> {
    if s.whitelist_template.is_none() && s.whitelist_routing.is_none() {
        return None;
    }
    let (auto_select, auto_template, routing) = (s.auto_select, s.auto_template, s.routing);
    if let Some(t) = s.whitelist_template {
        s.auto_template = Some(t);
        if s.auto_select == AutoSelect::Off {
            s.auto_select = AutoSelect::Fallback;
        }
    }
    if let Some(r) = s.whitelist_routing {
        s.routing = r;
    }
    Some(WhitelistSaved {
        auto_select,
        auto_template,
        routing,
        set_auto_select: s.auto_select,
        set_auto_template: s.auto_template,
        set_routing: s.routing,
    })
}

/// Gives back what [`enter`] replaced; a choice the user changed while the
/// mode was on stays (the user's change wins).
pub fn leave(s: &mut Settings, saved: &WhitelistSaved) {
    if s.auto_template == saved.set_auto_template {
        s.auto_template = saved.auto_template;
    }
    if s.auto_select == saved.set_auto_select {
        s.auto_select = saved.auto_select;
    }
    if s.routing == saved.set_routing {
        s.routing = saved.routing;
    }
}

/// The routing as the window names it.
pub fn routing_label(r: RoutingMode) -> &'static str {
    match r {
        RoutingMode::Global => "Всё через VPN",
        RoutingMode::BypassRu => "Россия напрямую",
        RoutingMode::OnlyListed => "Только выбранные сайты",
        RoutingMode::BlockedOnly => "Только заблокированные",
    }
}

/// The whitelist mode was switched on or off.
#[derive(Clone, Debug, Serialize)]
pub struct WhitelistEvent {
    /// On now.
    pub active: bool,
    /// For a toast or a log line.
    pub message: String,
    /// The template, auto-select or routing changed: a running connection
    /// must take it.
    pub reconnect: bool,
}

/// The default interface, to notice another network (desktop; Android tells
/// through [`Watch::wake`]).
fn network_fingerprint() -> Option<String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        netdev::get_default_interface().ok().map(|i| format!("{} {:?}", i.index, i.ipv4))
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    None
}

impl Client {
    /// One round of checks around the tunnel; the result is recorded.
    pub async fn check_whitelist(&self) -> NetState {
        let s = self.settings();
        let dial = self.controller.direct().await.map(|t| t.dial);
        let allowed = targets(&s.whitelist_allowed, DEFAULT_ALLOWED);
        let blocked = targets(&s.whitelist_blocked, DEFAULT_BLOCKED);
        let ((a_ok, a_total), (b_ok, b_total)) = tokio::join!(probe_all(&dial, allowed), probe_all(&dial, blocked));
        let r = classify(a_ok, a_total, b_ok, b_total);
        tracing::debug!("whitelist check: allowed {a_ok}/{a_total}, others {b_ok}/{b_total}: {r:?}");
        self.whitelist.record(r);
        r
    }

    /// Whether the mode should be on: the setting, or in `auto` the detected
    /// state (unknown yet: as it is now, so a restart does not flip it).
    fn whitelist_wanted(&self) -> bool {
        let d = self.data.read();
        match d.settings.whitelist_mode {
            WhitelistMode::On => true,
            WhitelistMode::Off => false,
            WhitelistMode::Auto => match self.whitelist.view().confirmed {
                Some(NetState::Whitelist) => true,
                Some(_) => false,
                None => d.whitelist.active,
            },
        }
    }

    /// Brings the applied mode in line with the setting and the detection;
    /// the event when it changed.
    pub fn sync_whitelist(&self) -> Result<Option<WhitelistEvent>> {
        let want = self.whitelist_wanted();
        if self.data.read().whitelist.active == want {
            return Ok(None);
        }
        self.mutate(|d| {
            let before = (d.settings.auto_select, d.settings.auto_template, d.settings.routing);
            let message = if want {
                let saved = enter(&mut d.settings);
                let message = match (saved.is_some(), d.settings.whitelist_template) {
                    (false, _) => "Белые списки оператора: открываются только разрешённые сайты".to_string(),
                    (true, Some(t)) => {
                        let name = d.auto_templates.iter().find(|x| x.id == t).map_or("шаблон", |x| x.name.as_str());
                        format!("Белые списки — переключено на «{name}»")
                    }
                    (true, None) => format!("Белые списки — маршрутизация «{}»", routing_label(d.settings.routing)),
                };
                d.whitelist.saved = saved;
                message
            } else {
                let had = d.whitelist.saved.take();
                if let Some(saved) = &had {
                    leave(&mut d.settings, saved);
                    // A template deleted meanwhile: all servers.
                    if let Some(t) = d.settings.auto_template
                        && !d.auto_templates.iter().any(|x| x.id == t)
                    {
                        d.settings.auto_template = None;
                    }
                }
                if had.is_some() { "Белые списки сняты — прежние настройки возвращены" } else { "Белые списки сняты" }.to_string()
            };
            d.whitelist.active = want;
            let after = (d.settings.auto_select, d.settings.auto_template, d.settings.routing);
            tracing::info!("{message}");
            self.controller.journal.note("routing", &message);
            Some(WhitelistEvent { active: want, message, reconnect: before != after })
        })
    }

    /// The notification's line: the server in use, with the whitelist mode
    /// in front while it is on.
    pub async fn notification_text(&self) -> Option<String> {
        let server = self.current_server().await?;
        Some(if self.data.read().whitelist.active { format!("Белые списки · {server}") } else { server })
    }

    /// Runs the detection for as long as the app does: checks once a minute in
    /// the foreground, every 5 minutes in the background, at once on another
    /// network or a run of direct timeouts, 10 s later to confirm a change.
    /// `on_event` gets every switch (toast, reconnect).
    /// Returns at once when it already runs (the app and a tile start both ask).
    pub async fn run_whitelist(&self, on_event: impl Fn(WhitelistEvent)) {
        if self.whitelist.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut net = network_fingerprint();
        let mut last_check: Option<Instant> = None;
        loop {
            let mut now_please = false;
            tokio::select! {
                _ = tokio::time::sleep(TICK) => {}
                _ = self.whitelist.wake.notified() => now_please = true,
            }
            if self.settings().whitelist_mode == WhitelistMode::Auto {
                let fp = network_fingerprint();
                if fp != net {
                    net = fp;
                    now_please = true;
                }
                let every = if self.whitelist.state.lock().detector.confirming() {
                    CONFIRM_EVERY
                } else if self.whitelist.foreground() {
                    FOREGROUND_EVERY
                } else {
                    BACKGROUND_EVERY
                };
                if now_please || last_check.is_none_or(|t| t.elapsed() >= every) {
                    last_check = Some(Instant::now());
                    self.check_whitelist().await;
                }
            }
            match self.sync_whitelist() {
                Ok(Some(ev)) => on_event(ev),
                Ok(None) => {}
                Err(e) => tracing::warn!("whitelist mode: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_are_classified() {
        assert_eq!(classify(3, 3, 5, 5), NetState::Normal);
        assert_eq!(classify(3, 3, 3, 5), NetState::Normal);
        assert_eq!(classify(2, 3, 2, 5), NetState::Whitelist);
        assert_eq!(classify(3, 3, 0, 5), NetState::Whitelist);
        assert_eq!(classify(0, 3, 0, 5), NetState::Offline);
        assert_eq!(classify(0, 3, 5, 5), NetState::Offline);
    }

    #[test]
    fn a_state_needs_two_equal_results() {
        let mut d = Detector::default();
        assert_eq!(d.observe(NetState::Whitelist), None);
        assert!(d.confirming());
        assert_eq!(d.observe(NetState::Whitelist), Some(NetState::Whitelist));
        assert_eq!(d.state(), Some(NetState::Whitelist));
        // One normal result between whitelist ones changes nothing.
        assert_eq!(d.observe(NetState::Normal), None);
        assert_eq!(d.observe(NetState::Whitelist), None);
        assert_eq!(d.observe(NetState::Normal), None);
        // Offline breaks the run and is never the state.
        assert_eq!(d.observe(NetState::Offline), None);
        assert_eq!(d.observe(NetState::Normal), None);
        assert_eq!(d.observe(NetState::Offline), None);
        assert_eq!(d.observe(NetState::Offline), None);
        assert_eq!(d.state(), Some(NetState::Whitelist));
        assert_eq!(d.observe(NetState::Normal), None);
        assert_eq!(d.observe(NetState::Normal), Some(NetState::Normal));
    }

    #[test]
    fn targets_are_parsed() {
        let t = parse_target("ya.ru").unwrap();
        assert_eq!(t.addr.to_string(), "ya.ru:443");
        assert_eq!(t.sni.as_deref(), Some("ya.ru"));
        let t = parse_target("1.1.1.1:8443").unwrap();
        assert_eq!(t.addr.port, 8443);
        assert_eq!(t.sni, None);
        assert_eq!(parse_target("[2606:4700::1111]").unwrap().addr.port, 443);
        assert_eq!(parse_target("2606:4700::1111").unwrap().sni, None);
        assert_eq!(parse_target("https://Gosuslugi.RU/").unwrap().sni.as_deref(), Some("gosuslugi.ru"));
        assert!(parse_target("ya.ru:http").is_none());
        assert!(parse_target("").is_none());
        assert_eq!(targets(&[], DEFAULT_BLOCKED).len(), DEFAULT_BLOCKED.len());
    }

    #[test]
    fn client_hello_is_one_tls_record_with_the_sni() {
        let h = client_hello(Some("ya.ru"));
        assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 1);
        assert!(h.windows(5).any(|w| w == b"ya.ru"));
        assert!(!client_hello(None).windows(5).any(|w| w == b"ya.ru"));
    }

    fn settings() -> Settings {
        Settings { routing: RoutingMode::Global, auto_select: AutoSelect::Off, ..Settings::default() }
    }

    #[test]
    fn enter_and_leave_give_the_choice_back() {
        let bypass = Uuid::new_v4();
        let mine = Uuid::new_v4();
        let mut s = settings();
        // Neither template nor routing: only the indicator.
        assert_eq!(enter(&mut s), None);
        s.auto_template = Some(mine);
        s.whitelist_template = Some(bypass);
        s.whitelist_routing = Some(RoutingMode::BypassRu);
        let saved = enter(&mut s).unwrap();
        assert_eq!((s.auto_select, s.auto_template, s.routing), (AutoSelect::Fallback, Some(bypass), RoutingMode::BypassRu));
        leave(&mut s, &saved);
        assert_eq!((s.auto_select, s.auto_template, s.routing), (AutoSelect::Off, Some(mine), RoutingMode::Global));
    }

    #[test]
    fn a_change_made_during_the_mode_is_kept() {
        let bypass = Uuid::new_v4();
        let mut s = settings();
        s.auto_select = AutoSelect::LeastPing;
        s.whitelist_template = Some(bypass);
        s.whitelist_routing = Some(RoutingMode::BypassRu);
        let saved = enter(&mut s).unwrap();
        // LeastPing stays as it was: auto-select was already on.
        assert_eq!(s.auto_select, AutoSelect::LeastPing);
        // The user picks another routing while the mode is on.
        s.routing = RoutingMode::OnlyListed;
        leave(&mut s, &saved);
        assert_eq!(s.routing, RoutingMode::OnlyListed);
        assert_eq!(s.auto_template, None);
    }

    #[test]
    fn the_client_switches_and_restores_with_the_detection() {
        let dir = std::env::temp_dir().join(format!("unbihex-wl-{}", Uuid::new_v4()));
        let c = Client::open(&dir);
        let t = c.create_template("Обход", Vec::new()).unwrap();
        let mut s = c.settings();
        s.whitelist_template = Some(t.id);
        s.whitelist_routing = Some(RoutingMode::BypassRu);
        c.set_settings(s).unwrap();
        // Nothing detected yet: nothing changes.
        assert!(c.sync_whitelist().unwrap().is_none());
        c.whitelist.record(NetState::Whitelist);
        assert!(c.sync_whitelist().unwrap().is_none());
        c.whitelist.record(NetState::Whitelist);
        let ev = c.sync_whitelist().unwrap().unwrap();
        assert!(ev.active && ev.reconnect);
        assert_eq!(ev.message, "Белые списки — переключено на «Обход»");
        assert_eq!(c.settings().auto_template, Some(t.id));
        assert!(c.snapshot().whitelist.active);
        // Survives a restart: the saved choice is in state.json.
        let c2 = Client::open(&dir);
        assert!(c2.snapshot().whitelist.saved.is_some());
        assert!(c2.sync_whitelist().unwrap().is_none());
        c.whitelist.record(NetState::Normal);
        c.whitelist.record(NetState::Normal);
        let ev = c.sync_whitelist().unwrap().unwrap();
        assert!(!ev.active);
        assert_eq!(c.settings().auto_template, None);
        assert_eq!(c.settings().routing, RoutingMode::Global);
        // Forced on, forced off.
        let mut s = c.settings();
        s.whitelist_mode = WhitelistMode::On;
        c.set_settings(s).unwrap();
        assert!(c.sync_whitelist().unwrap().unwrap().active);
        let mut s = c.settings();
        s.whitelist_mode = WhitelistMode::Off;
        c.set_settings(s).unwrap();
        assert!(!c.sync_whitelist().unwrap().unwrap().active);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
