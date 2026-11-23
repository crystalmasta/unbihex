//! Connection journal for the client's developer mode (SPEC §7, item 8): one event per
//! opened and closed TCP connection or UDP flow, DNS query, and auto-select switch.
//!
//! Nothing is collected until someone subscribes: the hot path checks one atomic
//! flag. A subscriber gets a bounded channel; when it falls behind, new events are
//! dropped and counted instead of blocking a connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::error::Error;
use crate::outbound::balancer::BalancerState;

/// Events a subscriber may fall behind by before new ones are dropped.
pub const DEFAULT_CAPACITY: usize = 20_000;

/// Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// One journal entry. Serialized as a JSON object with `ev` naming the kind.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum Event {
    /// A connection or flow was accepted (it may still hang in the handshake).
    Open(ConnOpen),
    /// A connection or flow ended, with its route, traffic and the reason.
    Close(ConnClose),
    /// A DNS query the engine answered or made.
    Dns(DnsEvent),
    /// A balancer (auto-select) moved new connections to another member.
    Switch(SwitchEvent),
    /// A line from the host app (routing changed and the like).
    Note(NoteEvent),
}

/// A connection or flow was accepted.
#[derive(Clone, Debug, Serialize)]
pub struct ConnOpen {
    /// Connection number, the same in its `close` event; unique in the process.
    pub conn: u64,
    /// Unix ms.
    pub ts: u64,
    /// `tcp` or `udp`.
    pub net: &'static str,
    /// Inbound tag.
    pub inbound: String,
    /// The application's address (TUN or local proxy side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<SocketAddr>,
    /// The destination as the application asked for it (a fake IP in the TUN).
    pub dst: String,
    /// The name: the target's own, restored from a fake IP, or sniffed (SNI, Host, QUIC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// A connection or flow ended.
#[derive(Clone, Debug, Serialize)]
pub struct ConnClose {
    /// Connection number.
    pub conn: u64,
    /// Unix ms of the start.
    pub start: u64,
    /// Unix ms of the end.
    pub end: u64,
    /// `tcp` or `udp`.
    pub net: &'static str,
    /// Inbound tag.
    pub inbound: String,
    /// The application's address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<SocketAddr>,
    /// The destination as the application asked for it.
    pub dst: String,
    /// The destination name, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The routing rule that decided (`#N …`), `final` for none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Outbound tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// `direct`, `proxy` or `block`; empty when it failed before routing.
    pub route: &'static str,
    /// A balancer's member that carried it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// Bytes from the application.
    pub up: u64,
    /// Bytes to the application.
    pub down: u64,
    /// Duration, ms.
    pub ms: u64,
    /// `closed`, `idle`, `timeout`, `refused`, `reset`, `handshake`, `dns`, `blocked`,
    /// `forbidden`, `limit`, `remote` or `error`.
    pub reason: &'static str,
    /// The error text, when it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A DNS query.
#[derive(Clone, Debug, Serialize)]
pub struct DnsEvent {
    /// Unix ms.
    pub ts: u64,
    /// The name asked for.
    pub name: String,
    /// Record type (`A`, `AAAA`, `HTTPS`…).
    pub qtype: String,
    /// Who answered: `fake-ip`, `local`, `home DNS`, `<server> via <outbound>`…
    pub resolver: String,
    /// Response code (`NoError`, `NXDomain`…), when there was a response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    /// Addresses and other answers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<String>,
    /// How long it took, ms.
    pub ms: u64,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A balancer switched members.
#[derive(Clone, Debug, Serialize)]
pub struct SwitchEvent {
    /// Unix ms.
    pub ts: u64,
    /// The balancer's tag.
    pub balancer: String,
    /// The member before (none when it is the first seen).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The member now.
    pub to: String,
    /// Why: `from_down` or `faster`, with the delays when known.
    pub reason: String,
}

/// A line from the host app.
#[derive(Clone, Debug, Serialize)]
pub struct NoteEvent {
    /// Unix ms.
    pub ts: u64,
    /// What changed (`routing`, `server`, `session`…).
    pub category: String,
    /// The line.
    pub text: String,
}

/// The event hub of one engine instance.
#[derive(Default)]
pub struct Events {
    on: AtomicBool,
    tx: ArcSwapOption<mpsc::Sender<Event>>,
    dropped: AtomicU64,
    /// The member each balancer was last seen using.
    members: parking_lot::Mutex<HashMap<String, String>>,
}

impl Events {
    /// Whether anyone listens. Everything else is skipped when not.
    #[inline]
    pub fn enabled(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Starts collecting into a new channel of `capacity` events (replacing a
    /// previous subscriber).
    pub fn subscribe(&self, capacity: usize) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        self.tx.store(Some(Arc::new(tx)));
        self.members.lock().clear();
        self.on.store(true, Ordering::Relaxed);
        rx
    }

    /// Stops collecting.
    pub fn unsubscribe(&self) {
        self.on.store(false, Ordering::Relaxed);
        self.tx.store(None);
    }

    /// Events dropped because the subscriber fell behind.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Sends `ev` without waiting; a full channel drops it.
    pub fn emit(&self, ev: Event) {
        if !self.enabled() {
            return;
        }
        if let Some(tx) = &*self.tx.load() {
            match tx.try_send(ev) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => self.unsubscribe(),
            }
        }
    }

    /// A line from the host app into the same stream.
    pub fn note(&self, category: &str, text: &str) {
        if self.enabled() {
            self.emit(Event::Note(NoteEvent {
                ts: now_ms(),
                category: category.into(),
                text: text.into(),
            }));
        }
    }

    /// A connection number, unique in the process (across engine restarts too).
    pub(crate) fn next_conn(&self) -> u64 {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The member `state` uses now; a `switch` event when it changed since the
    /// last connection through this balancer.
    pub(crate) fn member_used(&self, state: &BalancerState) -> Option<String> {
        let to = state.current.clone()?;
        let from = {
            let mut seen = self.members.lock();
            match seen.get(&state.tag) {
                Some(prev) if *prev == to => return Some(to),
                _ => seen.insert(state.tag.clone(), to.clone()),
            }
        };
        let member = |tag: &str| state.members.iter().find(|m| m.tag == tag);
        let delay = |tag: &str| {
            member(tag)
                .and_then(|m| m.delay_ms)
                .map_or("?".to_string(), |d| format!("{d} ms"))
        };
        let reason = match &from {
            None => "first".to_string(),
            Some(f) if member(f).is_some_and(|m| m.alive == Some(false)) => {
                format!("from_down; to {}", delay(&to))
            }
            Some(f) => format!("faster: {} -> {}", delay(f), delay(&to)),
        };
        if from.is_some() {
            self.emit(Event::Switch(SwitchEvent {
                ts: now_ms(),
                balancer: state.tag.clone(),
                from,
                to: to.clone(),
                reason,
            }));
        }
        Some(to)
    }
}

/// Why a connection failed, as a short code.
pub(crate) fn error_reason(e: &Error) -> &'static str {
    match e {
        Error::Timeout => "timeout",
        Error::Blocked => "blocked",
        Error::Dns(_) => "dns",
        Error::Tls(_) | Error::Protocol(_) => "handshake",
        Error::Forbidden(_) => "forbidden",
        Error::Io(e) => io_reason(e),
        _ => "error",
    }
}

/// Why a relay ended with an I/O error.
pub(crate) fn io_reason(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::TimedOut => "idle",
        K::ConnectionRefused => "refused",
        K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe => "reset",
        _ => "error",
    }
}

/// Milliseconds in `d`, saturated.
pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::balancer::MemberState;

    fn note(e: &Events) {
        e.note("routing", "x");
    }

    #[tokio::test]
    async fn nothing_is_sent_without_a_subscriber_and_overflow_is_counted() {
        let e = Events::default();
        note(&e);
        assert!(!e.enabled());
        let mut rx = e.subscribe(2);
        for _ in 0..5 {
            note(&e);
        }
        assert_eq!(e.dropped(), 3);
        assert!(matches!(rx.recv().await, Some(Event::Note(_))));
        e.unsubscribe();
        note(&e);
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn balancer_switches_are_reported_once() {
        let e = Events::default();
        let mut rx = e.subscribe(8);
        let state = |cur: &str, a_alive: bool| BalancerState {
            tag: "proxy".into(),
            current: Some(cur.into()),
            members: vec![
                MemberState {
                    tag: "a".into(),
                    alive: Some(a_alive),
                    delay_ms: Some(900),
                },
                MemberState {
                    tag: "b".into(),
                    alive: Some(true),
                    delay_ms: Some(100),
                },
            ],
        };
        assert_eq!(e.member_used(&state("a", true)).as_deref(), Some("a"));
        e.member_used(&state("a", true));
        e.member_used(&state("b", false));
        let Some(Event::Switch(s)) = rx.recv().await else {
            panic!()
        };
        assert_eq!((s.from.as_deref(), s.to.as_str()), (Some("a"), "b"));
        assert!(s.reason.starts_with("from_down"), "{}", s.reason);
        e.unsubscribe();
        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn events_serialize_with_their_kind() {
        let ev = Event::Note(NoteEvent {
            ts: 1,
            category: "routing".into(),
            text: "t".into(),
        });
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.starts_with(r#"{"ev":"note""#), "{json}");
    }
}
