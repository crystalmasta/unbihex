//! Server control (the `server` feature): Xray-style traffic counters and the users of
//! VLESS inbounds, which can be added and removed while the server runs.
//!
//! Counter names are Xray's, so panels read them unchanged:
//! `user>>>{email}>>>traffic>>>uplink|downlink` and `inbound>>>{tag}>>>traffic>>>uplink|downlink`.
//! Uplink is what the client sent, downlink what it received. Users without an email
//! are not counted, as in Xray.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::VlessUser;
use crate::error::{Error, Result};
use crate::inbound::vless::UserList;
use crate::outbound::PacketStream;

const UPLINK: &str = ">>>traffic>>>uplink";
const DOWNLINK: &str = ">>>traffic>>>downlink";

/// Bytes up and down for one user or inbound.
#[derive(Debug, Default)]
pub(crate) struct Traffic {
    up: AtomicU64,
    down: AtomicU64,
}

impl Traffic {
    fn read(c: &AtomicU64, reset: bool) -> i64 {
        let v = if reset {
            c.swap(0, Ordering::Relaxed)
        } else {
            c.load(Ordering::Relaxed)
        };
        i64::try_from(v).unwrap_or(i64::MAX)
    }
}

type Table = RwLock<HashMap<String, Arc<Traffic>>>;

/// Named traffic counters of users and inbounds.
#[derive(Debug, Default)]
pub struct ServerStats {
    users: Table,
    inbounds: Table,
}

fn entry(table: &Table, key: &str) -> Arc<Traffic> {
    if let Some(t) = table.read().get(key) {
        return t.clone();
    }
    table.write().entry(key.to_string()).or_default().clone()
}

impl ServerStats {
    /// The user's counters; `None` for a user without an email.
    pub(crate) fn user(&self, email: &str) -> Option<Arc<Traffic>> {
        (!email.is_empty()).then(|| entry(&self.users, email))
    }

    /// The inbound's counters.
    pub(crate) fn inbound(&self, tag: &str) -> Arc<Traffic> {
        entry(&self.inbounds, tag)
    }

    /// One counter by its full name (`GetStats`); `None` if there is no such counter.
    pub fn get(&self, name: &str, reset: bool) -> Option<i64> {
        let (table, rest) = if let Some(r) = name.strip_prefix("user>>>") {
            (&self.users, r)
        } else {
            (&self.inbounds, name.strip_prefix("inbound>>>")?)
        };
        let (key, up) = match rest.strip_suffix(UPLINK) {
            Some(k) => (k, true),
            None => (rest.strip_suffix(DOWNLINK)?, false),
        };
        let t = table.read().get(key)?.clone();
        Some(Traffic::read(if up { &t.up } else { &t.down }, reset))
    }

    /// Every counter whose name contains `pattern` (all for an empty one), sorted by name
    /// (`QueryStats`).
    pub fn query(&self, pattern: &str, reset: bool) -> Vec<(String, i64)> {
        let mut out = Vec::new();
        for (kind, table) in [("user", &self.users), ("inbound", &self.inbounds)] {
            for (key, t) in table.read().iter() {
                for (suffix, c) in [(UPLINK, &t.up), (DOWNLINK, &t.down)] {
                    let name = format!("{kind}>>>{key}{suffix}");
                    if name.contains(pattern) {
                        out.push((name, Traffic::read(c, reset)));
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// `(email, uplink, downlink)` of every counted user, sorted by email (`GetUsersStats`).
    pub fn users_traffic(&self, reset: bool) -> Vec<(String, i64, i64)> {
        let mut out: Vec<_> = self
            .users
            .read()
            .iter()
            .map(|(e, t)| {
                (
                    e.clone(),
                    Traffic::read(&t.up, reset),
                    Traffic::read(&t.down, reset),
                )
            })
            .collect();
        out.sort();
        out
    }
}

/// What the management API works with: the counters and the users of each VLESS inbound.
#[derive(Default)]
pub struct ServerControl {
    stats: Arc<ServerStats>,
    inbounds: RwLock<HashMap<String, Arc<UserList>>>,
}

impl ServerControl {
    /// The traffic counters.
    pub fn stats(&self) -> &Arc<ServerStats> {
        &self.stats
    }

    pub(crate) fn register(&self, tag: &str, users: Arc<UserList>) {
        self.inbounds.write().insert(tag.to_string(), users);
    }

    fn inbound(&self, tag: &str) -> Result<Arc<UserList>> {
        self.inbounds
            .read()
            .get(tag)
            .cloned()
            .ok_or_else(|| Error::config(format!("inbound {tag:?} not found")))
    }

    /// Adds a user; new connections may use it at once.
    pub fn add_user(&self, tag: &str, user: VlessUser) -> Result<()> {
        if user.email.is_empty() {
            return Err(Error::config("user has no email"));
        }
        let email = user.email.clone();
        self.inbound(tag)?.add(&user)?;
        self.stats.user(&email);
        Ok(())
    }

    /// Removes a user by email; its open connections stay, new ones are refused.
    pub fn remove_user(&self, tag: &str, email: &str) -> Result<()> {
        self.inbound(tag)?.remove(email)
    }

    /// The inbound's users, or the one with `email` when it is given and not empty.
    pub fn users(&self, tag: &str, email: Option<&str>) -> Result<Vec<VlessUser>> {
        let all = self.inbound(tag)?.configs();
        Ok(match email.filter(|e| !e.is_empty()) {
            Some(e) => all.into_iter().filter(|u| u.email == e).collect(),
            None => all,
        })
    }

    /// How many users the inbound has.
    pub fn user_count(&self, tag: &str) -> Result<usize> {
        Ok(self.inbound(tag)?.len())
    }

    /// Tags of the VLESS inbounds, sorted.
    pub fn inbound_tags(&self) -> Vec<String> {
        let mut tags: Vec<_> = self.inbounds.read().keys().cloned().collect();
        tags.sort();
        tags
    }
}

/// Where a connection's bytes are counted.
#[derive(Clone)]
pub(crate) struct Meter {
    user: Option<Arc<Traffic>>,
    inbound: Arc<Traffic>,
}

impl Meter {
    pub(crate) fn new(user: Option<Arc<Traffic>>, inbound: Arc<Traffic>) -> Self {
        Meter { user, inbound }
    }

    fn up(&self, n: usize) {
        let n = n as u64;
        self.inbound.up.fetch_add(n, Ordering::Relaxed);
        if let Some(u) = &self.user {
            u.up.fetch_add(n, Ordering::Relaxed);
        }
    }

    fn down(&self, n: usize) {
        let n = n as u64;
        self.inbound.down.fetch_add(n, Ordering::Relaxed);
        if let Some(u) = &self.user {
            u.down.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// A client stream that counts what is read (uplink) and written (downlink).
pub(crate) struct Counted<S> {
    inner: S,
    meter: Meter,
}

impl<S> Counted<S> {
    pub(crate) fn new(inner: S, meter: Meter) -> Self {
        Counted { inner, meter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            self.meter.up(buf.filled().len() - before);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = r {
            self.meter.down(n);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A client datagram flow that counts the payloads.
pub(crate) struct CountedPackets {
    inner: Box<dyn PacketStream>,
    meter: Meter,
}

impl CountedPackets {
    pub(crate) fn new(inner: Box<dyn PacketStream>, meter: Meter) -> Self {
        CountedPackets { inner, meter }
    }
}

#[async_trait::async_trait]
impl PacketStream for CountedPackets {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        self.inner.send(payload).await?;
        self.meter.down(payload.len());
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.recv(buf).await?;
        self.meter.up(n);
        Ok(n)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn vless_user(id: &str, email: &str, flow: &str) -> VlessUser {
        VlessUser {
            id: Secret(id.into()),
            email: email.into(),
            flow: flow.into(),
        }
    }

    fn control() -> ServerControl {
        let c = ServerControl::default();
        c.register("in", Arc::new(UserList::new("in", &[]).unwrap()));
        c
    }

    #[test]
    fn names_get_and_query() {
        let s = ServerStats::default();
        Meter::new(s.user("a@x"), s.inbound("in")).up(10);
        Meter::new(s.user("b@x"), s.inbound("in")).down(7);
        Meter::new(s.user(""), s.inbound("in")).up(1);
        assert_eq!(s.get("user>>>a@x>>>traffic>>>uplink", false), Some(10));
        assert_eq!(s.get("user>>>b@x>>>traffic>>>downlink", false), Some(7));
        assert_eq!(s.get("inbound>>>in>>>traffic>>>uplink", false), Some(11));
        assert_eq!(s.get("user>>>nobody>>>traffic>>>uplink", false), None);
        assert_eq!(s.get("user>>>a@x>>>traffic>>>sideways", false), None);
        assert_eq!(s.get("outbound>>>x>>>traffic>>>uplink", false), None);

        let users = s.query("user>>>", false);
        let names: Vec<_> = users.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "user>>>a@x>>>traffic>>>downlink",
                "user>>>a@x>>>traffic>>>uplink",
                "user>>>b@x>>>traffic>>>downlink",
                "user>>>b@x>>>traffic>>>uplink",
            ]
        );
        assert_eq!(s.query("", false).len(), 6);
        assert_eq!(s.query("uplink", true).len(), 3);
        assert_eq!(s.get("user>>>a@x>>>traffic>>>uplink", false), Some(0));
        assert_eq!(s.get("user>>>b@x>>>traffic>>>downlink", true), Some(7));
        assert_eq!(s.get("user>>>b@x>>>traffic>>>downlink", false), Some(0));
        assert_eq!(
            s.users_traffic(false),
            [("a@x".into(), 0, 0), ("b@x".into(), 0, 0)]
        );
    }

    #[test]
    fn users_come_and_go() {
        let c = control();
        c.add_user("in", vless_user(ID, "a@x", "")).unwrap();
        assert!(
            c.add_user("in", vless_user(ID, "a@x", "")).is_err(),
            "duplicate"
        );
        assert!(
            c.add_user("nope", vless_user(ID, "b@x", "")).is_err(),
            "no inbound"
        );
        assert!(
            c.add_user("in", vless_user("not-a-uuid", "b@x", ""))
                .is_err()
        );
        assert!(
            c.add_user("in", vless_user(ID, "b@x", "xtls-rprx-direct"))
                .is_err()
        );
        assert!(
            c.add_user("in", vless_user(ID, "", "")).is_err(),
            "no email"
        );
        c.add_user("in", vless_user(ID, "b@x", "xtls-rprx-vision"))
            .unwrap();
        assert_eq!(c.user_count("in").unwrap(), 2);
        assert_eq!(
            c.users("in", Some("b@x")).unwrap()[0].flow,
            "xtls-rprx-vision"
        );
        assert_eq!(c.users("in", Some("")).unwrap().len(), 2);
        assert_eq!(
            c.stats().get("user>>>a@x>>>traffic>>>uplink", false),
            Some(0)
        );
        c.remove_user("in", "a@x").unwrap();
        assert!(c.remove_user("in", "a@x").is_err(), "not found");
        assert_eq!(c.user_count("in").unwrap(), 1);
        assert_eq!(c.inbound_tags(), ["in"]);
    }

    #[tokio::test]
    async fn counted_stream_counts_both_ways() {
        let s = ServerStats::default();
        let (near, mut far) = tokio::io::duplex(1024);
        let mut counted = Counted::new(near, Meter::new(s.user("a@x"), s.inbound("in")));
        far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        counted.write_all(b"hi!").await.unwrap();
        assert_eq!(s.get("user>>>a@x>>>traffic>>>uplink", false), Some(5));
        assert_eq!(s.get("user>>>a@x>>>traffic>>>downlink", false), Some(3));
        assert_eq!(s.get("inbound>>>in>>>traffic>>>downlink", false), Some(3));
    }
}
