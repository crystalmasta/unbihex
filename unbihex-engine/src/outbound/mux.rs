//! Mux.Cool client: many UDP destinations inside one transport stream.
//!
//! An application talks to several destinations from one socket. Giving each
//! destination its own TCP+TLS connection costs a REALITY handshake per
//! destination — measured at ~170 ms on a 50 ms link. Mux.Cool gives one
//! session per local socket inside one connection, and every datagram names
//! its destination: a new destination costs microseconds, and the IP
//! destinations of one socket share one server-side UDP socket and NAT mapping.
//! A domain destination is resolved by the server, so its reply names an IP
//! that cannot pick the flow; it keeps a session of its own.
//!
//! Losing the connection fails every flow on it; the next flow dials a new
//! connection with the same per-source global ID, and Xray then reuses the UDP
//! socket it kept for a minute. Servers that do not speak Mux.Cool close it,
//! and the flow then fails — the same contract Xray's clients have.
//!
//! By Pavel Shakhmin (github.com/pshakhmin), PR #53.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::xudp::{destination_id, source_id};
use super::{BoxStream, PacketStream};
use crate::address::{Address, TargetAddr};
use crate::error::{Error, Result};
use crate::mux::{
    STATUS_END, STATUS_KEEP, STATUS_NEW, data_frame, end_frame, keepalive_frame, new_udp_frame,
    read_frame,
};

/// Frames waiting for the writer. One queue for the whole connection: frames
/// must not interleave, and Mux.Cool has no per-session flow control.
const QUEUE: usize = 64;
/// A PING-like keep-alive frame; NATs and CDNs reap idle connections.
#[cfg(not(test))]
const KEEPALIVE: Duration = Duration::from_secs(30);
#[cfg(test)]
const KEEPALIVE: Duration = Duration::from_millis(20);
/// A connection with no sessions for this long is closed: after a network
/// change a write can keep succeeding into a dead socket, and new flows must
/// not be handed to it.
#[cfg(not(test))]
const IDLE_RETIRE: Duration = Duration::from_secs(60);
#[cfg(test)]
const IDLE_RETIRE: Duration = Duration::from_millis(60);
/// A connection that dies this soon after opening, before carrying a single
/// reply, is treated as a server without Mux.Cool.
const REJECT_WINDOW: Duration = Duration::from_secs(5);
/// How long a rejection keeps new flows on the plain path: a dispatch that
/// failed for one address also closes the connection, so it is not final.
const BROKEN_TTL: Duration = Duration::from_secs(600);
/// A close_notify to a dead peer must not hold the socket.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
#[cfg(not(test))]
const MAX_SESSIONS: usize = 120;
#[cfg(test)]
const MAX_SESSIONS: usize = 2;

type DialFuture = Pin<Box<dyn Future<Output = Result<BoxStream>> + Send>>;
type DialFn = Arc<dyn Fn() -> DialFuture + Send + Sync>;

/// Opens and keeps the shared Mux.Cool connection.
pub struct MuxClient {
    dial: DialFn,
    /// The current connection first-served, plus older ones that still carry
    /// flows. A source keeps the session it already has, wherever it lives:
    /// a second session for one source would reuse its global ID and make the
    /// server move the first destination's link.
    conns: Mutex<Vec<Arc<Conn>>>,
    next_id: AtomicU16,
    /// Keeps global IDs of two clients that reach one server apart; stable for
    /// this client, so reconnect still reuses the server-side socket.
    salt: [u8; 8],
    /// Flows without a local socket (DNS queries) get a session each: sharing
    /// one would collide when two queries name the same server.
    next_anonymous: AtomicU64,
    /// When a server last closed the mux connection before it carried any reply.
    broken: Arc<SyncMutex<Option<Instant>>>,
    /// Cancels every connection, current or retired, when the client goes.
    cancel: CancellationToken,
}

impl MuxClient {
    /// `dial` returns a fresh stream with the VLESS Mux.Cool request already
    /// written; it is called again only after the previous connection died.
    #[cfg(test)]
    pub fn new<F, Fut>(dial: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BoxStream>> + Send + 'static,
    {
        Self::with_salt(dial, rand::random())
    }

    /// The same, with the salt the outbound also uses for its single-stream
    /// XUDP flows: a flow that falls back from one path to the other must keep
    /// one global ID, or Xray's cached UDP socket is not reused.
    pub fn with_salt<F, Fut>(dial: F, salt: [u8; 8]) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BoxStream>> + Send + 'static,
    {
        let dial: DialFn = Arc::new(move || Box::pin(dial()) as DialFuture);
        MuxClient {
            dial,
            conns: Mutex::new(Vec::new()),
            next_id: AtomicU16::new(1),
            salt,
            next_anonymous: AtomicU64::new(1),
            broken: Arc::default(),
            cancel: CancellationToken::new(),
        }
    }

    /// Whether the server turned out not to speak Mux.Cool, within the last
    /// [`BROKEN_TTL`].
    pub fn is_broken(&self) -> bool {
        self.broken.lock().is_some_and(|at| at.elapsed() < BROKEN_TTL)
    }

    /// Opens a UDP flow to `target` from the local socket `source`. Every flow
    /// of one source shares a session and a global ID, so the server can keep
    /// one NAT mapping for all of them.
    pub async fn open_udp(&self, source: Option<SocketAddr>, target: TargetAddr) -> Result<MuxUdp> {
        if self.is_broken() {
            return Err(Error::Unsupported("mux: server rejected Mux.Cool".into()));
        }
        // A domain is resolved by the server, and its reply names the IP; that
        // IP cannot pick the flow. Such destinations keep a session of their
        // own (as before this change), with one flow and a unique ID.
        let domain = matches!(target.addr, Address::Domain(_));
        let key = match (source, domain) {
            (Some(src), true) => SessionKey::Destination(src, target.clone()),
            (Some(src), false) => SessionKey::Source(src),
            (None, _) => SessionKey::Anonymous(self.next_anonymous.fetch_add(1, Ordering::Relaxed)),
        };
        let gid = match (source, domain) {
            (Some(_), true) => destination_id(source, &target, &self.salt),
            (Some(_), false) => source_id(source, &self.salt),
            // Xray ignores an empty ID, so these never hit its XUDP table.
            (None, _) => [0; 8],
        };
        // One dial at a time: a burst of UDP flows must not open a tunnel each.
        let mut conns = self.conns.lock().await;
        conns.retain(|c| !c.closed.load(Ordering::Relaxed) || !c.sessions.lock().is_empty());
        // A source keeps its session even when a newer connection exists;
        // opening a second one would move the server-side link to it.
        let found = conns
            .iter()
            .find(|conn| conn.sessions.lock().by_key(&key).is_some())
            .cloned();
        let conn = match found {
            Some(conn) => conn,
            None => {
                // A server caps the sessions of one Mux.Cool stream. When the
                // live connection is full, grow another one: flows already on
                // the old one keep running, new sources land on the fresh one.
                match conns
                    .last()
                    .filter(|c| {
                        !c.closed.load(Ordering::Relaxed)
                            && c.sessions.lock().len() < MAX_SESSIONS
                    })
                    .cloned()
                {
                    Some(conn) => conn,
                    None => {
                        let stream = (self.dial)().await?;
                        let conn =
                            Conn::start(stream, self.broken.clone(), self.cancel.child_token());
                        for old in conns.iter() {
                            old.retired.store(true, Ordering::Relaxed);
                        }
                        conns.push(conn.clone());
                        conn
                    }
                }
            }
        };
        drop(conns);

        let (tx, rx) = mpsc::channel(QUEUE);
        let session = conn.open_flow(key, gid, &target, tx, &self.next_id)?;
        conn.opened.store(true, Ordering::Relaxed);
        *conn.idle_at.lock() = None;
        Ok(MuxUdp {
            session,
            target,
            rx: Mutex::new(rx),
            conn,
        })
    }
}

impl Drop for MuxClient {
    fn drop(&mut self) {
        // Every Conn holds a child token, so one cancel releases the reader,
        // the writer and the keepalive of the current and of retired
        // connections without taking a lock.
        self.cancel.cancel();
    }
}

struct Conn {
    /// Serialized frames to the writer task.
    tx: mpsc::Sender<Vec<u8>>,
    sessions: SyncMutex<Sessions>,
    closed: AtomicBool,
    /// Stops the reader and the writer, so the stream is dropped and the
    /// connection really closes.
    cancel: CancellationToken,
    /// A full connection replaced by a fresh one: it serves the flows already
    /// on it and closes once the last one ends.
    retired: AtomicBool,
    /// Any reply arrived: without one a closed connection looks like a server
    /// that does not speak Mux.Cool.
    ever_data: AtomicBool,
    /// A session was opened on this connection.
    opened: AtomicBool,
    opened_at: Instant,
    /// When the last session ended; None while a session is alive.
    idle_at: SyncMutex<Option<Instant>>,
    broken: Arc<SyncMutex<Option<Instant>>>,
}

#[derive(Default)]
struct Sessions {
    by_id: HashMap<u16, Arc<SourceSession>>,
    by_key: HashMap<SessionKey, Arc<SourceSession>>,
}

impl Sessions {
    fn len(&self) -> usize {
        self.by_id.len()
    }

    fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    fn get(&self, id: u16) -> Option<Arc<SourceSession>> {
        self.by_id.get(&id).cloned()
    }

    fn by_key(&self, key: &SessionKey) -> Option<Arc<SourceSession>> {
        self.by_key.get(key).cloned()
    }

    fn remove(&mut self, id: u16) -> Option<Arc<SourceSession>> {
        let session = self.by_id.remove(&id)?;
        self.by_key.remove(&session.key);
        Some(session)
    }

    fn clear(&mut self) {
        for (_, session) in self.by_id.drain() {
            session.shutdown();
        }
        self.by_key.clear();
    }
}

/// What identifies a session. A local socket gets one session; a flow without
/// one (a DNS query) gets its own.
#[derive(Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    Source(SocketAddr),
    /// A domain destination gets a session of its own: the server resolves the
    /// name and replies from the IP, which cannot be matched to the name.
    Destination(SocketAddr, TargetAddr),
    Anonymous(u64),
}

/// One local UDP socket: a Mux.Cool session that carries every destination the
/// socket talks to.
struct SourceSession {
    id: u16,
    key: SessionKey,
    gid: [u8; 8],
    tx: mpsc::Sender<Vec<u8>>,
    /// Destination -> queue into the waiting `MuxUdp`.
    flows: SyncMutex<HashMap<TargetAddr, mpsc::Sender<Vec<u8>>>>,
    /// Serializes the choice of the first frame with its enqueue: a second
    /// destination must never reach the server before the first frame opened
    /// the session.
    first: Mutex<bool>,
    /// The target of the `new` frame: the link was dispatched to it, so an
    /// address-less reply belongs to this flow.
    origin: SyncMutex<Option<TargetAddr>>,
    closed: AtomicBool,
}

impl SourceSession {
    async fn send(&self, target: &TargetAddr, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::protocol("mux session ended"));
        }
        let mut first = self.first.lock().await;
        let frame = if *first {
            let frame = new_udp_frame(self.id, target, &self.gid, payload)?;
            *self.origin.lock() = Some(target.clone());
            frame
        } else {
            data_frame(self.id, Some(target), payload)
        };
        match self.tx.send(frame).await {
            Ok(()) => {
                *first = false;
                Ok(())
            }
            Err(_) => {
                self.closed.store(true, Ordering::Relaxed);
                Err(Error::protocol("mux: connection closed"))
            }
        }
    }

    /// Routes a reply to the flow it belongs to. The address on the frame is
    /// the source the server's socket got the datagram from.
    fn deliver(&self, dest: Option<TargetAddr>, data: Vec<u8>) {
        let flows = self.flows.lock();
        let exact = dest.as_ref().and_then(|dest| flows.get(dest)).cloned();
        let tx = exact.or_else(|| {
            if dest.is_none() {
                // The server omitted the source (an outbound that overrides
                // the destination): the link belongs to the `new` target.
                if let Some(origin) = self.origin.lock().as_ref()
                    && let Some(tx) = flows.get(origin)
                {
                    return Some(tx.clone());
                }
                return (flows.len() == 1).then(|| flows.values().next().cloned()).flatten();
            }
            // A domain destination is answered from its resolved IP, which is
            // not the flow's key. Such sessions carry one flow on purpose.
            if flows.len() == 1 {
                let (target, tx) = flows.iter().next()?;
                if matches!(target.addr, Address::Domain(_)) {
                    return Some(tx.clone());
                }
            }
            None
        });
        if let Some(tx) = tx {
            // Drop on a full queue instead of holding up every other flow:
            // Mux.Cool has no per-session flow control.
            if tx.try_send(data).is_err() {
                tracing::trace!("mux: datagram dropped, session queue full");
            }
        }
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Dropping the senders closes every receiver: a flow blocked on `recv`
        // sees the end at once instead of waiting for a frame that will not come.
        self.flows.lock().clear();
    }
}

impl Conn {
    fn start(stream: BoxStream, broken: Arc<SyncMutex<Option<Instant>>>, cancel: CancellationToken) -> Arc<Conn> {
        let (tx, rx) = mpsc::channel(QUEUE);
        let conn = Arc::new(Conn {
            tx,
            sessions: SyncMutex::new(Sessions::default()),
            closed: AtomicBool::new(false),
            cancel,
            retired: AtomicBool::new(false),
            ever_data: AtomicBool::new(false),
            opened: AtomicBool::new(false),
            opened_at: Instant::now(),
            idle_at: SyncMutex::new(None),
            broken,
        });
        let (reader, writer) = tokio::io::split(stream);
        tokio::spawn(write_frames(writer, rx, conn.clone()));
        tokio::spawn(read_frames(reader, conn.clone()));
        tokio::spawn(keep_alive(conn.clone()));
        conn
    }

    /// Finds or creates the session for `key` and registers `target` on it
    /// under one lock, so the last flow's drop cannot remove the session in
    /// between and orphan the new flow.
    fn open_flow(
        &self,
        key: SessionKey,
        gid: [u8; 8],
        target: &TargetAddr,
        tx: mpsc::Sender<Vec<u8>>,
        next_id: &AtomicU16,
    ) -> Result<Arc<SourceSession>> {
        let mut sessions = self.sessions.lock();
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::protocol("mux: connection closed"));
        }
        let session = match sessions.by_key.get(&key) {
            Some(session) => session.clone(),
            None => {
                if sessions.len() >= MAX_SESSIONS {
                    return Err(Error::protocol("mux: too many sessions on one connection"));
                }
                let id = loop {
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    if id != 0 && !sessions.by_id.contains_key(&id) {
                        break id;
                    }
                };
                let session = Arc::new(SourceSession {
                    id,
                    key: key.clone(),
                    gid,
                    tx: self.tx.clone(),
                    flows: SyncMutex::new(HashMap::new()),
                    first: Mutex::new(true),
                    origin: SyncMutex::new(None),
                    closed: AtomicBool::new(false),
                });
                sessions.by_id.insert(id, session.clone());
                sessions.by_key.insert(key, session.clone());
                session
            }
        };
        let mut flows = session.flows.lock();
        if flows.contains_key(target) {
            return Err(Error::protocol("mux: destination already open"));
        }
        flows.insert(target.clone(), tx);
        drop(flows);
        Ok(session)
    }

    fn shutdown(&self) {
        // A server without Mux.Cool closes the connection right after the
        // first new-session frame; remember it so the next flows take the
        // plain VLESS UDP path.
        if self.opened.load(Ordering::Relaxed)
            && !self.ever_data.load(Ordering::Relaxed)
            && self.opened_at.elapsed() < REJECT_WINDOW
        {
            *self.broken.lock() = Some(Instant::now());
        }
        self.closed.store(true, Ordering::Relaxed);
        self.cancel.cancel();
        // Dropping the senders closes every receiver: a flow blocked on `recv`
        // sees the end at once instead of waiting for a frame that will not come.
        self.sessions.lock().clear();
    }

    /// Closes the connection when it has no sessions and is either idle or
    /// retired. The check and the `closed` flag are under the sessions lock, so
    /// a flow that opens concurrently either keeps the connection or is refused.
    fn close_if_idle(&self) -> bool {
        let sessions = self.sessions.lock();
        if !sessions.is_empty() {
            return false;
        }
        let idle = *self.idle_at.lock();
        let expired = idle.is_some_and(|at| at.elapsed() > IDLE_RETIRE);
        if !expired && !self.retired.load(Ordering::Relaxed) {
            return false;
        }
        self.closed.store(true, Ordering::Relaxed);
        drop(sessions);
        self.shutdown();
        true
    }
}

async fn read_frames(mut r: ReadHalf<BoxStream>, conn: Arc<Conn>) {
    loop {
        let frame = tokio::select! {
            _ = conn.cancel.cancelled() => break,
            frame = read_frame(&mut r) => frame,
        };
        let idle = match frame {
            Ok(Some(frame)) => match frame.status {
                STATUS_NEW | STATUS_KEEP => {
                    if let Some(data) = frame.data {
                        conn.ever_data.store(true, Ordering::Relaxed);
                        let session = { conn.sessions.lock().get(frame.id) };
                        if let Some(session) = session {
                            session.deliver(frame.target.map(|(_, target)| target), data);
                        }
                    }
                    false
                }
                STATUS_END => {
                    let session = { conn.sessions.lock().remove(frame.id) };
                    if let Some(session) = session {
                        session.shutdown();
                    }
                    conn.sessions.lock().is_empty()
                }
                // A server never opens sessions or pings; ignore the rest.
                _ => false,
            },
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("mux connection ended: {e}");
                break;
            }
        };
        if idle {
            *conn.idle_at.lock() = Some(Instant::now());
        }
    }
    conn.shutdown();
}

async fn write_frames(
    mut w: WriteHalf<BoxStream>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    conn: Arc<Conn>,
) {
    loop {
        let mut batch = tokio::select! {
            _ = conn.cancel.cancelled() => break,
            frame = rx.recv() => match frame {
                Some(frame) => frame,
                None => break,
            },
        };
        while batch.len() < 64 * 1024 {
            match rx.try_recv() {
                Ok(frame) => batch.extend_from_slice(&frame),
                Err(_) => break,
            }
        }
        let written = tokio::select! {
            _ = conn.cancel.cancelled() => break,
            r = w.write_all(&batch) => r,
        };
        if written.is_err() {
            break;
        }
        let flushed = tokio::select! {
            _ = conn.cancel.cancelled() => break,
            r = w.flush() => r,
        };
        if flushed.is_err() {
            break;
        }
    }
    let _ = tokio::time::timeout(SHUTDOWN_WAIT, w.shutdown()).await;
    conn.shutdown();
}

/// Keeps the connection from going quiet long enough for a NAT to reap it.
async fn keep_alive(conn: Arc<Conn>) {
    loop {
        tokio::time::sleep(KEEPALIVE).await;
        if conn.closed.load(Ordering::Relaxed) || conn.close_if_idle() {
            return;
        }
        // Best effort: a full writer queue already proves the connection is busy.
        let _ = conn.tx.try_send(keepalive_frame(0));
    }
}

/// One destination on a shared source session.
pub struct MuxUdp {
    session: Arc<SourceSession>,
    target: TargetAddr,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    conn: Arc<Conn>,
}

impl Drop for MuxUdp {
    fn drop(&mut self) {
        let last = {
            let mut sessions = self.conn.sessions.lock();
            let mut flows = self.session.flows.lock();
            flows.remove(&self.target);
            if flows.is_empty()
                && sessions
                    .by_id
                    .get(&self.session.id)
                    .is_some_and(|session| Arc::ptr_eq(session, &self.session))
            {
                sessions.remove(self.session.id);
                true
            } else {
                false
            }
        };
        if last {
            self.session.shutdown();
            if self.conn.sessions.lock().is_empty() {
                *self.conn.idle_at.lock() = Some(Instant::now());
            }
            // Tell the server the session is over. A full writer queue must not
            // lose the frame: the server would keep the UDP socket until its
            // idle timeout. Fall back to a task that waits for room.
            let frame = end_frame(self.session.id);
            if self.session.tx.try_send(frame.clone()).is_err()
                && let Ok(handle) = tokio::runtime::Handle::try_current()
            {
                let tx = self.session.tx.clone();
                handle.spawn(async move {
                    let _ = tx.send(frame).await;
                });
            }
        }
    }
}

#[async_trait::async_trait]
impl PacketStream for MuxUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        self.session.send(&self.target, payload).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        let data = rx
            .recv()
            .await
            .ok_or_else(|| Error::protocol("mux session ended"))?;
        let out = buf
            .get_mut(..data.len())
            .ok_or_else(|| Error::protocol("mux: UDP packet larger than buffer"))?;
        out.copy_from_slice(&data);
        Ok(data.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::mux::{STATUS_END, STATUS_KEEP, STATUS_NEW, read_frame};

    fn src(port: u16) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn target(port: u16) -> TargetAddr {
        TargetAddr::from(SocketAddr::from(([1, 2, 3, 4], port)))
    }

    /// Echoes every datagram back, naming the destination it came from — what
    /// a full-cone server does.
    async fn echo_server<S>(io: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut r, mut w) = tokio::io::split(io);
        while let Ok(Some(frame)) = read_frame(&mut r).await {
            match frame.status {
                STATUS_NEW | STATUS_KEEP => {
                    if let Some(data) = frame.data {
                        let dest = frame.target.map(|(_, target)| target);
                        let reply = data_frame(frame.id, dest.as_ref(), &data);
                        if w.write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                }
                STATUS_END => return,
                _ => {}
            }
        }
    }

    fn client_with_echo(dials: Arc<AtomicUsize>) -> MuxClient {
        MuxClient::new(move || {
            let dials = dials.clone();
            async move {
                dials.fetch_add(1, Ordering::Relaxed);
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(echo_server(server));
                Ok(Box::new(client) as BoxStream)
            }
        })
    }

    #[tokio::test]
    async fn destinations_of_one_socket_share_a_session() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = client_with_echo(dials.clone());
        let one = client.open_udp(src(40000), target(9001)).await.unwrap();
        let two = client.open_udp(src(40000), target(9002)).await.unwrap();
        assert_eq!(dials.load(Ordering::Relaxed), 1, "one tunnel for both");
        let conns = client.conns.lock().await;
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].sessions.lock().len(), 1, "one session per socket");

        one.send(b"first").await.unwrap();
        two.send(b"second").await.unwrap();
        let mut buf = [0u8; 32];
        // Each reply names the destination it came from.
        let a = one.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..a], b"first");
        let b = two.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..b], b"second");
    }

    /// A server that answers every datagram from `reply_from`.
    fn client_replying_from(reply_from: TargetAddr) -> MuxClient {
        MuxClient::new(move || {
            let reply_from = reply_from.clone();
            async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(server);
                    while let Ok(Some(frame)) = read_frame(&mut r).await {
                        if let Some(data) = frame.data {
                            let reply = data_frame(frame.id, Some(&reply_from), &data);
                            if w.write_all(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
                Ok(Box::new(client) as BoxStream)
            }
        })
    }

    #[tokio::test]
    async fn a_domain_destination_takes_replies_from_its_ip() {
        // The server resolves the name and answers from the IP, which is not
        // the flow's key. With fake-IP this is every TUN flow.
        let client = client_replying_from("1.2.3.4:53".parse().unwrap());
        let flow = client
            .open_udp(src(40000), "dns.example:53".parse().unwrap())
            .await
            .unwrap();
        flow.send(b"q").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), flow.recv(&mut buf))
            .await
            .expect("the reply from the resolved IP must arrive")
            .unwrap();
        assert_eq!(&buf[..n], b"q");
    }

    #[tokio::test]
    async fn an_unknown_peer_does_not_hijack_a_single_ip_flow() {
        // A datagram from a peer that was never a destination must not be
        // handed to an IP flow: the application would see the wrong source.
        let client = client_replying_from("5.6.7.8:9001".parse().unwrap());
        let flow = client.open_udp(src(40000), target(9001)).await.unwrap();
        flow.send(b"x").await.unwrap();
        let mut buf = [0u8; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), flow.recv(&mut buf))
                .await
                .is_err(),
            "an unassociated peer is not delivered"
        );
    }

    #[tokio::test]
    async fn a_domain_destination_gets_its_own_session() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = client_with_echo(dials);
        let _ip = client.open_udp(src(40000), target(9001)).await.unwrap();
        let _domain = client
            .open_udp(src(40000), "dns.example:53".parse().unwrap())
            .await
            .unwrap();
        let conns = client.conns.lock().await;
        assert_eq!(conns[0].sessions.lock().len(), 2);
    }

    #[tokio::test]
    async fn flows_without_a_socket_do_not_collide() {
        // DNS queries have no local socket and may name the same server at the
        // same time: each must get its own session.
        let dials = Arc::new(AtomicUsize::new(0));
        let client = client_with_echo(dials.clone());
        let one = client.open_udp(None, target(53)).await.unwrap();
        let two = client.open_udp(None, target(53)).await.unwrap();
        assert_eq!(dials.load(Ordering::Relaxed), 1);
        one.send(b"a").await.unwrap();
        two.send(b"b").await.unwrap();
        let mut buf = [0u8; 8];
        let n = one.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"a");
        let n = two.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"b");
    }

    #[tokio::test]
    async fn different_sockets_get_their_own_sessions() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = client_with_echo(dials.clone());
        let _one = client.open_udp(src(40000), target(9001)).await.unwrap();
        let _two = client.open_udp(src(40001), target(9001)).await.unwrap();
        assert_eq!(dials.load(Ordering::Relaxed), 1, "one tunnel for both");
        let conns = client.conns.lock().await;
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].sessions.lock().len(), 2, "one session per socket");
    }

    #[tokio::test]
    async fn a_server_without_mux_is_remembered() {
        // The server closes right after the new-session frame, the way one that
        // does not implement Mux.Cool does. The client must stop trying mux and
        // let the plain path take over.
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_for_client = dials.clone();
        let client = MuxClient::new(move || {
            let dials = dials_for_client.clone();
            async move {
                dials.fetch_add(1, Ordering::Relaxed);
                let (client, server) = tokio::io::duplex(64 * 1024);
                drop(server);
                Ok(Box::new(client) as BoxStream)
            }
        });

        let flow = client.open_udp(src(40000), target(9001)).await.unwrap();
        let mut buf = [0u8; 8];
        assert!(flow.send(b"x").await.is_err() || flow.recv(&mut buf).await.is_err());
        for _ in 0..100 {
            if client.is_broken() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(client.is_broken(), "a rejection is remembered");
        assert!(
            client
                .open_udp(src(40000), target(9001))
                .await
                .is_err()
        );
        assert_eq!(dials.load(Ordering::Relaxed), 1, "no second mux dial");
        // For a while: the plain path is tried again later.
        let at = client.broken.lock().expect("marked");
        *client.broken.lock() = at.checked_sub(BROKEN_TTL);
        assert!(!client.is_broken(), "a rejection expires");
    }

    #[tokio::test]
    async fn a_connection_that_carried_data_is_not_marked_broken() {
        // A healthy connection that later dies must not disable mux for the
        // outbound: the next flow dials again.
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_for_client = dials.clone();
        let client = MuxClient::new(move || {
            let dials = dials_for_client.clone();
            async move {
                let n = dials.fetch_add(1, Ordering::Relaxed);
                let (client, server) = tokio::io::duplex(64 * 1024);
                if n == 0 {
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(server);
                        // Reply once, then drop the connection.
                        while let Ok(Some(frame)) = read_frame(&mut r).await {
                            if let Some(data) = frame.data {
                                let reply = data_frame(frame.id, None, &data);
                                w.write_all(&reply).await.ok();
                                break;
                            }
                        }
                    });
                } else {
                    tokio::spawn(echo_server(server));
                }
                Ok(Box::new(client) as BoxStream)
            }
        });

        let first = client.open_udp(src(40000), target(9001)).await.unwrap();
        first.send(b"hi").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(first.recv(&mut buf).await.unwrap(), 2);
        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!client.is_broken());

        let second = client.open_udp(src(40000), target(9001)).await.unwrap();
        second.send(b"ok").await.unwrap();
        assert_eq!(second.recv(&mut buf).await.unwrap(), 2);
        assert!(dials.load(Ordering::Relaxed) >= 2);
    }

    /// A dial whose server side only waits for EOF and reports it.
    fn watching_dial(closed: Arc<AtomicBool>) -> impl Fn() -> DialFuture + Send + Sync {
        move || {
            let closed = closed.clone();
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        match server.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                closed.store(true, Ordering::Relaxed);
                                return;
                            }
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxStream)
            }) as DialFuture
        }
    }

    #[tokio::test]
    async fn dropping_the_client_closes_the_tunnel() {
        let closed = Arc::new(AtomicBool::new(false));
        let client = MuxClient::new(watching_dial(closed.clone()));
        let _flow = client.open_udp(src(40000), target(9001)).await.unwrap();
        drop(client);
        for _ in 0..100 {
            if closed.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(closed.load(Ordering::Relaxed), "the stream really closed");
    }

    #[tokio::test]
    async fn an_idle_tunnel_is_closed() {
        let closed = Arc::new(AtomicBool::new(false));
        let client = MuxClient::new(watching_dial(closed.clone()));
        let flow = client.open_udp(src(40000), target(9001)).await.unwrap();
        drop(flow);
        tokio::time::sleep(IDLE_RETIRE + KEEPALIVE * 4).await;
        assert!(closed.load(Ordering::Relaxed), "an idle tunnel is reaped");
    }

    #[tokio::test]
    async fn a_full_tunnel_grows_another_one() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = client_with_echo(dials.clone());
        let mut flows = Vec::new();
        for i in 0..=MAX_SESSIONS {
            flows.push(
                client
                    .open_udp(src(40000 + i as u16), target(9001))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(dials.load(Ordering::Relaxed), 2, "a second tunnel");
        for flow in &flows {
            flow.send(b"ok").await.unwrap();
            let mut buf = [0u8; 8];
            let n = flow.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ok");
        }
    }

    #[tokio::test]
    async fn frames_are_written_without_interleaving() {
        // Two sessions write concurrently; the writer queue serializes whole
        // frames, so the server must read exactly three data frames.
        let frames = Arc::new(AtomicUsize::new(0));
        let frames_for_client = frames.clone();
        let client = MuxClient::new(move || {
            let frames = frames_for_client.clone();
            async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let (mut r, _w) = tokio::io::split(server);
                    while let Ok(Some(frame)) = read_frame(&mut r).await {
                        match frame.status {
                            STATUS_NEW | STATUS_KEEP => {
                                if frame.data.is_some() {
                                    frames.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            STATUS_END => return,
                            _ => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxStream)
            }
        });
        let a = client.open_udp(src(40000), target(9001)).await.unwrap();
        let b = client.open_udp(src(40001), target(9002)).await.unwrap();
        a.send(b"aaaa").await.unwrap();
        b.send(b"bb").await.unwrap();
        a.send(b"a").await.unwrap();
        for _ in 0..100 {
            if frames.load(Ordering::Relaxed) == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(frames.load(Ordering::Relaxed), 3, "three whole frames arrived");
    }
}
