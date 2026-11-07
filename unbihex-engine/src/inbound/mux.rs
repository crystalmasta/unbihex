//! Mux.Cool on the server: many TCP and UDP sessions inside one VLESS stream
//! (command 3). XUDP — how Xray clients send UDP for Vision users and for full-cone
//! UDP — is Mux.Cool with session 0 and a destination on every packet.
//!
//! ```text
//! meta_len(be16) | id(be16) | status | option | [network | port(be16) | atyp | addr | [global_id(8)]]
//! [data_len(be16) | data]            (when option has bit 0x01)
//! ```
//!
//! The address is present on `new` frames and on UDP `keep` frames that carry one.
//! Replies go back as `keep` frames; a UDP reply names the destination it came from.
//!
//! Each UDP destination of a session is a flow of its own through the dispatcher,
//! so routing applies per destination (the outbound socket differs per destination
//! too). The global ID is read but flows are not kept across reconnects yet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::address::TargetAddr;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::outbound::PacketStream;
use crate::session::{Network, Session};

const MAX_SESSIONS: usize = 128;
/// Destinations one UDP session may reach at once. Xray clients put every
/// destination of one local socket into a single session, and a browser can
/// easily exceed a few dozen; the old 64 silently dropped the rest.
const MAX_UDP_FLOWS: usize = 256;
/// TCP replies are cut into frames of at most this size, as Xray does.
const TCP_CHUNK: usize = 8 * 1024;
const TCP_PIPE: usize = 64 * 1024;
const UDP_QUEUE: usize = 64;

use crate::mux::{
    NETWORK_TCP, STATUS_END, STATUS_KEEP, STATUS_NEW, data_frame, end_frame,
    read_frame,
};

/// Who the sessions of one Mux.Cool stream belong to.
pub struct MuxContext {
    /// Routes the sessions.
    pub dispatcher: Arc<Dispatcher>,
    /// The client's address.
    pub source: SocketAddr,
    /// The inbound that accepted the stream.
    pub inbound_tag: String,
    /// Whether TCP sessions are served. Vision users get UDP only: with TCP inside,
    /// the connection would carry TLS-in-TLS that Vision cannot shape.
    pub allow_tcp: bool,
}

enum Sub {
    Tcp {
        uplink: WriteHalf<DuplexStream>,
        task: JoinHandle<()>,
    },
    Udp {
        target: TargetAddr,
        flows: HashMap<TargetAddr, mpsc::Sender<Vec<u8>>>,
    },
}

impl Sub {
    fn alive(&self) -> bool {
        match self {
            Sub::Tcp { task, .. } => !task.is_finished(),
            Sub::Udp { flows, .. } => flows.values().any(|f| !f.is_closed()),
        }
    }

    /// Ends the uplink: EOF for TCP (a dropped half of a split stream would not
    /// signal it), a closed queue for UDP flows.
    async fn close(self) {
        if let Sub::Tcp { mut uplink, .. } = self {
            uplink.shutdown().await.ok();
        }
    }
}

/// Serves every session of `stream` until the client closes it.
pub async fn serve<S>(stream: S, ctx: MuxContext)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut r, w) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    let done = CancellationToken::new();
    // Sessions and the writer end with the stream.
    let _stop = done.clone().drop_guard();
    tokio::spawn(write_frames(w, rx, done.clone()));
    let mut sessions = HashMap::new();
    let result = tokio::select! {
        _ = done.cancelled() => Ok(()),
        r = demux(&mut r, &mut sessions, &ctx, &tx, &done) => r,
    };
    if let Err(e) = result {
        tracing::debug!("mux {}: {e}", ctx.source);
    }
}

async fn demux<R: AsyncRead + Unpin>(
    r: &mut R,
    sessions: &mut HashMap<u16, Sub>,
    ctx: &MuxContext,
    tx: &mpsc::Sender<Vec<u8>>,
    done: &CancellationToken,
) -> Result<()> {
    while let Some(f) = read_frame(r).await? {
        match f.status {
            STATUS_NEW => {
                let Some((network, target)) = f.target else {
                    return Err(Error::protocol("mux: new session without a destination"));
                };
                if let Some(old) = sessions.remove(&f.id) {
                    old.close().await;
                }
                if sessions.len() >= MAX_SESSIONS {
                    sessions.retain(|_, s| s.alive());
                }
                if sessions.len() >= MAX_SESSIONS {
                    tx.send(end_frame(f.id)).await.ok();
                    continue;
                }
                let mut sub = match network {
                    NETWORK_TCP if ctx.allow_tcp => open_tcp(f.id, target, ctx, tx, done),
                    NETWORK_TCP => {
                        return Err(Error::protocol("mux: TCP sessions are refused for Vision"));
                    }
                    _ => Sub::Udp {
                        target,
                        flows: HashMap::new(),
                    },
                };
                let alive = match f.data {
                    Some(data) => deliver(f.id, &mut sub, None, data, ctx, tx, done).await,
                    None => true,
                };
                if alive {
                    sessions.insert(f.id, sub);
                }
            }
            STATUS_KEEP => match sessions.get_mut(&f.id) {
                Some(sub) => {
                    if let Some(data) = f.data {
                        let dest = f.target.map(|(_, t)| t);
                        if !deliver(f.id, sub, dest, data, ctx, tx, done).await {
                            sessions.remove(&f.id);
                        }
                    }
                }
                // Xray tells the client a session it does not know is over.
                None => {
                    tx.send(end_frame(f.id)).await.ok();
                }
            },
            STATUS_END => {
                if let Some(sub) = sessions.remove(&f.id) {
                    sub.close().await;
                }
            }
            // Keep-alive.
            _ => {}
        }
    }
    Ok(())
}

/// Hands uplink data to a session; false when the session is gone.
async fn deliver(
    id: u16,
    sub: &mut Sub,
    dest: Option<TargetAddr>,
    data: Vec<u8>,
    ctx: &MuxContext,
    tx: &mpsc::Sender<Vec<u8>>,
    done: &CancellationToken,
) -> bool {
    match sub {
        // Like Xray, a slow TCP destination holds up the whole stream: there is no
        // per-session flow control in Mux.Cool.
        Sub::Tcp { uplink, .. } => data.is_empty() || uplink.write_all(&data).await.is_ok(),
        Sub::Udp { target, flows } => {
            if data.is_empty() {
                return true;
            }
            let dest = dest.unwrap_or_else(|| target.clone());
            // A full queue drops the datagram; a closed one means the flow went idle.
            let data = match flows.get(&dest) {
                None => data,
                Some(f) => match f.try_send(data) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return true,
                    Err(mpsc::error::TrySendError::Closed(data)) => data,
                },
            };
            flows.retain(|_, f| !f.is_closed());
            if flows.len() >= MAX_UDP_FLOWS {
                tracing::debug!("mux: {} UDP flows, dropping {}", MAX_UDP_FLOWS, dest);
                return true;
            }
            flows.insert(dest.clone(), open_udp(id, dest, data, ctx, tx, done));
            true
        }
    }
}

fn open_tcp(
    id: u16,
    target: TargetAddr,
    ctx: &MuxContext,
    tx: &mpsc::Sender<Vec<u8>>,
    done: &CancellationToken,
) -> Sub {
    let (inner, outer) = tokio::io::duplex(TCP_PIPE);
    let (mut downlink, uplink) = tokio::io::split(outer);
    let sess = Session {
        network: Network::Tcp,
        source: Some(ctx.source),
        target,
        inbound_tag: ctx.inbound_tag.clone(),
        sniffed: None,
    };
    let (d, stop) = (ctx.dispatcher.clone(), done.clone());
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = stop.cancelled() => {}
            _ = d.dispatch_tcp(sess, Box::new(inner)) => {}
        }
    });
    let (tx, stop) = (tx.clone(), done.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_CHUNK];
        loop {
            let n = tokio::select! {
                _ = stop.cancelled() => return,
                r = downlink.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                },
            };
            if tx.send(data_frame(id, None, &buf[..n])).await.is_err() {
                return;
            }
        }
        tx.send(end_frame(id)).await.ok();
    });
    Sub::Tcp { uplink, task }
}

fn open_udp(
    id: u16,
    dest: TargetAddr,
    first: Vec<u8>,
    ctx: &MuxContext,
    tx: &mpsc::Sender<Vec<u8>>,
    done: &CancellationToken,
) -> mpsc::Sender<Vec<u8>> {
    let (queue, rx) = mpsc::channel(UDP_QUEUE);
    queue.try_send(first).ok();
    let sess = Session {
        network: Network::Udp,
        source: Some(ctx.source),
        target: dest.clone(),
        inbound_tag: ctx.inbound_tag.clone(),
        sniffed: None,
    };
    let flow = MuxUdp {
        id,
        dest,
        rx: Mutex::new(rx),
        tx: tx.clone(),
    };
    let (d, stop) = (ctx.dispatcher.clone(), done.clone());
    tokio::spawn(async move {
        tokio::select! {
            _ = stop.cancelled() => {}
            _ = d.dispatch_udp(sess, Box::new(flow)) => {}
        }
    });
    queue
}

/// One UDP destination of a mux session, as the dispatcher sees it.
struct MuxUdp {
    id: u16,
    dest: TargetAddr,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl PacketStream for MuxUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        self.tx
            .send(data_frame(self.id, Some(&self.dest), payload))
            .await
            .map_err(|_| Error::protocol("mux stream closed"))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let p = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::protocol("mux session ended"))?;
        let b = buf
            .get_mut(..p.len())
            .ok_or_else(|| Error::protocol("UDP packet larger than buffer"))?;
        b.copy_from_slice(&p);
        Ok(p.len())
    }
}

/// Writes queued frames, batching what is already waiting.
async fn write_frames<W: AsyncWrite + Unpin>(
    mut w: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    done: CancellationToken,
) {
    let write = async {
        while let Some(mut batch) = rx.recv().await {
            while batch.len() < TCP_PIPE {
                match rx.try_recv() {
                    Ok(f) => batch.extend_from_slice(&f),
                    Err(_) => break,
                }
            }
            w.write_all(&batch).await?;
            w.flush().await?;
        }
        w.shutdown().await
    };
    tokio::select! {
        _ = done.cancelled() => {}
        r = write => if let Err(e) = r { tracing::trace!("mux writer: {e}") },
    }
    done.cancel();
}
