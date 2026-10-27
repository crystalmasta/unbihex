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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, TargetAddr, normalize_domain};
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::outbound::PacketStream;
use crate::outbound::xudp::write_addr;
use crate::session::{Network, Session};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEPALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 2;
/// Xray refuses longer metadata as well.
const MAX_META: usize = 512;
const MAX_SESSIONS: usize = 128;
const MAX_UDP_FLOWS: usize = 64;
/// TCP replies are cut into frames of at most this size, as Xray does.
const TCP_CHUNK: usize = 8 * 1024;
const TCP_PIPE: usize = 64 * 1024;
const UDP_QUEUE: usize = 64;

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

/// One parsed frame.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    id: u16,
    status: u8,
    target: Option<(u8, TargetAddr)>,
    data: Option<Vec<u8>>,
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

/// A `keep` frame with data; UDP replies name their source.
fn data_frame(id: u16, udp_source: Option<&TargetAddr>, data: &[u8]) -> Vec<u8> {
    let mut meta = Vec::with_capacity(32);
    meta.extend_from_slice(&id.to_be_bytes());
    meta.extend_from_slice(&[STATUS_KEEP, OPTION_DATA]);
    if let Some(src) = udp_source {
        let mut addr = Vec::with_capacity(24);
        // A domain over 255 bytes cannot come in, so it cannot go out either.
        if write_addr(&mut addr, src).is_ok() {
            meta.push(NETWORK_UDP);
            meta.extend_from_slice(&addr);
        }
    }
    // Callers keep data within u16 (TCP chunks, UDP datagrams).
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(4 + meta.len() + data.len());
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data[..usize::from(len)]);
    out
}

fn end_frame(id: u16) -> Vec<u8> {
    let mut out = vec![0, 4];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[STATUS_END, 0]);
    out
}

/// Reads one frame; None at a clean end of the stream.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let meta_len = usize::from(u16::from_be_bytes(len));
    if !(4..=MAX_META).contains(&meta_len) {
        return Err(Error::protocol(format!("mux: metadata length {meta_len}")));
    }
    let mut meta = vec![0u8; meta_len];
    r.read_exact(&mut meta).await?;
    let mut f = parse_meta(&meta)?;
    if meta[3] & OPTION_DATA != 0 {
        let len = usize::from(r.read_u16().await?);
        let mut data = vec![0u8; len];
        r.read_exact(&mut data).await?;
        f.data = Some(data);
    }
    Ok(Some(f))
}

fn parse_meta(meta: &[u8]) -> Result<Frame> {
    let bad = || Error::protocol("mux: malformed frame");
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    if !(STATUS_NEW..=STATUS_KEEPALIVE).contains(&status) {
        return Err(Error::protocol(format!("mux: frame status {status}")));
    }
    let mut target = None;
    if status == STATUS_NEW || (status == STATUS_KEEP && meta.len() > 4) {
        let network = *meta.get(4).ok_or_else(bad)?;
        if network != NETWORK_TCP && network != NETWORK_UDP {
            return Err(Error::protocol(format!("mux: network {network}")));
        }
        // The global ID that may follow a UDP destination is not used yet.
        let (addr, _rest) = parse_addr(meta.get(5..).ok_or_else(bad)?)?;
        target = Some((network, addr));
    }
    Ok(Frame {
        id,
        status,
        target,
        data: None,
    })
}

/// `port(be16) | atyp | addr`, returning what follows it.
fn parse_addr(b: &[u8]) -> Result<(TargetAddr, &[u8])> {
    let bad = || Error::protocol("mux: malformed address");
    let (head, rest) = b.split_at_checked(3).ok_or_else(bad)?;
    let port = u16::from_be_bytes([head[0], head[1]]);
    let (addr, rest) = match head[2] {
        1 => {
            let (a, rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
            (Address::Ip(Ipv4Addr::from(*a).into()), rest)
        }
        2 => {
            let (&n, rest) = rest.split_first().ok_or_else(bad)?;
            let (name, rest) = rest.split_at_checked(usize::from(n)).ok_or_else(bad)?;
            let name = std::str::from_utf8(name).map_err(|_| bad())?;
            (
                Address::Domain(normalize_domain(name).map_err(|_| bad())?),
                rest,
            )
        }
        3 => {
            let (a, rest) = rest.split_first_chunk::<16>().ok_or_else(bad)?;
            (Address::Ip(Ipv6Addr::from(*a).into()), rest)
        }
        t => return Err(Error::protocol(format!("mux: address type {t}"))),
    };
    Ok((TargetAddr::new(addr, port), rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::xudp::encode_packet;

    #[tokio::test]
    async fn reads_xudp_frames() {
        let dest: TargetAddr = "1.2.3.4:53".parse().unwrap();
        let mut wire = encode_packet(true, &dest, &[7; 8], b"q").unwrap();
        let other: TargetAddr = "Example.com:443".parse().unwrap();
        wire.extend(encode_packet(false, &other, &[7; 8], b"zz").unwrap());
        wire.extend(end_frame(0));
        let mut r = &wire[..];
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(
            f,
            Frame {
                id: 0,
                status: STATUS_NEW,
                target: Some((NETWORK_UDP, dest)),
                data: Some(b"q".to_vec()),
            }
        );
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEP);
        assert_eq!(
            f.target,
            Some((NETWORK_UDP, "example.com:443".parse().unwrap()))
        );
        assert_eq!(f.data.as_deref(), Some(&b"zz"[..]));
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!((f.status, f.target, f.data), (STATUS_END, None, None));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_malformed_frames() {
        for wire in [
            &[0, 3, 0, 0, 2][..],                             // metadata too short
            &[0, 6, 0, 1, STATUS_NEW, 0, 9, 0][..],           // unknown network
            &[0, 8, 0, 1, STATUS_NEW, 0, 1, 0, 80, 4][..],    // unknown address type
            &[0, 9, 0, 1, STATUS_NEW, 0, 1, 0, 80, 1, 1][..], // truncated IPv4
            &[0, 4, 0, 1, 9, 0][..],                          // unknown status
        ] {
            let mut r = wire;
            assert!(read_frame(&mut r).await.is_err(), "{wire:?}");
        }
    }

    #[test]
    fn reply_frames() {
        let src: TargetAddr = "[::1]:5353".parse().unwrap();
        let f = data_frame(3, Some(&src), b"ok");
        // meta: id 0 3 | keep | data | udp | port | atyp 3 | 16 bytes = 24
        assert_eq!(&f[..2], &24u16.to_be_bytes());
        assert_eq!(&f[2..7], &[0, 3, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        assert_eq!(&f[7..10], &[0x14, 0xe9, 3]);
        assert_eq!(&f[26..], &[0, 2, b'o', b'k']);
        assert_eq!(
            data_frame(1, None, b"x"),
            vec![0, 4, 0, 1, STATUS_KEEP, OPTION_DATA, 0, 1, b'x']
        );
        assert_eq!(end_frame(258), vec![0, 4, 1, 2, STATUS_END, 0]);
    }
}
