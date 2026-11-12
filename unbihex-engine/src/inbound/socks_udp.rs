//! SOCKS5 UDP ASSOCIATE (RFC 1928 §7, SPEC §10.1): a UDP socket per association on
//! the inbound's address, datagrams with the SOCKS header from the client's IP only,
//! one flow per destination through the dispatcher (rules, fake IP, QUIC sniffing),
//! for as long as the TCP connection that asked for it stays open.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::address::{TargetAddr, parse_socks_addr, write_socks_addr};
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::outbound::PacketStream;
use crate::session::{Network, Session};

/// The most destinations one association keeps open at once.
const MAX_FLOWS: usize = 512;

/// Datagrams queued for one destination before more are dropped.
const QUEUE: usize = 64;

/// A UDP association accepted by the handshake, not yet running.
pub struct Association {
    socket: Arc<UdpSocket>,
    /// The address the client said it will send from (`DST.ADDR`/`DST.PORT` of the
    /// request); a zero port or address means "not known yet".
    hint: SocketAddr,
}

impl Association {
    /// Binds the association's socket on `ip` (the address the client reached the
    /// inbound at); `hint` is the request's address.
    pub async fn bind(ip: IpAddr, hint: SocketAddr) -> Result<Association> {
        let socket = UdpSocket::bind(SocketAddr::new(ip.to_canonical(), 0)).await?;
        Ok(Association {
            socket: Arc::new(socket),
            hint,
        })
    }

    /// The `BND.ADDR`/`BND.PORT` reply for the client.
    pub fn reply(&self) -> Result<Vec<u8>> {
        let mut r = vec![0x05, 0x00, 0x00];
        write_socks_addr(&TargetAddr::from(self.socket.local_addr()?), &mut r)?;
        Ok(r)
    }
}

/// The destinations of an association and where their datagrams go.
type Flows = parking_lot::Mutex<HashMap<TargetAddr, mpsc::Sender<Vec<u8>>>>;

/// Relays the association until the control connection closes; all its flows end
/// with it.
pub async fn run(
    mut control: TcpStream,
    a: Association,
    peer: SocketAddr,
    tag: String,
    sniff: bool,
    d: Arc<Dispatcher>,
) {
    let local = match a.socket.local_addr() {
        Ok(l) => l,
        Err(_) => return,
    };
    let client = Arc::new(parking_lot::Mutex::new(None::<SocketAddr>));
    let flows: Arc<Flows> = Arc::default();
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; 65_535];
    let mut ctl = [0u8; 256];
    loop {
        tokio::select! {
            // Anything but EOF on the control connection is ignored.
            r = control.read(&mut ctl) => match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            r = a.socket.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                if !from_client(from, peer, a.hint) {
                    tracing::debug!("{tag} udp: datagram from {from} dropped (not the client {peer})");
                    continue;
                }
                let Some((target, payload)) = parse(&buf[..n]) else { continue };
                if is_self(&target, local) {
                    continue;
                }
                *client.lock() = Some(from);
                let tx = flows.lock().get(&target).cloned();
                if let Some(tx) = tx {
                    match tx.try_send(payload.to_vec()) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                }
                if flows.lock().len() >= MAX_FLOWS {
                    continue;
                }
                let (tx, rx) = mpsc::channel(QUEUE);
                let _ = tx.try_send(payload.to_vec());
                flows.lock().insert(target.clone(), tx.clone());
                let flow = SocksFlow {
                    rx: tokio::sync::Mutex::new(rx),
                    socket: a.socket.clone(),
                    client: client.clone(),
                    header: header(&target),
                };
                let sess = Session {
                    network: Network::Udp,
                    source: Some(from),
                    target: target.clone(),
                    inbound_tag: tag.clone(),
                    sniffed: None,
                };
                let (d, flows) = (d.clone(), flows.clone());
                tasks.spawn(async move {
                    if sniff {
                        d.dispatch_udp_sniffing(sess, Box::new(flow)).await;
                    } else {
                        d.dispatch_udp(sess, Box::new(flow)).await;
                    }
                    // Idle or failed: the next datagram opens a new flow.
                    let mut f = flows.lock();
                    if f.get(&target).is_some_and(|t| t.same_channel(&tx)) {
                        f.remove(&target);
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    // Dropping the set aborts the flows still running.
    tasks.abort_all();
}

/// Whether a datagram from `from` belongs to the client at `peer` (same IP, and the
/// port it announced, if any).
fn from_client(from: SocketAddr, peer: SocketAddr, hint: SocketAddr) -> bool {
    from.ip().to_canonical() == peer.ip().to_canonical()
        && (hint.port() == 0 || hint.port() == from.port())
}

/// `RSV RSV FRAG ATYP ADDR PORT DATA`; fragments are not supported and dropped.
fn parse(d: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if d.len() < 4 || d[2] != 0 {
        return None;
    }
    let (target, used) = parse_socks_addr(&d[3..]).ok()?;
    Some((target, &d[3 + used..]))
}

/// The SOCKS header of replies from `target`.
fn header(target: &TargetAddr) -> Vec<u8> {
    let mut h = vec![0, 0, 0];
    // A domain from the client fits: it was parsed from the same encoding.
    let _ = write_socks_addr(target, &mut h);
    h
}

/// A destination that is the association's own socket would loop.
fn is_self(target: &TargetAddr, local: SocketAddr) -> bool {
    let Some(ip) = target.addr.as_ip() else {
        return false;
    };
    let ip = ip.to_canonical();
    target.port == local.port()
        && (ip == local.ip().to_canonical() || ip.is_loopback() || ip.is_unspecified())
}

/// One destination of an association, as the dispatcher sees it.
struct SocksFlow {
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    socket: Arc<UdpSocket>,
    client: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
    header: Vec<u8>,
}

#[async_trait::async_trait]
impl PacketStream for SocksFlow {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        let Some(client) = *self.client.lock() else {
            return Ok(());
        };
        let mut d = Vec::with_capacity(self.header.len() + payload.len());
        d.extend_from_slice(&self.header);
        d.extend_from_slice(payload);
        self.socket.send_to(&d, client).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match self.rx.lock().await.recv().await {
            Some(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            None => Err(Error::protocol("socks udp association closed")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// An outbound that answers every UDP datagram with itself.
    struct EchoOut;

    struct EchoFlow(
        tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        mpsc::Sender<Vec<u8>>,
    );

    #[async_trait::async_trait]
    impl PacketStream for EchoFlow {
        async fn send(&self, payload: &[u8]) -> Result<()> {
            let _ = self.1.try_send(payload.to_vec());
            Ok(())
        }
        async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            let d = self.0.lock().await.recv().await.ok_or(Error::Timeout)?;
            buf[..d.len()].copy_from_slice(&d);
            Ok(d.len())
        }
    }

    #[async_trait::async_trait]
    impl crate::outbound::Outbound for EchoOut {
        fn tag(&self) -> &str {
            "named"
        }
        async fn connect_tcp(&self, _: &Session) -> Result<crate::outbound::BoxStream> {
            Err(Error::Timeout)
        }
        async fn connect_udp(&self, _: &Session) -> Result<Box<dyn PacketStream>> {
            let (tx, rx) = mpsc::channel(16);
            Ok(Box::new(EchoFlow(tokio::sync::Mutex::new(rx), tx)))
        }
    }

    /// A QUIC Initial to a bare IP on 443 through the association takes the domain
    /// rule of its SNI; another name falls to `final` (block). Closing the control
    /// connection ends the association and its flows.
    #[tokio::test]
    async fn quic_through_an_association_takes_the_domain_rule() {
        use crate::sniff::quic::tests::{crypto, initial_packet, quic_client_hello};
        use rustls::quic::Version;

        let cfg = crate::config::Config::from_json(
            r#"{"outbounds":[{"type":"direct","tag":"named"},{"type":"block","tag":"block"}],
               "route":{"rules":[{"domain_suffix":["blocked.example"],"outbound":"named"}],
                        "final":"block"}}"#,
        )
        .unwrap();
        let block: Arc<dyn crate::outbound::Outbound> =
            Arc::new(crate::outbound::block::BlockOutbound::new("block"));
        let d = Arc::new(Dispatcher::new(
            crate::router::Router::new(&cfg).unwrap(),
            vec![Arc::new(EchoOut), block],
            cfg.limits.clone(),
            None,
            Arc::default(),
        ));
        let target: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let datagrams = |name: &str| {
            let hello = quic_client_hello(Version::V1, name, 1300);
            let half = hello.len() / 2;
            [
                initial_packet(Version::V1, &[5; 8], 0, &crypto(0, &hello[..half]), 1200),
                initial_packet(Version::V1, &[5; 8], 1, &crypto(half, &hello[half..]), 1200),
            ]
        };
        for (name, answered) in [("www.blocked.example", true), ("other.example", false)] {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client_tcp = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
            let (control, peer) = l.accept().await.unwrap();
            let assoc =
                Association::bind("127.0.0.1".parse().unwrap(), "0.0.0.0:0".parse().unwrap())
                    .await
                    .unwrap();
            let relay = assoc.socket.local_addr().unwrap();
            let run = tokio::spawn(run(
                control,
                assoc,
                peer,
                "socks-in".into(),
                true,
                d.clone(),
            ));
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for p in datagrams(name) {
                let mut m = header(&target.into());
                m.extend_from_slice(&p);
                c.send_to(&m, relay).await.unwrap();
            }
            let mut buf = vec![0u8; 4096];
            let got =
                tokio::time::timeout(std::time::Duration::from_secs(1), c.recv(&mut buf)).await;
            assert_eq!(got.is_ok(), answered, "{name}");
            if answered {
                let n = got.unwrap().unwrap();
                let (from, used) = parse_socks_addr(&buf[3..n]).unwrap();
                assert_eq!(from, target.into());
                assert_eq!(buf[3 + used..n].len(), 1200, "the first Initial comes back");
            }
            drop(client_tcp);
            tokio::time::timeout(std::time::Duration::from_secs(2), run)
                .await
                .expect("the association ends with its control connection")
                .unwrap();
        }
    }

    #[test]
    fn header_parsing() {
        let mut d = vec![0, 0, 0];
        write_socks_addr(&"1.2.3.4:53".parse().unwrap(), &mut d).unwrap();
        d.extend_from_slice(b"q");
        let (t, p) = parse(&d).unwrap();
        assert_eq!((t.to_string().as_str(), p), ("1.2.3.4:53", &b"q"[..]));
        d[2] = 1; // a fragment
        assert!(parse(&d).is_none());
        assert!(parse(&[0, 0, 0]).is_none());
        assert!(parse(&[0, 0, 0, 9, 1, 2]).is_none());
    }

    #[test]
    fn only_the_client_and_not_ourselves() {
        let peer: SocketAddr = "192.168.1.5:40000".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(from_client("192.168.1.5:5353".parse().unwrap(), peer, any));
        assert!(from_client(
            "[::ffff:192.168.1.5]:5353".parse().unwrap(),
            peer,
            any
        ));
        assert!(!from_client("192.168.1.6:5353".parse().unwrap(), peer, any));
        let hint: SocketAddr = "0.0.0.0:6000".parse().unwrap();
        assert!(from_client("192.168.1.5:6000".parse().unwrap(), peer, hint));
        assert!(!from_client(
            "192.168.1.5:6001".parse().unwrap(),
            peer,
            hint
        ));
        let local: SocketAddr = "192.168.1.1:7000".parse().unwrap();
        for t in ["192.168.1.1:7000", "127.0.0.1:7000", "0.0.0.0:7000"] {
            assert!(is_self(&t.parse().unwrap(), local), "{t}");
        }
        assert!(!is_self(&"192.168.1.1:7001".parse().unwrap(), local));
        assert!(!is_self(&"8.8.8.8:7000".parse().unwrap(), local));
    }
}
