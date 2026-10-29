//! The REALITY server against our own REALITY client, and what everyone else sees:
//! the site it impersonates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use unbihex_engine::config::{RealityConfig, TlsConfig};
use unbihex_engine::outbound::fragment::FragmentConfig;
use unbihex_engine::outbound::reality::RealityClient;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::tls_stream::TlsRecordStream;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};
use unbihex_engine::{Config, Instance};

const PLAIN_USER: &str = "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6";
const VISION_USER: &str = "0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9";
const SITE: &str = "reality.test";
const SHORT_ID: &str = "0123abcd";

/// The impersonated site: a TLS echo server for `reality.test`; anything that is not
/// TLS gets an HTTP 400.
struct Site {
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    visits: Arc<AtomicUsize>,
}

async fn site() -> Site {
    let ck = rcgen::generate_simple_self_signed(vec![SITE.into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key)
    .unwrap();
    // Several handshake records, like a real site's certificate chain.
    let mut cfg = cfg;
    cfg.max_fragment_size = Some(200);
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let visits = Arc::new(AtomicUsize::new(0));
    let v = visits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            v.fetch_add(1, Ordering::SeqCst);
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if s.peek(&mut first).await.unwrap_or(0) == 0 {
                    return;
                }
                if first[0] != 0x16 {
                    // Read the request first: closing with unread data resets the connection.
                    let mut s = s;
                    let mut req = [0u8; 1024];
                    let _ = s.read(&mut req).await;
                    let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    let _ = s.shutdown().await;
                    return;
                }
                let Ok(tls) = TlsRecordStream::accept(s, cfg).await else {
                    return;
                };
                let (mut r, mut w) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Site { addr, cert, visits }
}

struct Server {
    instance: Instance,
    addr: SocketAddr,
    public_key: String,
    site: Site,
}

async fn server() -> Server {
    init_tracing();
    let site = site().await;
    let mut private = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut private);
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let (instance, port) = start_on_free_port(|port| {
        let json = serde_json::json!({
            "inbounds": [{
                "type": "vless", "tag": "vless-in", "listen": format!("127.0.0.1:{port}"),
                "users": [
                    {"id": PLAIN_USER, "email": "plain@test"},
                    {"id": VISION_USER, "email": "vision@test", "flow": "xtls-rprx-vision"}
                ],
                "reality": {
                    "dest": site.addr.to_string(),
                    "server_names": [SITE],
                    "private_key": URL_SAFE_NO_PAD.encode(private),
                    "short_ids": ["", SHORT_ID],
                    "max_time_diff_ms": 60_000
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        });
        Config::from_json(&json.to_string()).unwrap()
    })
    .await;
    Server {
        instance,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        site,
    }
}

fn client(s: &Server, user: &str, short_id: &str, fingerprint: Option<&str>) -> VlessOutbound {
    client_at(s, s.addr, user, short_id, fingerprint)
}

fn client_at(
    s: &Server,
    addr: SocketAddr,
    user: &str,
    short_id: &str,
    fingerprint: Option<&str>,
) -> VlessOutbound {
    let reality = RealityClient::new(&RealityConfig {
        server_name: SITE.into(),
        public_key: s.public_key.clone(),
        short_id: short_id.into(),
        alpn: vec![],
        fingerprint: fingerprint.map(String::from),
    })
    .unwrap();
    VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(user).unwrap().as_bytes(),
        ServerEndpoint {
            host: SITE.into(),
            port: addr.port(),
            addrs: vec![addr],
        },
        None,
        Default::default(),
    )
    .with_reality(Some(reality))
    .with_vision(user == VISION_USER)
}

fn session(network: Network, target: SocketAddr) -> Session {
    Session {
        network,
        source: None,
        target: target.into(),
        inbound_tag: "t".into(),
        sniffed: None,
    }
}

async fn echo_through(ob: &VlessOutbound, echo: SocketAddr, size: usize) {
    let s = ob.connect_tcp(&session(Network::Tcp, echo)).await.unwrap();
    let (mut r, mut w) = tokio::io::split(s);
    let data: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.flush().await.unwrap();
        w
    });
    let mut got = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .unwrap();
    assert!(got == data, "echoed bytes differ");
    drop(writer.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_with_vision_and_chrome_hello() {
    let s = server().await;
    let echo = tcp_echo().await;
    let ob = client(&s, VISION_USER, SHORT_ID, Some("chrome"));
    echo_through(&ob, echo, 5).await;
    echo_through(&ob, echo, 1 << 20).await;
    // UDP of a Vision user: XUDP over REALITY.
    let udp = udp_echo().await;
    let flow = ob.connect_udp(&session(Network::Udp, udp)).await.unwrap();
    flow.send(b"over xudp").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), flow.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"over xudp");
    // The server asks the site once per handshake (to copy its record sizes), as Xray.
    assert_eq!(
        s.site.visits.load(Ordering::SeqCst),
        3,
        "the site saw more than one probe per handshake"
    );
    s.instance.shutdown().await;
}

/// What a passive observer between client and server sees.
#[derive(Default)]
struct Wire {
    /// The client's first bytes (its ClientHello).
    hello: Vec<u8>,
    /// (type, length) of each record the server sent.
    records: Vec<(u8, usize)>,
}

/// A relay to `to` for one connection that records the [`Wire`].
async fn observer(to: SocketAddr) -> (SocketAddr, Arc<Mutex<Wire>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let wire = Arc::new(Mutex::new(Wire::default()));
    let w = wire.clone();
    tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let s = TcpStream::connect(to).await.unwrap();
        let (mut cr, mut cw) = c.into_split();
        let (mut sr, mut sw) = s.into_split();
        let up = w.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 16384];
            while let Ok(n @ 1..) = cr.read(&mut buf).await {
                {
                    let mut wire = up.lock().unwrap();
                    if wire.records.is_empty() {
                        wire.hello.extend_from_slice(&buf[..n]);
                    }
                }
                if sw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let (mut buf, mut pos, mut chunk) = (Vec::new(), 0, [0u8; 16384]);
        while let Ok(n @ 1..) = sr.read(&mut chunk).await {
            buf.extend_from_slice(&chunk[..n]);
            while let Some(h) = buf.get(pos..pos + 5) {
                let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
                if buf.len() < pos + 5 + len {
                    break;
                }
                w.lock().unwrap().records.push((h[0], len));
                pos += 5 + len;
            }
            if cw.write_all(&chunk[..n]).await.is_err() {
                break;
            }
        }
    });
    (addr, wire)
}

/// The site's first flight to `hello`: (type, length) of its records.
async fn site_answer(site: SocketAddr, hello: &[u8]) -> Vec<(u8, usize)> {
    let mut s = TcpStream::connect(site).await.unwrap();
    s.write_all(hello).await.unwrap();
    let (mut buf, mut out, mut pos) = (Vec::new(), Vec::new(), 0);
    while let Ok(Ok(n @ 1..)) =
        tokio::time::timeout(Duration::from_millis(500), s.read_buf(&mut buf)).await
    {
        let _ = n;
        while let Some(h) = buf.get(pos..pos + 5) {
            let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
            if buf.len() < pos + 5 + len {
                break;
            }
            out.push((h[0], len));
            pos += 5 + len;
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_records_look_like_the_site() {
    let s = server().await;
    let echo = tcp_echo().await;
    let (relay, wire) = observer(s.addr).await;
    echo_through(
        &client_at(&s, relay, PLAIN_USER, SHORT_ID, Some("chrome")),
        echo,
        5,
    )
    .await;
    let (hello, ours) = {
        let w = wire.lock().unwrap();
        (w.hello.clone(), w.records.clone())
    };
    let site = site_answer(s.site.addr, &hello).await;
    assert!(site.len() >= 3, "site answered {site:?}");
    // ServerHello, ChangeCipherSpec and every encrypted handshake record match. The
    // site signs with ECDSA, whose DER length varies by a byte or two per connection.
    let close = site
        .iter()
        .zip(&ours)
        .all(|(&(t, a), &(u, b))| t == u && a.abs_diff(b) <= 2);
    assert!(close, "site {site:?}, ours {ours:?}");
    assert!(
        site.len() > 3,
        "the site sent one handshake record: {site:?}"
    );
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_plain_user_rustls_hello_and_empty_short_id() {
    let s = server().await;
    let echo = tcp_echo().await;
    echo_through(&client(&s, PLAIN_USER, "", None), echo, 1 << 16).await;
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_reassembles_a_fragmented_hello() {
    let s = server().await;
    let echo = tcp_echo().await;
    let fragment = FragmentConfig {
        length: "50-90".into(),
        interval: "1-3".into(),
    };
    let ob = client(&s, PLAIN_USER, SHORT_ID, Some("chrome")).with_fragment(Some(fragment));
    echo_through(&ob, echo, 1000).await;
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strangers_get_the_real_site() {
    let s = server().await;
    let echo = tcp_echo().await;

    // A browser: a full TLS session with the site, through our port.
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some(SITE.into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: Some("chrome".into()),
    };
    let tls = TlsClient::with_extra_roots(&tls_cfg, SITE, vec![s.site.cert.clone()]).unwrap();
    let mut browser = tls
        .connect(TcpStream::connect(s.addr).await.unwrap())
        .await
        .unwrap();
    browser.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    browser.flush().await.unwrap();
    let mut got = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(10), browser.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"GET / HTTP/1.1\r\n\r\n");

    // Plain HTTP: the site's own answer.
    let mut probe = TcpStream::connect(s.addr).await.unwrap();
    probe
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), probe.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert!(answer.starts_with(b"HTTP/1.1 400"), "{answer:?}");

    // Our client with a short ID the server does not know reaches the site and
    // refuses its certificate.
    let r = client(&s, PLAIN_USER, "ffff", Some("chrome"))
        .connect_tcp(&session(Network::Tcp, echo))
        .await;
    assert!(r.is_err(), "a wrong short ID got through");
    assert_eq!(s.site.visits.load(Ordering::SeqCst), 3);
    s.instance.shutdown().await;
}
