//! Load generator for the Unbihex engine.
//!
//!   ubench serve IP BASE               BASE: source (download), BASE+1: sink (upload), BASE+2: echo
//!   ubench tput  VIA TARGET down|up STREAMS SECS
//!   ubench conns VIA TARGET COUNT HOLD_SECS
//!   ubench rate  VIA TARGET CONC SECS
//!
//! VIA is `direct` or a SOCKS5 address. Results are printed as one JSON line.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const BUF: usize = 64 * 1024;
const MSG: usize = 64;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        match args.first().map(String::as_str) {
            Some("serve") => serve(args[1].parse().unwrap(), args[2].parse().unwrap()).await,
            Some("tput") => {
                tput(&args[1], args[2].parse().unwrap(), &args[3], args[4].parse().unwrap(), args[5].parse().unwrap()).await
            }
            Some("conns") => conns(&args[1], args[2].parse().unwrap(), args[3].parse().unwrap(), args[4].parse().unwrap()).await,
            Some("rate") => rate(&args[1], args[2].parse().unwrap(), args[3].parse().unwrap(), args[4].parse().unwrap()).await,
            _ => eprintln!("usage: see source"),
        }
    });
}

async fn serve(ip: std::net::IpAddr, base: u16) {
    let source = TcpListener::bind((ip, base)).await.unwrap();
    let sink = TcpListener::bind((ip, base + 1)).await.unwrap();
    let echo = TcpListener::bind((ip, base + 2)).await.unwrap();
    eprintln!("serving on {ip}:{base}..{}", base + 2);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = source.accept().await else { continue };
            tokio::spawn(async move {
                let buf = vec![0x5au8; BUF];
                while s.write_all(&buf).await.is_ok() {}
            });
        }
    });
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = sink.accept().await else { continue };
            tokio::spawn(async move {
                let mut buf = vec![0u8; BUF];
                while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    loop {
        let Ok((mut s, _)) = echo.accept().await else { continue };
        tokio::spawn(async move {
            let mut buf = [0u8; MSG];
            while s.read_exact(&mut buf).await.is_ok() {
                if s.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Opens a TCP stream to `target`, through SOCKS5 unless `via` is "direct".
async fn open(via: &str, target: SocketAddr) -> std::io::Result<TcpStream> {
    if via == "direct" {
        let s = TcpStream::connect(target).await?;
        s.set_nodelay(true)?;
        return Ok(s);
    }
    let mut s = TcpStream::connect(via).await?;
    s.set_nodelay(true)?;
    s.write_all(&[5, 1, 0]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r != [5, 0] {
        return Err(std::io::Error::other("socks auth"));
    }
    let SocketAddr::V4(t) = target else {
        return Err(std::io::Error::other("ipv4 only"));
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&t.ip().octets());
    req.extend_from_slice(&t.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", head[1])));
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            usize::from(l[0]) + 2
        }
        _ => return Err(std::io::Error::other("socks atyp")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

/// One request/response of MSG bytes; returns its round-trip time.
async fn ping(s: &mut TcpStream) -> std::io::Result<Duration> {
    let msg = [0x42u8; MSG];
    let mut back = [0u8; MSG];
    let t = Instant::now();
    s.write_all(&msg).await?;
    s.read_exact(&mut back).await?;
    Ok(t.elapsed())
}

async fn tput(via: &str, target: SocketAddr, dir: &str, streams: usize, secs: f64) {
    let bytes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    let down = dir == "down";
    for _ in 0..streams {
        let (via, bytes, errors) = (via.to_string(), bytes.clone(), errors.clone());
        tasks.push(tokio::spawn(async move {
            let Ok(mut s) = open(&via, target).await else {
                errors.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let mut buf = vec![0x33u8; BUF];
            loop {
                let n = if down {
                    match s.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    }
                } else {
                    match s.write(&buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    }
                };
                bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
        }));
    }
    // Warm-up second, then the measured window.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (b0, t0) = (bytes.load(Ordering::Relaxed), Instant::now());
    tokio::time::sleep(Duration::from_secs_f64(secs)).await;
    let (b1, dt) = (bytes.load(Ordering::Relaxed), t0.elapsed().as_secs_f64());
    for t in &tasks {
        t.abort();
    }
    let gbps = (b1 - b0) as f64 * 8.0 / dt / 1e9;
    println!(
        r#"{{"test":"tput","dir":"{dir}","streams":{streams},"gbit_s":{gbps:.3},"mbyte_s":{:.1},"errors":{}}}"#,
        (b1 - b0) as f64 / dt / 1e6,
        errors.load(Ordering::Relaxed)
    );
}

fn pct(v: &mut [Duration], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i].as_secs_f64() * 1000.0
}

async fn conns(via: &str, target: SocketAddr, count: usize, hold: f64) {
    // At most this many handshakes in flight while ramping up.
    let gate = Arc::new(Semaphore::new(256));
    let t0 = Instant::now();
    let mut tasks = Vec::with_capacity(count);
    for _ in 0..count {
        let (via, gate) = (via.to_string(), gate.clone());
        tasks.push(tokio::spawn(async move {
            let permit = gate.acquire_owned().await.unwrap();
            let t = Instant::now();
            let r = tokio::time::timeout(Duration::from_secs(20), async {
                let mut s = open(&via, target).await?;
                ping(&mut s).await?;
                Ok::<_, std::io::Error>(s)
            })
            .await;
            drop(permit);
            match r {
                Ok(Ok(s)) => Ok((s, t.elapsed())),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("timeout".into()),
            }
        }));
    }
    let mut open_streams = Vec::new();
    let mut setup = Vec::new();
    let mut errors = std::collections::BTreeMap::<String, usize>::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok((s, d)) => {
                open_streams.push(s);
                setup.push(d);
            }
            Err(e) => *errors.entry(e).or_default() += 1,
        }
    }
    let ramp = t0.elapsed().as_secs_f64();
    eprintln!("READY {} open", open_streams.len());
    tokio::time::sleep(Duration::from_secs_f64(hold)).await;
    // Every held stream still answers?
    let mut alive = 0;
    let mut rtt = Vec::new();
    for s in open_streams.iter_mut() {
        if let Ok(Ok(d)) = tokio::time::timeout(Duration::from_secs(5), ping(s)).await {
            alive += 1;
            rtt.push(d);
        }
    }
    let ok = setup.len();
    let errs: Vec<String> = errors.iter().map(|(k, v)| format!("\"{}\":{v}", k.replace('"', "'"))).collect();
    println!(
        r#"{{"test":"conns","count":{count},"opened":{ok},"alive_after_hold":{alive},"ramp_s":{ramp:.2},"setup_p50_ms":{:.1},"setup_p99_ms":{:.1},"ping_p50_ms":{:.2},"ping_p99_ms":{:.2},"errors":{{{}}}}}"#,
        pct(&mut setup, 0.5),
        pct(&mut setup, 0.99),
        pct(&mut rtt, 0.5),
        pct(&mut rtt, 0.99),
        errs.join(",")
    );
}

async fn rate(via: &str, target: SocketAddr, conc: usize, secs: f64) {
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let mut tasks = Vec::new();
    for _ in 0..conc {
        let via = via.to_string();
        tasks.push(tokio::spawn(async move {
            let (mut lat, mut errs) = (Vec::new(), 0u64);
            while Instant::now() < deadline {
                let t = Instant::now();
                let r = tokio::time::timeout(Duration::from_secs(10), async {
                    let mut s = open(&via, target).await?;
                    ping(&mut s).await?;
                    // Reset instead of FIN: no TIME_WAIT pile-up on our side.
                    let _ = s.set_linger(Some(Duration::ZERO));
                    Ok::<_, std::io::Error>(())
                })
                .await;
                match r {
                    Ok(Ok(())) => lat.push(t.elapsed()),
                    _ => errs += 1,
                }
            }
            (lat, errs)
        }));
    }
    let t0 = Instant::now();
    let (mut lat, mut errs) = (Vec::new(), 0);
    for t in tasks {
        let (l, e) = t.await.unwrap();
        lat.extend(l);
        errs += e;
    }
    let dt = t0.elapsed().as_secs_f64().max(secs);
    let n = lat.len();
    println!(
        r#"{{"test":"rate","conc":{conc},"conns":{n},"conn_per_s":{:.0},"lat_p50_ms":{:.1},"lat_p99_ms":{:.1},"errors":{errs}}}"#,
        n as f64 / dt,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99)
    );
}
