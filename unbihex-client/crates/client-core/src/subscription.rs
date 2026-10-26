//! Downloading and parsing subscriptions.
//!
//! A subscription is an HTTP(S) URL that returns share links, one per line,
//! usually base64-encoded as a whole. Panels (Marzban, Remnawave, 3x-ui, …) add
//! headers with the title, traffic quota and update interval.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use url::{Host, Url};

use crate::error::{ClientError, Result};
use crate::links::{b64_decode, is_share_link};
use crate::model::SubscriptionInfo;

/// What a subscription returned.
#[derive(Clone, Debug, Default)]
pub struct Fetched {
    /// Share links in the order the panel sent them.
    pub links: Vec<String>,
    /// `profile-title`.
    pub title: Option<String>,
    /// `subscription-userinfo`.
    pub info: Option<SubscriptionInfo>,
    /// `profile-update-interval`, hours.
    pub update_interval_hours: Option<u32>,
    /// `support-url`.
    pub support_url: Option<String>,
    /// `profile-web-page-url`.
    pub web_page_url: Option<String>,
}

/// Request options.
#[derive(Clone, Debug)]
pub struct FetchOptions {
    /// User-Agent header.
    pub user_agent: String,
    /// `x-hwid` value, when device headers are enabled.
    pub hwid: Option<String>,
}

/// Name of the OS for `x-device-os`.
pub fn device_os() -> &'static str {
    if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    }
}

/// Largest subscription body, after decompression.
const MAX_BODY: usize = 8 << 20;

/// Most redirects followed for one request.
const MAX_REDIRECTS: usize = 5;

const INSECURE_HTTP: &str =
    "подписка по http:// небезопасна: подделав ответ, можно подменить серверы; используйте https://";

/// Whether `url` may be fetched: https anywhere, plain http only from this
/// computer or the local network, where nobody on the way can forge the answer.
pub(crate) fn is_safe_url(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(ip)) => is_local_ip(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => is_local_ip(IpAddr::V6(ip)),
            None => false,
        },
        _ => false,
    }
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// A redirect policy that never leaves https for a public http address.
pub(crate) fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("слишком много перенаправлений")
        } else if !is_safe_url(attempt.url()) {
            let msg = format!("перенаправление на {} отклонено: {INSECURE_HTTP}", attempt.url());
            attempt.error(msg)
        } else {
            attempt.follow()
        }
    })
}

/// Why a size-limited read failed.
pub(crate) enum BodyError {
    /// The body is larger than allowed.
    TooLarge,
    /// The connection failed.
    Read(reqwest::Error),
}

/// Reads the whole body, stopping as soon as it exceeds `max` bytes.
pub(crate) async fn read_limited(
    mut resp: reqwest::Response,
    max: usize,
) -> std::result::Result<Vec<u8>, BodyError> {
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(BodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(BodyError::Read)? {
        if body.len() + chunk.len() > max {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The message of a request error, with the reason a redirect was refused.
pub(crate) fn request_error(e: &reqwest::Error) -> String {
    if e.is_redirect()
        && let Some(why) = std::error::Error::source(e)
    {
        return why.to_string();
    }
    e.to_string()
}

/// Downloads and parses a subscription.
pub async fn fetch(url: &str, opts: &FetchOptions) -> Result<Fetched> {
    let parsed = Url::parse(url.trim())
        .map_err(|_| ClientError::Subscription("неверный адрес подписки".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ClientError::Subscription(
            "адрес подписки должен начинаться с https://".into(),
        ));
    }
    if !is_safe_url(&parsed) {
        return Err(ClientError::Subscription(INSECURE_HTTP.into()));
    }
    let client = reqwest::Client::builder()
        // HTTP(S)_PROXY or system proxies may point at our own or a dead local port; TUN captures us when connected.
        .no_proxy()
        .user_agent(opts.user_agent.clone())
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(10))
        .redirect(redirect_policy())
        .build()
        .map_err(|e| ClientError::Subscription(e.to_string()))?;
    let mut req = client.get(parsed).header("Accept", "*/*");
    if let Some(hwid) = &opts.hwid {
        req = req
            .header("x-hwid", hwid)
            .header("x-device-os", device_os())
            .header("x-device-model", "Unbihex")
            .header("x-app-version", env!("CARGO_PKG_VERSION"));
    }
    let resp = req.send().await.map_err(|e| {
        let msg = if e.is_timeout() {
            "сервер подписки не ответил вовремя".to_string()
        } else if e.is_connect() {
            "не удалось подключиться к серверу подписки".to_string()
        } else {
            request_error(&e)
        };
        ClientError::Subscription(msg)
    })?;
    let status = resp.status();
    if !status.is_success() {
        let hint = match status.as_u16() {
            401 | 403 => " (доступ запрещён: проверьте ссылку или лимит устройств)",
            404 => " (подписка не найдена)",
            _ => "",
        };
        return Err(ClientError::Subscription(format!("HTTP {status}{hint}")));
    }
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let mut out = Fetched {
        title: header("profile-title").map(|t| decode_title(&t)),
        info: header("subscription-userinfo").and_then(|h| parse_userinfo(&h)),
        update_interval_hours: header("profile-update-interval").and_then(|h| h.parse().ok()),
        support_url: header("support-url"),
        web_page_url: header("profile-web-page-url"),
        links: Vec::new(),
    };
    if out.title.is_none() {
        out.title = header("content-disposition").and_then(|h| filename_of(&h));
    }
    let body = read_limited(resp, MAX_BODY).await.map_err(|e| {
        ClientError::Subscription(match e {
            BodyError::TooLarge => "ответ подписки больше 8 МБ".into(),
            BodyError::Read(e) => format!("ошибка чтения ответа: {e}"),
        })
    })?;
    out.links = parse_body(&String::from_utf8_lossy(&body))?;
    Ok(out)
}

/// Extracts share links from a subscription body (plain or base64).
pub fn parse_body(body: &str) -> Result<Vec<String>> {
    let body = body.trim_start_matches('\u{feff}').trim();
    if body.is_empty() {
        return Err(ClientError::Subscription("подписка пустая".into()));
    }
    if (body.starts_with('{') || body.starts_with('['))
        && let Some(links) = crate::jsonsub::links_from_json(body)
        && !links.is_empty()
    {
        return Ok(links);
    }
    let links = links_in(body);
    if !links.is_empty() {
        return Ok(links);
    }
    if let Some(decoded) = b64_decode(body).and_then(|b| String::from_utf8(b).ok()) {
        let links = links_in(&decoded);
        if !links.is_empty() {
            return Ok(links);
        }
    }
    let kind = if body.starts_with('{') || body.starts_with('[') {
        Some("JSON без поддерживаемых серверов")
    } else if body.contains("proxies:") {
        Some("Clash YAML")
    } else if body.starts_with('<') {
        Some("HTML-страницу")
    } else {
        None
    };
    Err(ClientError::Subscription(match kind {
        Some(k) => format!(
            "сервер вернул {k}, а не список ссылок; укажите другой User-Agent для подписки"
        ),
        None => "в ответе нет ссылок на серверы".into(),
    }))
}

fn links_in(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| is_share_link(l))
        .map(String::from)
        .collect()
}

/// `upload=1; download=2; total=3; expire=4`.
pub fn parse_userinfo(h: &str) -> Option<SubscriptionInfo> {
    let mut info = SubscriptionInfo::default();
    let mut any = false;
    for part in h.split(';') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        // Some panels send floats or empty values.
        let v = v.trim();
        let n = v
            .parse::<u64>()
            .ok()
            .or_else(|| v.parse::<f64>().ok().map(|f| f.max(0.0) as u64));
        let Some(n) = n else { continue };
        any = true;
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = n,
            "download" => info.download = n,
            "total" => info.total = n,
            "expire" => info.expire = (n > 0).then_some(n),
            _ => {}
        }
    }
    any.then_some(info)
}

/// `profile-title` may be `base64:<b64>`.
fn decode_title(t: &str) -> String {
    if let Some(b) = t.strip_prefix("base64:")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b.trim())
        && let Ok(s) = String::from_utf8(bytes)
    {
        return s;
    }
    t.to_string()
}

fn filename_of(h: &str) -> Option<String> {
    let (_, rest) = h.split_once("filename=")?;
    let name = rest.split(';').next()?.trim().trim_matches('"');
    (!name.is_empty()).then(|| name.to_string())
}

/// A name for a subscription without `profile-title`: its host.
pub fn fallback_name(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| "Подписка".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn base64_and_plain_bodies() {
        let plain = format!("vless://{UUID}@a.com:443?security=tls#A\r\n\r\nss://YWVzLTI1Ni1nY206cA@1.2.3.4:1#B\n# comment\n");
        assert_eq!(parse_body(&plain).unwrap().len(), 2);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
        // Panels often wrap base64 at 76 columns.
        let wrapped: String = b64
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned() + "\n")
            .collect();
        assert_eq!(parse_body(&wrapped).unwrap().len(), 2);
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&plain);
        assert_eq!(parse_body(&url_safe).unwrap().len(), 2);
    }

    #[test]
    fn other_formats_are_explained() {
        assert!(parse_body("{\"outbounds\":[]}").unwrap_err().to_string().contains("JSON"));
        let xray = r#"{"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"1.2.3.4","port":1080}]}}]}"#;
        assert_eq!(parse_body(xray).unwrap().len(), 1);
        assert!(parse_body("proxies:\n - name: a").unwrap_err().to_string().contains("Clash"));
        assert!(parse_body("").is_err());
    }

    #[test]
    fn headers() {
        let i = parse_userinfo("upload=100; download=2000; total=10737418240; expire=1767225600").unwrap();
        assert_eq!(i.total, 10737418240);
        assert_eq!(i.expire, Some(1767225600));
        let i = parse_userinfo("upload=0;download=5.0;total=0;expire=0").unwrap();
        assert_eq!((i.download, i.expire), (5, None));
        assert!(parse_userinfo("garbage").is_none());
        assert_eq!(decode_title("base64:0JzQvtC5IFZQTg=="), "Мой VPN");
        assert_eq!(decode_title("Plain"), "Plain");
        assert_eq!(filename_of("attachment; filename=\"My Sub\""), Some("My Sub".into()));
        assert_eq!(fallback_name("https://panel.example.com/sub/x"), "panel.example.com");
    }

    #[tokio::test]
    async fn fetch_from_local_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let body = base64::engine::general_purpose::STANDARD
            .encode(format!("vless://{UUID}@a.com:443?security=tls#A\n"));
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            assert!(req.contains("x-hwid: abc"), "{req}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nprofile-title: base64:0JzQvtC5IFZQTg==\r\nsubscription-userinfo: upload=1; download=2; total=3; expire=0\r\nprofile-update-interval: 6\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        });
        let f = fetch(
            &format!("http://127.0.0.1:{port}/sub"),
            &FetchOptions {
                user_agent: "test".into(),
                hwid: Some("abc".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(f.links.len(), 1);
        assert_eq!(f.title.as_deref(), Some("Мой VPN"));
        assert_eq!(f.update_interval_hours, Some(6));
        assert_eq!(f.info.unwrap().total, 3);
    }

    #[test]
    fn plain_http_only_to_local_addresses() {
        let safe = |u: &str| is_safe_url(&Url::parse(u).unwrap());
        for ok in [
            "https://example.com/sub",
            "https://8.8.8.8/sub",
            "http://127.0.0.1:2096/sub",
            "http://192.168.1.10/sub",
            "http://10.0.0.1/sub",
            "http://172.16.5.4/sub",
            "http://169.254.1.1/sub",
            "http://[::1]:8080/sub",
            "http://[fd00::1]/sub",
            "http://[fe80::1]/sub",
            "http://[::ffff:192.168.1.10]/sub",
            "http://localhost:8080/sub",
            "http://LOCALHOST/sub",
        ] {
            assert!(safe(ok), "{ok}");
        }
        for bad in [
            "http://example.com/sub",
            "http://8.8.8.8/sub",
            "http://172.32.0.1/sub",
            "http://[2001:db8::1]/sub",
            "http://[::ffff:8.8.8.8]/sub",
            "http://localhost.example.com/sub",
            "ftp://127.0.0.1/sub",
        ] {
            assert!(!safe(bad), "{bad}");
        }
    }

    fn opts() -> FetchOptions {
        FetchOptions {
            user_agent: "test".into(),
            hwid: None,
        }
    }

    /// Serves one canned response head, then `body_len` bytes of body.
    async fn serve_once(head: String, body_len: usize) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(head.as_bytes()).await;
            let chunk = vec![b'a'; 64 * 1024];
            let mut left = body_len;
            while left > 0 {
                let n = left.min(chunk.len());
                if s.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
        });
        port
    }

    #[tokio::test]
    async fn public_http_is_refused() {
        let e = fetch("http://example.com/sub", &opts()).await.unwrap_err();
        assert!(e.to_string().contains("небезопасна"), "{e}");
    }

    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_BODY + 1
        );
        let port = serve_once(head, 0).await;
        let e = fetch(&format!("http://127.0.0.1:{port}/sub"), &opts()).await.unwrap_err();
        assert!(e.to_string().contains("больше 8 МБ"), "{e}");

        // Without Content-Length the limit is enforced while reading.
        let head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string();
        let port = serve_once(head, MAX_BODY + 100).await;
        let e = fetch(&format!("http://127.0.0.1:{port}/sub"), &opts()).await.unwrap_err();
        assert!(e.to_string().contains("больше 8 МБ"), "{e}");
    }

    #[tokio::test]
    async fn redirect_to_public_http_is_refused() {
        let head = "HTTP/1.1 302 Found\r\nLocation: http://example.com/sub\r\n\
                    Content-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string();
        let port = serve_once(head, 0).await;
        let e = fetch(&format!("http://127.0.0.1:{port}/sub"), &opts()).await.unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("example.com") && msg.contains("небезопасна"), "{msg}");
    }
}
