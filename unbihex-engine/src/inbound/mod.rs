//! Inbounds: where traffic enters Unbihex (SPEC §10).

pub mod http;
pub mod mixed;
#[cfg(feature = "server")]
pub mod mux;
#[cfg(feature = "server")]
pub mod reality;
#[cfg(feature = "server")]
mod reality_shape;
pub mod socks;
pub mod tun;
#[cfg(feature = "server")]
pub mod vless;

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

use crate::config::{ProxyInboundConfig, UserConfig};

/// Whether a client from `peer` must present credentials to this inbound.
pub(crate) fn needs_auth(cfg: &ProxyInboundConfig, peer: SocketAddr) -> bool {
    !cfg.users.is_empty() && !(cfg.loopback_without_auth && peer.ip().to_canonical().is_loopback())
}

/// Constant-time comparison for credentials. Both sides are hashed first, so
/// neither the content nor the length of the secret shows in the timing.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (Sha256::digest(a), Sha256::digest(b));
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

pub(crate) fn check_user(users: &[UserConfig], name: &[u8], pass: &[u8]) -> bool {
    // Evaluate every entry so timing does not reveal which username exists.
    users.iter().fold(false, |ok, u| {
        let m = ct_eq(u.username.as_bytes(), name) & ct_eq(u.password.expose().as_bytes(), pass);
        ok | m
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;

    #[test]
    fn credentials() {
        assert!(ct_eq(b"s3cret", b"s3cret"));
        assert!(!ct_eq(b"s3cret", b"s3cre"));
        assert!(!ct_eq(b"s3cret", b"s3creT"));
        let users = vec![UserConfig {
            username: "u".into(),
            password: Secret("p".into()),
        }];
        assert!(check_user(&users, b"u", b"p"));
        assert!(!check_user(&users, b"u", b"x"));
        assert!(!check_user(&users, b"x", b"p"));
    }

    #[test]
    fn auth_decision() {
        let mut cfg = ProxyInboundConfig {
            tag: "in".into(),
            listen: "0.0.0.0:1080".parse().unwrap(),
            users: vec![],
            loopback_without_auth: true,
        };
        let lan: SocketAddr = "192.168.1.20:50000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let local6: SocketAddr = "[::1]:50000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:50000".parse().unwrap();
        let mapped_lan: SocketAddr = "[::ffff:192.168.1.20]:50000".parse().unwrap();
        assert!(!needs_auth(&cfg, lan));

        cfg.users.push(UserConfig {
            username: "u".into(),
            password: Secret("p".into()),
        });
        assert!(needs_auth(&cfg, lan));
        assert!(needs_auth(&cfg, mapped_lan));
        for p in [local, local6, mapped] {
            assert!(!needs_auth(&cfg, p), "{p}");
        }

        cfg.loopback_without_auth = false;
        for p in [lan, local, local6, mapped] {
            assert!(needs_auth(&cfg, p), "{p}");
        }
    }
}
