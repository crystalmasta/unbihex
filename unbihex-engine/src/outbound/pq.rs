//! X25519MLKEM768 (0x11ec), the hybrid post-quantum key exchange browsers offer first
//! (draft-ietf-tls-ecdhe-mlkem), in pure Rust: the `ml-kem` crate and x25519-dalek.
//!
//! * client share = ML-KEM-768 encapsulation key (1184 B) | X25519 public key (32 B);
//! * server share = ML-KEM-768 ciphertext (1088 B) | X25519 public key (32 B);
//! * secret = ML-KEM shared key (32 B) | X25519 shared secret (32 B).
//!
//! Like Chrome, the client also offers the X25519 half as a separate key share (the same
//! key, through rustls's `hybrid_component`), so a server without ML-KEM still completes
//! with one round trip.

use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed, TryKeyInit};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{NamedGroup, ProtocolVersion};
use x25519_dalek::{PublicKey, StaticSecret};

const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const X_LEN: usize = 32;

/// The secrets one key share is built from.
pub struct HybridSecrets {
    /// X25519 private key.
    pub x25519: [u8; 32],
    /// ML-KEM-768 seed (d | z, FIPS 203).
    pub mlkem_seed: [u8; 64],
}

impl HybridSecrets {
    /// Fresh random secrets.
    pub fn random() -> HybridSecrets {
        let mut s = HybridSecrets {
            x25519: [0; 32],
            mlkem_seed: [0; 64],
        };
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s.x25519);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s.mlkem_seed);
        s
    }
}

/// The X25519MLKEM768 group; `secrets` supplies each new key share (REALITY replays
/// fixed ones).
pub struct X25519MlKem768 {
    secrets: fn() -> Result<HybridSecrets, rustls::Error>,
}

impl std::fmt::Debug for X25519MlKem768 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519MLKEM768")
    }
}

/// X25519MLKEM768 with fresh random keys.
pub static X25519_MLKEM768: X25519MlKem768 = X25519MlKem768::new(|| Ok(HybridSecrets::random()));

impl X25519MlKem768 {
    /// A group whose key shares come from `secrets`.
    pub const fn new(secrets: fn() -> Result<HybridSecrets, rustls::Error>) -> Self {
        X25519MlKem768 { secrets }
    }
}

fn bad_share() -> rustls::Error {
    rustls::Error::General("X25519MLKEM768: malformed key share".into())
}

fn dh(secret: &StaticSecret, peer: &[u8]) -> Result<[u8; 32], rustls::Error> {
    let peer: [u8; 32] = peer.try_into().map_err(|_| bad_share())?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(rustls::Error::General("X25519MLKEM768: weak X25519 share".into()));
    }
    Ok(shared.to_bytes())
}

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let s = (self.secrets)()?;
        let dk = DecapsulationKey768::from_seed(Seed::from(s.mlkem_seed));
        let x25519 = StaticSecret::from(s.x25519);
        let x_pub = PublicKey::from(&x25519).to_bytes();
        let mut share = dk.encapsulation_key().to_bytes().to_vec();
        share.extend_from_slice(&x_pub);
        Ok(Box::new(ActiveHybrid {
            dk,
            x25519,
            x_pub,
            share,
        }))
    }

    /// Server side: encapsulate to the client's key and answer with our own X25519 key.
    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, rustls::Error> {
        if peer.len() != EK_LEN + X_LEN {
            return Err(bad_share());
        }
        let ek = EncapsulationKey768::new_from_slice(&peer[..EK_LEN]).map_err(|_| bad_share())?;
        let mut m = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut m);
        let (ct, mlkem_secret) = ek.encapsulate_deterministic(&m.into());
        let s = (self.secrets)()?;
        let x25519 = StaticSecret::from(s.x25519);
        let x_secret = dh(&x25519, &peer[EK_LEN..])?;
        let mut pub_key = ct.to_vec();
        pub_key.extend_from_slice(PublicKey::from(&x25519).as_bytes());
        let mut secret = mlkem_secret.to_vec();
        secret.extend_from_slice(&x_secret);
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveHybrid {
    dk: DecapsulationKey768,
    x25519: StaticSecret,
    x_pub: [u8; 32],
    share: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        if peer.len() != CT_LEN + X_LEN {
            return Err(bad_share());
        }
        let mlkem_secret = self
            .dk
            .decapsulate_slice(&peer[..CT_LEN])
            .map_err(|_| bad_share())?;
        let x_secret = dh(&self.x25519, &peer[CT_LEN..])?;
        let mut secret = mlkem_secret.to_vec();
        secret.extend_from_slice(&x_secret);
        Ok(SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, &self.x_pub))
    }

    /// The server chose plain X25519 from our separate share.
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        Ok(SharedSecret::from(dh(&self.x25519, peer)?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_agree() {
        let client = X25519_MLKEM768.start().unwrap();
        assert_eq!(client.pub_key().len(), EK_LEN + X_LEN);
        let (group, x_pub) = client.hybrid_component().unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(x_pub, &client.pub_key()[EK_LEN..]);
        let server = X25519_MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), CT_LEN + X_LEN);
        let secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes().len(), 64);
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn same_secrets_give_the_same_share() {
        static FIXED: X25519MlKem768 = X25519MlKem768::new(|| {
            Ok(HybridSecrets {
                x25519: [5; 32],
                mlkem_seed: [6; 64],
            })
        });
        assert_eq!(
            FIXED.start().unwrap().pub_key(),
            FIXED.start().unwrap().pub_key()
        );
    }

    #[test]
    fn malformed_shares_are_refused() {
        let client = X25519_MLKEM768.start().unwrap();
        assert!(client.complete(&[0u8; 10]).is_err());
        assert!(X25519_MLKEM768.start_and_complete(&[0u8; 10]).is_err());
        // An all-zero X25519 key is a small-order point.
        let client = X25519_MLKEM768.start().unwrap();
        let mut reply = vec![0u8; CT_LEN + X_LEN];
        reply[..CT_LEN].fill(1);
        assert!(client.complete(&reply).is_err());
    }
}
