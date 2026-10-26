//! Traffic counters, split by whether bytes went through a proxy or directly.

use std::sync::atomic::{AtomicU64, Ordering};

/// Byte counters updated while data is relayed.
#[derive(Debug, Default)]
pub struct Counters {
    /// Sent through proxy outbounds.
    pub proxy_up: AtomicU64,
    /// Received through proxy outbounds.
    pub proxy_down: AtomicU64,
    /// Sent through the direct outbound.
    pub direct_up: AtomicU64,
    /// Received through the direct outbound.
    pub direct_down: AtomicU64,
}

impl Counters {
    /// The (up, down) pair for one kind of outbound.
    pub(crate) fn pair(&self, direct: bool) -> (&AtomicU64, &AtomicU64) {
        if direct {
            (&self.direct_up, &self.direct_down)
        } else {
            (&self.proxy_up, &self.proxy_down)
        }
    }

    /// Current values: (proxy_up, proxy_down, direct_up, direct_down).
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.proxy_up.load(Ordering::Relaxed),
            self.proxy_down.load(Ordering::Relaxed),
            self.direct_up.load(Ordering::Relaxed),
            self.direct_down.load(Ordering::Relaxed),
        )
    }
}
