//! Unbihex client core: subscriptions, servers, routing presets and control of
//! the Unbihex engine (`Desktop\unbihex-engine`). Shared by the desktop app,
//! the Android app (same process) and, through the engine config JSON, the iOS
//! Packet Tunnel extension.

pub mod client;
pub mod controller;
pub mod error;
pub mod geo;
pub mod jsonsub;
pub mod links;
pub mod model;
pub mod ping;
pub mod plan;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod platform;
pub mod subscription;

pub use client::{AddReport, Client, PingResult};
pub use controller::{ConnectionInfo, Controller, Status};
pub use error::{ClientError, Result};
pub use model::{AppData, GeoStatus, PingMethod, ProxyMode, RoutingMode, Server, Settings, Subscription};

/// Version of the engine this client is built with.
pub const ENGINE_VERSION: &str = unbihex_engine::VERSION;
