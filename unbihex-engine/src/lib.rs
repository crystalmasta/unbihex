//! Unbihex core: routing, protocols and the TUN inbound. See `SPEC.md`.

pub mod address;
pub mod config;
pub mod dispatcher;
pub mod dns;
/// Engine errors.
pub mod error;
pub mod inbound;
pub mod link;
/// Outgoing sockets and stream helpers.
pub mod net;
pub mod outbound;
pub mod relay;
pub mod router;
/// Large rule lists: geosite/geoip and sing-box rule-sets.
pub mod rules;
/// Server control: per-user traffic counters and live users of the VLESS inbounds.
#[cfg(feature = "server")]
pub mod server;
/// Sessions passed from inbounds to the dispatcher.
pub mod session;
pub mod stats;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use config::Config;
pub use error::{Error, Result};
pub use inbound::tun::TunInfo;
pub use net::{InterfaceBinding, ProtectFn};

use config::InboundConfig;
use dispatcher::{Dispatcher, LocalGuard};
use dns::fakeip::FakeIpPool;
use dns::server::DnsServer;
use dns::{DnsClient, Resolver};
use net::SocketFactory;
use outbound::{OutboundContext, build_outbound};
use router::Router;

/// Engine version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the host platform provides (SPEC §4).
#[derive(Clone, Default)]
pub struct PlatformHooks {
    /// Mobile: the TUN descriptor created by the OS. Desktop: None (Unbihex creates the device).
    pub tun_fd: Option<i32>,
    /// Android: `VpnService.protect(fd)`.
    pub protect: Option<ProtectFn>,
    /// Desktop: the physical interface outgoing sockets are pinned to.
    pub bind_interface: Option<InterfaceBinding>,
}

/// A running engine.
pub struct Instance {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    tun: Option<TunInfo>,
    server_ips: parking_lot::Mutex<Vec<IpAddr>>,
    counters: Arc<stats::Counters>,
    dispatcher: Arc<Dispatcher>,
    /// Outbound services for hot reload; server names resolve through our own DNS
    /// once traffic is captured.
    reload_ctx: OutboundContext,
    /// What a hot reload must not change (inbounds, DNS, limits).
    fixed: String,
    geo: parking_lot::Mutex<rules::GeoCache>,
    #[cfg(feature = "server")]
    server: Arc<server::ServerControl>,
}

/// The parts of a config that a hot reload cannot change.
fn fixed_part(c: &Config) -> String {
    format!("{:?}|{:?}|{:?}", c.inbounds, c.dns, c.limits)
}

async fn build_outbounds(
    config: &Config,
    ctx: &OutboundContext,
) -> Result<(Vec<Arc<dyn outbound::Outbound>>, Vec<IpAddr>)> {
    let mut outbounds = Vec::with_capacity(config.outbounds.len());
    for oc in &config.outbounds {
        let ob = build_outbound(oc, ctx)
            .await
            .map_err(|e| Error::config(format!("outbound {}: {e}", oc.tag())))?;
        outbounds.push(ob);
    }
    let mut server_ips: Vec<IpAddr> = outbounds
        .iter()
        .filter_map(|o| o.server())
        .flat_map(|s| s.addrs.iter().map(|a| a.ip()))
        .collect();
    server_ips.sort();
    server_ips.dedup();
    Ok((outbounds, server_ips))
}

impl Instance {
    /// Validates `config`, builds outbounds and starts every inbound.
    pub async fn start(config: Config, hooks: PlatformHooks) -> Result<Instance> {
        config.validate()?;
        let sockets = Arc::new(SocketFactory::new(
            hooks.bind_interface.clone(),
            hooks.protect.clone(),
        ));
        let tun_cfg = config.tun().cloned();
        let mobile = hooks.tun_fd.is_some();
        if mobile && tun_cfg.is_none() {
            return Err(Error::config(
                "tun_fd was given but the config has no tun inbound",
            ));
        }
        // The userspace stack (ipstack) blocks inside Drop of TCP streams via
        // `block_in_place`, which only works on the multi-thread runtime.
        if tun_cfg.is_some()
            && tokio::runtime::Handle::current().runtime_flavor()
                != tokio::runtime::RuntimeFlavor::MultiThread
        {
            return Err(Error::config(
                "a tun inbound requires a multi-thread tokio runtime",
            ));
        }

        let dns_client = Arc::new(DnsClient::new(config.dns.upstream.clone(), sockets.clone()));
        let upstream = Arc::new(Resolver::Upstream(dns_client.clone()));
        let system = Arc::new(Resolver::System);
        let fakeip = tun_cfg.as_ref().map(|_| {
            // Clients may cache an answer for its whole TTL (and often longer).
            let ttl = Duration::from_secs(u64::from(config.dns.ttl) * 4);
            Arc::new(
                FakeIpPool::new(config.dns.fakeip_range)
                    .with_quarantine(dns::fakeip::DEFAULT_QUARANTINE.max(ttl)),
            )
        });
        let ctx = OutboundContext {
            sockets: sockets.clone(),
            // With a TUN the system resolver answers with fake IPs, so use our own client.
            resolver: if tun_cfg.is_some() {
                upstream.clone()
            } else {
                system.clone()
            },
            // Server names are resolved before traffic is captured; mobile has no such window.
            server_resolver: if mobile { upstream.clone() } else { system },
            fakeip: fakeip.clone(),
        };

        let (outbounds, server_ips) = build_outbounds(&config, &ctx).await?;

        let mut geo = rules::GeoCache::default();
        let router = Router::with_cache(&config, &mut geo)?;
        let fakeip_exclude = config.dns.fakeip_exclude_suffixes()?;
        let reload_ctx = OutboundContext {
            // After the TUN is up the system resolver answers with fake IPs.
            server_resolver: if tun_cfg.is_some() {
                ctx.resolver.clone()
            } else {
                ctx.server_resolver.clone()
            },
            ..ctx.clone()
        };
        let counters = Arc::new(stats::Counters::default());
        let listens: Vec<std::net::SocketAddr> = config
            .inbounds
            .iter()
            .filter_map(|i| match i {
                InboundConfig::Socks(c) | InboundConfig::Http(c) | InboundConfig::Mixed(c) => {
                    Some(c.listen)
                }
                #[cfg(feature = "server")]
                InboundConfig::Vless(c) => Some(c.listen),
                InboundConfig::Tun(_) => None,
            })
            .collect();
        let guard = LocalGuard::new(&listens, tun_cfg.as_ref().map(|t| t.tag.clone()));
        // A server's users must not reach its LAN by name: no client-style exceptions.
        #[cfg(feature = "server")]
        let serves = config
            .inbounds
            .iter()
            .any(|i| matches!(i, InboundConfig::Vless(_)));
        #[cfg(not(feature = "server"))]
        let serves = false;
        let private_names = config.dns.private_answer_suffixes(!serves)?;
        let dispatcher = Arc::new(
            Dispatcher::new(
                router,
                outbounds,
                config.limits.clone(),
                fakeip.clone(),
                counters.clone(),
            )
            .with_policy(ctx.resolver.clone(), guard)
            .with_private_names(private_names, !serves),
        );
        let handshake = Duration::from_secs(config.limits.handshake_timeout_secs);
        let handshakes = Arc::new(tokio::sync::Semaphore::new(config.limits.max_connections));
        let cancel = CancellationToken::new();
        let mut instance = Instance {
            cancel: cancel.clone(),
            tasks: Vec::new(),
            tun: None,
            server_ips: parking_lot::Mutex::new(server_ips),
            counters,
            dispatcher: dispatcher.clone(),
            reload_ctx,
            fixed: fixed_part(&config),
            geo: parking_lot::Mutex::new(geo),
            #[cfg(feature = "server")]
            server: Arc::default(),
        };

        for ic in &config.inbounds {
            let started = match ic {
                InboundConfig::Socks(c) => inbound::socks::bind(c).await.map(|l| {
                    tokio::spawn(inbound::socks::serve(
                        l,
                        c.clone(),
                        dispatcher.clone(),
                        handshake,
                        handshakes.clone(),
                        cancel.clone(),
                    ))
                }),
                InboundConfig::Http(c) => inbound::http::bind(c).await.map(|l| {
                    tokio::spawn(inbound::http::serve(
                        l,
                        c.clone(),
                        dispatcher.clone(),
                        handshake,
                        handshakes.clone(),
                        cancel.clone(),
                    ))
                }),
                InboundConfig::Mixed(c) => inbound::mixed::bind(c).await.map(|l| {
                    tokio::spawn(inbound::mixed::serve(
                        l,
                        c.clone(),
                        dispatcher.clone(),
                        handshake,
                        handshakes.clone(),
                        cancel.clone(),
                    ))
                }),
                #[cfg(feature = "server")]
                InboundConfig::Vless(c) => {
                    let control = instance.server.clone();
                    inbound::vless::bind(c, control.stats().clone())
                        .await
                        .map(|(l, server)| {
                            control.register(&c.tag, server.users());
                            tokio::spawn(inbound::vless::serve(
                                l,
                                server,
                                dispatcher.clone(),
                                handshake,
                                handshakes.clone(),
                                cancel.clone(),
                            ))
                        })
                }
                InboundConfig::Tun(c) => {
                    if !c.dns_hijack {
                        tracing::warn!(
                            "tun {}: dns_hijack is off, so DNS goes to the system resolver as plain \
                             UDP (to the ISP, when the resolver is the router) and domain rules see \
                             no names",
                            c.tag
                        );
                    }
                    // The fake-IP pool always exists when a tun inbound is configured.
                    let dns_server = match (c.dns_hijack, fakeip.clone()) {
                        (true, Some(pool)) => Some(Arc::new(
                            DnsServer::new(pool, dns_client.clone(), config.dns.ttl)
                                .with_dispatcher(dispatcher.clone(), c.tag.clone())
                                .with_fakeip_exclude(fakeip_exclude.clone()),
                        )),
                        _ => None,
                    };
                    inbound::tun::start(
                        c,
                        hooks.tun_fd,
                        Duration::from_secs(config.limits.udp_idle_secs),
                        Duration::from_secs(config.limits.tcp_idle_secs),
                        dispatcher.clone(),
                        dns_server,
                        cancel.clone(),
                    )
                    .await
                    .map(|(info, handle)| {
                        instance.tun = Some(info);
                        handle
                    })
                }
            };
            match started {
                Ok(handle) => instance.tasks.push(handle),
                Err(e) => {
                    instance.shutdown().await;
                    return Err(e);
                }
            }
        }
        tracing::info!("unbihex {VERSION} started");
        Ok(instance)
    }

    /// The TUN interface, when a TUN inbound runs.
    pub fn tun_info(&self) -> Option<&TunInfo> {
        self.tun.as_ref()
    }

    /// Resolved addresses of all proxy servers (desktop routes them around the TUN).
    pub fn server_ips(&self) -> Vec<IpAddr> {
        self.server_ips.lock().clone()
    }

    /// Hot reload: replaces outbounds and routing rules without touching inbounds or
    /// open connections. Fails (and changes nothing) if the new config differs in
    /// inbounds, DNS or limits; those need a restart.
    pub async fn reload(&self, config: Config) -> Result<()> {
        config.validate()?;
        if fixed_part(&config) != self.fixed {
            return Err(Error::config(
                "inbounds, dns or limits changed: a restart is required",
            ));
        }
        let (outbounds, server_ips) = build_outbounds(&config, &self.reload_ctx).await?;
        let router = {
            let mut geo = self.geo.lock();
            Router::with_cache(&config, &mut geo)?
        };
        self.dispatcher
            .swap_table(dispatcher::Table::new(router, outbounds));
        *self.server_ips.lock() = server_ips;
        tracing::info!("configuration reloaded");
        Ok(())
    }

    /// Users and traffic counters of the server inbounds, for the management API.
    #[cfg(feature = "server")]
    pub fn server(&self) -> Arc<server::ServerControl> {
        self.server.clone()
    }

    /// Live traffic counters.
    pub fn counters(&self) -> Arc<stats::Counters> {
        self.counters.clone()
    }

    /// Stops all inbounds and waits up to 5 seconds for their tasks.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        for mut t in self.tasks {
            if tokio::time::timeout(Duration::from_secs(5), &mut t)
                .await
                .is_err()
            {
                t.abort();
            }
        }
        tracing::info!("unbihex stopped");
    }
}
