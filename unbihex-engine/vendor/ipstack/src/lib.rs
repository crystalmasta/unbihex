#![doc = include_str!("../README.md")]

use ahash::AHashMap;
use packet::{NetworkPacket, NetworkTuple, TransportHeader};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

pub(crate) type PacketSender = UnboundedSender<NetworkPacket>;
pub(crate) type PacketReceiver = UnboundedReceiver<NetworkPacket>;
pub(crate) type SessionCollection = AHashMap<NetworkTuple, PacketSender>;

mod error;
mod packet;
mod stream;

pub use self::error::{IpStackError, Result};
pub use self::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport};
pub use self::stream::{TcpConfig, TcpOptions};
pub use etherparse::IpNumber;

#[cfg(unix)]
const TTL: u8 = 64;

#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0A];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

/// Minimum MTU required for IPv6 (per RFC 8200 §5: MTU ≥ 1280).
/// Also satisfies IPv4 minimum MTU (RFC 791 §3.1: 68 bytes).
const MIN_MTU: u16 = 1280;

/// Configuration for the IP stack.
///
/// This structure holds configuration parameters that control the behavior of the IP stack,
/// including network settings and protocol-specific timeouts.
///
/// # Examples
///
/// ```
/// use ipstack::IpStackConfig;
/// use std::time::Duration;
///
/// let mut config = IpStackConfig::default();
/// config.mtu(1500).expect("Failed to set MTU")
///       .udp_timeout(Duration::from_secs(60))
///       .packet_information(false);
/// ```
#[non_exhaustive]
pub struct IpStackConfig {
    /// Maximum Transmission Unit (MTU) size in bytes.
    /// Default is `MIN_MTU` (1280).
    pub mtu: u16,
    /// Whether to include packet information headers (Unix platforms only).
    /// Default is `false`.
    pub packet_information: bool,
    /// TCP-specific configuration parameters.
    pub tcp_config: Arc<TcpConfig>,
    /// Timeout for UDP connections.
    /// Default is 30 seconds.
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: MIN_MTU,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    /// Set custom TCP configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The TCP configuration to use
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::{IpStackConfig, TcpConfig};
    ///
    /// let mut config = IpStackConfig::default();
    /// config.with_tcp_config(TcpConfig::default());
    /// ```
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }

    /// Set the UDP connection timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for UDP connections
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.udp_timeout(Duration::from_secs(60));
    /// ```
    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }

    /// Set the Maximum Transmission Unit (MTU) size.
    ///
    /// # Arguments
    ///
    /// * `mtu` - The MTU size in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.mtu(1500).expect("Failed to set MTU");
    /// ```
    pub fn mtu(&mut self, mtu: u16) -> Result<&mut Self, IpStackError> {
        if mtu < MIN_MTU {
            return Err(IpStackError::InvalidMtuSize(mtu));
        }
        self.mtu = mtu;
        Ok(self)
    }

    /// Set the Maximum Transmission Unit (MTU) size without validation.
    pub fn mtu_unchecked(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable packet information headers (Unix platforms only).
    ///
    /// When enabled on Unix platforms, the TUN device will include 4-byte packet
    /// information headers.
    ///
    /// # Arguments
    ///
    /// * `packet_information` - Whether to include packet information headers
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.packet_information(true);
    /// ```
    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

/// The main IP stack instance.
///
/// `IpStack` provides a userspace TCP/IP stack implementation for TUN devices.
/// It processes network packets and creates stream abstractions for TCP, UDP, and
/// unknown transport protocols.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use std::net::Ipv4Addr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Configure TUN device
///     let mut config = tun::Configuration::default();
///     config
///         .address(Ipv4Addr::new(10, 0, 0, 1))
///         .netmask(Ipv4Addr::new(255, 255, 255, 0))
///         .up();
///
///     // Create IP stack
///     let ipstack_config = IpStackConfig::default();
///     let mut ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&config)?);
///
///     // Accept incoming streams
///     while let Ok(stream) = ip_stack.accept().await {
///         match stream {
///             IpStackStream::Tcp(tcp) => {
///                 // Handle TCP connection
///             }
///             IpStackStream::Udp(udp) => {
///                 // Handle UDP connection
///             }
///             _ => {}
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
    handle: JoinHandle<Result<()>>,
}

impl IpStack {
    /// Create a new IP stack instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the IP stack
    /// * `device` - An async TUN device implementing `AsyncRead` + `AsyncWrite`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig};
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut tun_config = tun::Configuration::default();
    /// tun_config.address(Ipv4Addr::new(10, 0, 0, 1))
    ///           .netmask(Ipv4Addr::new(255, 255, 255, 0))
    ///           .up();
    ///
    /// let ipstack_config = IpStackConfig::default();
    /// let ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&tun_config)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<Device>(config: IpStackConfig, device: Device) -> IpStack
    where
        Device: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        IpStack {
            accept_receiver,
            handle: run(config, device, accept_sender),
        }
    }

    /// Accept an incoming network stream.
    ///
    /// This method waits for and returns the next incoming network connection or packet.
    /// The returned `IpStackStream` enum indicates the type of stream (TCP, UDP, or unknown).
    ///
    /// # Returns
    ///
    /// * `Ok(IpStackStream)` - The next incoming stream
    /// * `Err(IpStackError::AcceptError)` - If the IP stack has been shut down
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig, IpStackStream};
    ///
    /// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
    /// match ip_stack.accept().await? {
    ///     IpStackStream::Tcp(tcp) => {
    ///         println!("New TCP connection from {}", tcp.peer_addr());
    ///     }
    ///     IpStackStream::Udp(udp) => {
    ///         println!("New UDP stream from {}", udp.peer_addr());
    ///     }
    ///     IpStackStream::UnknownTransport(unknown) => {
    ///         println!("Unknown transport protocol: {:?}", unknown.ip_protocol());
    ///     }
    ///     IpStackStream::UnknownNetwork(data) => {
    ///         println!("Unknown network packet: {} bytes", data.len());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        self.accept_receiver.recv().await.ok_or(IpStackError::AcceptError)
    }
}

impl Drop for IpStack {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn run<Device: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    config: IpStackConfig,
    mut device: Device,
    accept_sender: UnboundedSender<IpStackStream>,
) -> JoinHandle<Result<()>> {
    let mut sessions: SessionCollection = AHashMap::new();
    let (session_remove_tx, mut session_remove_rx) = mpsc::unbounded_channel::<NetworkTuple>();
    let pi = config.packet_information;
    let offset = if pi && cfg!(unix) { 4 } else { 0 };
    let mut buffer = vec![0_u8; config.mtu as usize + offset];
    let (up_pkt_sender, mut up_pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

    tokio::spawn(async move {
        loop {
            select! {
                Ok(n) = device.read(&mut buffer) => {
                    if let Err(e) = process_device_read(&buffer[offset..n], &mut sessions, &session_remove_tx, &up_pkt_sender, &config, &accept_sender).await {
                        let io_err: std::io::Error = e.into();
                        if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                            log::trace!("Received junk data: {io_err}");
                        } else {
                            log::warn!("process_device_read error: {io_err}");
                        }
                    }
                }
                Some(network_tuple) = session_remove_rx.recv() => {
                    sessions.remove(&network_tuple);
                    log::debug!("session destroyed: {network_tuple}");
                }
                Some(packet) = up_pkt_receiver.recv() => {
                    process_upstream_recv(packet, &mut device, #[cfg(unix)]pi).await?;
                }
            }
        }
    })
}

async fn process_device_read(
    data: &[u8],
    sessions: &mut SessionCollection,
    session_remove_tx: &UnboundedSender<NetworkTuple>,
    up_pkt_sender: &PacketSender,
    config: &IpStackConfig,
    accept_sender: &UnboundedSender<IpStackStream>,
) -> Result<()> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        let stream = IpStackStream::UnknownNetwork(data.to_owned());
        accept_sender.send(stream)?;
        return Ok(());
    };

    if let TransportHeader::Unknown = packet.transport_header() {
        let stream = IpStackStream::UnknownTransport(IpStackUnknownTransport::new(
            packet.src_addr().ip(),
            packet.dst_addr().ip(),
            packet.payload.unwrap_or_default(),
            &packet.ip,
            config.mtu,
            up_pkt_sender.clone(),
        ));
        accept_sender.send(stream)?;
        return Ok(());
    }

    let network_tuple = packet.network_tuple();
    match sessions.entry(network_tuple) {
        std::collections::hash_map::Entry::Occupied(entry) => {
            let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
            log::trace!("packet sent to stream: {network_tuple} len {len}");
            entry.get().send(packet).map_err(std::io::Error::other)?;
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let ip_stack_stream = create_stream(packet, config, up_pkt_sender.clone(), Some(tx))?;
            let session_remove_tx = session_remove_tx.clone();
            tokio::spawn(async move {
                rx.await.ok();
                if let Err(e) = session_remove_tx.send(network_tuple) {
                    log::error!("Failed to send session removal for {network_tuple}: {e}");
                }
            });
            let packet_sender = ip_stack_stream.stream_sender()?;
            accept_sender.send(ip_stack_stream)?;
            entry.insert(packet_sender);
            log::debug!("session created: {network_tuple}");
        }
    }
    Ok(())
}

fn create_stream(
    packet: NetworkPacket,
    cfg: &IpStackConfig,
    up_pkt_sender: PacketSender,
    msgr: Option<::tokio::sync::oneshot::Sender<()>>,
) -> Result<IpStackStream> {
    let src_addr = packet.src_addr();
    let dst_addr = packet.dst_addr();
    match packet.transport_header() {
        TransportHeader::Tcp(h) => {
            let stream = IpStackTcpStream::new(src_addr, dst_addr, h.clone(), up_pkt_sender, cfg.mtu, msgr, cfg.tcp_config.clone())?;
            Ok(IpStackStream::Tcp(stream))
        }
        TransportHeader::Udp(_) => {
            let payload = packet.payload.unwrap_or_default();
            let stream = IpStackUdpStream::new(src_addr, dst_addr, payload, up_pkt_sender, cfg.mtu, cfg.udp_timeout, msgr);
            Ok(IpStackStream::Udp(stream))
        }
        TransportHeader::Unknown => Err(IpStackError::UnsupportedTransportProtocol),
    }
}

async fn process_upstream_recv<Device: AsyncWrite + Unpin + 'static>(
    up_packet: NetworkPacket,
    device: &mut Device,
    #[cfg(unix)] packet_information: bool,
) -> Result<()> {
    #[allow(unused_mut)]
    let Ok(mut packet_bytes) = up_packet.to_bytes() else {
        log::warn!("to_bytes error");
        return Ok(());
    };
    #[cfg(unix)]
    if packet_information {
        if up_packet.src_addr().is_ipv4() {
            packet_bytes.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP4].concat());
        } else {
            packet_bytes.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP6].concat());
        }
    }
    device.write_all(&packet_bytes).await?;
    // device.flush().await?;

    Ok(())
}
