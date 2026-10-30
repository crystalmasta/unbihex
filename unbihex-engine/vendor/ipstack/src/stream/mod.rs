use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub use self::tcp::IpStackTcpStream;
pub use self::tcp::{TcpConfig, TcpOptions};
pub use self::udp::IpStackUdpStream;
pub use self::unknown::IpStackUnknownTransport;

mod seqnum;
mod tcb;
mod tcp;
mod udp;
mod unknown;

/// A network stream accepted by the IP stack.
///
/// This enum represents different types of network streams that can be accepted from the TUN device.
/// Each variant provides appropriate abstractions for handling specific protocol types.
///
/// # Variants
///
/// * `Tcp` - A TCP connection stream implementing `AsyncRead` + `AsyncWrite`
/// * `Udp` - A UDP stream implementing `AsyncRead` + `AsyncWrite`
/// * `UnknownTransport` - A stream for unknown transport layer protocols (e.g., ICMP, IGMP)
/// * `UnknownNetwork` - Raw network layer packets that couldn't be parsed
pub enum IpStackStream {
    /// A TCP connection stream.
    Tcp(IpStackTcpStream),
    /// A UDP stream.
    Udp(IpStackUdpStream),
    /// A stream for unknown transport protocols.
    UnknownTransport(IpStackUnknownTransport),
    /// Raw network packets that couldn't be parsed.
    UnknownNetwork(Vec<u8>),
}

impl IpStackStream {
    /// Returns the local socket address for this stream.
    ///
    /// For TCP and UDP streams, this returns the source address of the connection.
    /// For unknown transport and network streams, this returns an unspecified address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::{IpStack, IpStackStream};
    /// # async fn example(stream: IpStackStream) {
    /// let local_addr = stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.local_addr(),
            IpStackStream::Udp(udp) => udp.local_addr(),
            IpStackStream::UnknownNetwork(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            IpStackStream::UnknownTransport(unknown) => match unknown.src_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }

    /// Returns the remote socket address for this stream.
    ///
    /// For TCP and UDP streams, this returns the destination address of the connection.
    /// For unknown transport and network streams, this returns an unspecified address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::{IpStack, IpStackStream};
    /// # async fn example(stream: IpStackStream) {
    /// let peer_addr = stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.peer_addr(),
            IpStackStream::Udp(udp) => udp.peer_addr(),
            IpStackStream::UnknownNetwork(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            IpStackStream::UnknownTransport(unknown) => match unknown.dst_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }

    pub(crate) fn stream_sender(&self) -> Result<crate::PacketSender, std::io::Error> {
        match self {
            IpStackStream::Tcp(tcp) => Ok(tcp.stream_sender()),
            IpStackStream::Udp(udp) => Ok(udp.stream_sender()),
            _ => Err(std::io::Error::other("Unknown transport stream does not have a sender")),
        }
    }
}
