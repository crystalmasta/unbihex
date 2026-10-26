//! Outgoing sockets that never loop back into our own TUN (SPEC §9).
//!
//! Every socket Unbihex opens to the outside world (proxy servers, direct
//! connections, DNS upstreams) is created here and pinned to the physical
//! interface (desktop) or passed to `VpnService.protect` (Android) before
//! `connect`/`bind`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::error::{Error, Result};

/// `VpnService.protect(fd)`: returns `false` when the socket could not be protected.
pub type ProtectFn = Arc<dyn Fn(i32) -> bool + Send + Sync>;

/// The physical interface outgoing sockets are bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceBinding {
    /// Interface name (used on Linux and Android).
    pub name: String,
    /// Interface index (used on Apple platforms and Windows).
    pub index: u32,
}

/// Creates outgoing sockets that bypass the TUN.
#[derive(Clone, Default)]
pub struct SocketFactory {
    binding: Option<InterfaceBinding>,
    protect: Option<ProtectFn>,
}

impl std::fmt::Debug for SocketFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketFactory")
            .field("binding", &self.binding)
            .field("protect", &self.protect.is_some())
            .finish()
    }
}

impl SocketFactory {
    /// Creates a factory; both arguments are optional.
    pub fn new(binding: Option<InterfaceBinding>, protect: Option<ProtectFn>) -> Self {
        SocketFactory { binding, protect }
    }

    /// The interface sockets are bound to.
    pub fn binding(&self) -> Option<&InterfaceBinding> {
        self.binding.as_ref()
    }

    /// Connects a TCP socket bound to the physical interface.
    pub async fn tcp_connect(&self, addr: SocketAddr) -> Result<TcpStream> {
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        self.prepare(&sock, addr.is_ipv6())?;
        sock.set_nonblocking(true)?;
        let std_stream: std::net::TcpStream = sock.into();
        let stream = TcpSocket::from_std_stream(std_stream).connect(addr).await?;
        let sref = SockRef::from(&stream);
        sref.set_tcp_nodelay(true)?;
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));
        // Not every platform supports every keepalive knob; it is an optimization only.
        let _ = sref.set_tcp_keepalive(&keepalive);
        Ok(stream)
    }

    /// Binds a UDP socket on the physical interface.
    pub async fn udp_bind(&self, v6: bool) -> Result<UdpSocket> {
        let (domain, any) = if v6 {
            (
                Domain::IPV6,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            )
        } else {
            (
                Domain::IPV4,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        self.prepare(&sock, v6)?;
        sock.set_nonblocking(true)?;
        sock.bind(&any.into())?;
        let std_sock: std::net::UdpSocket = sock.into();
        Ok(UdpSocket::from_std(std_sock)?)
    }

    /// An unprivileged ICMP echo socket (`SOCK_DGRAM`, blocking) on the physical
    /// interface. Linux needs the group in `net.ipv4.ping_group_range`; Android and
    /// Apple platforms allow it to apps.
    #[cfg(unix)]
    pub fn icmp_socket(&self, v6: bool) -> Result<Socket> {
        let (domain, proto) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(proto))?;
        self.prepare(&sock, v6)?;
        Ok(sock)
    }

    fn prepare(&self, sock: &Socket, v6: bool) -> Result<()> {
        if let Some(protect) = &self.protect {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                if !protect(sock.as_raw_fd()) {
                    return Err(Error::Protect);
                }
            }
            #[cfg(not(unix))]
            let _ = protect;
        }
        if let Some(b) = &self.binding {
            bind_to_interface(sock, b, v6).map_err(|e| {
                Error::Platform(format!("cannot bind socket to interface {}: {e}", b.name))
            })?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to_interface(sock: &Socket, b: &InterfaceBinding, _v6: bool) -> io::Result<()> {
    sock.bind_device(Some(b.name.as_bytes()))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_to_interface(sock: &Socket, b: &InterfaceBinding, v6: bool) -> io::Result<()> {
    let idx = std::num::NonZeroU32::new(b.index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "interface index is 0"))?;
    if v6 {
        sock.bind_device_by_index_v6(Some(idx))
    } else {
        sock.bind_device_by_index_v4(Some(idx))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // FFI: setsockopt has no safe wrapper for IP_UNICAST_IF.
fn bind_to_interface(sock: &Socket, b: &InterfaceBinding, v6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt,
    };
    // IP_UNICAST_IF expects the index in network byte order; IPV6_UNICAST_IF in host order.
    let (level, name, value) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, b.index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, b.index.to_be())
    };
    // SAFETY: the socket handle is valid for the lifetime of `sock`, and the option
    // value points to a live u32 whose size is passed as the option length.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_socket() as SOCKET,
            level,
            name,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
fn bind_to_interface(_sock: &Socket, _b: &InterfaceBinding, _v6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is not supported on this OS",
    ))
}
