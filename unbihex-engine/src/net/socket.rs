//! Outgoing sockets that never loop back into our own TUN (SPEC §9).
//!
//! Every socket Unbihex opens to the outside world (proxy servers, direct
//! connections, DNS upstreams) is created here and pinned to the physical
//! interface (desktop) or passed to `VpnService.protect` (Android) before
//! `connect`/`bind`. On Linux the socket can also carry a mark (`SO_MARK`)
//! for policy routing.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::error::{Error, Result};

/// `VpnService.protect(fd)`: returns `false` when the socket could not be protected.
pub type ProtectFn = Arc<dyn Fn(i32) -> bool + Send + Sync>;

// By Pavel Shakhmin (github.com/pshakhmin), PR #20.
/// Default for [`set_socket_buffer`]: leave the buffers to the kernel.
///
/// Linux autotunes the receive buffer up to `net.ipv4.tcp_rmem[2]`, growing the
/// window as fast as the application drains the socket. Pinning `SO_RCVBUF` turns
/// that off: on a shaped 50 ms path (MTU 1500) a fixed 4 MiB gave 55 MB/s against
/// 64 and sometimes collapsed to 1 MB/s, when the kernel's estimate of the
/// application's appetite (`rcv_space`) fell from 5 MB to 56 KB. The loopback
/// profile that once favoured 4 MiB has MTU 65536, where the initial window
/// (36 KB) is smaller than one segment, which no real link has.
pub const DEFAULT_SOCKET_BUFFER: usize = 0;
/// Smallest configurable value: below this the cap binds on any real path.
pub const MIN_SOCKET_BUFFER: usize = 64 * 1024;
/// Largest configurable value. The kernel clamps to `net.core.{r,w}mem_max`
/// anyway; this only keeps a typo from asking for gigabytes per socket.
pub const MAX_SOCKET_BUFFER: usize = 16 * 1024 * 1024;

// By Pavel Shakhmin (github.com/pshakhmin), PR #20.
/// Process-wide value, set once from `limits.socket_buffer` before any socket
/// exists: inbounds tune their sockets before a session exists and have no config.
static SOCKET_BUFFER: AtomicUsize = AtomicUsize::new(DEFAULT_SOCKET_BUFFER);

/// Sets the buffer every later [`tune_tcp`] call asks for; `0` leaves sockets at
/// the kernel default.
pub fn set_socket_buffer(bytes: usize) {
    SOCKET_BUFFER.store(bytes, Ordering::Relaxed);
}

/// The value [`tune_tcp`] currently applies.
pub fn socket_buffer() -> usize {
    SOCKET_BUFFER.load(Ordering::Relaxed)
}

// By Pavel Shakhmin (github.com/pshakhmin), PR #18 and #20.
/// Applies what every TCP socket carrying tunnel traffic needs: no Nagle, and the
/// configured buffer (`limits.socket_buffer`). Failures are ignored on purpose —
/// this is an optimization, and some platforms cap or refuse the size (the
/// effective value stays visible via `getsockopt`, so it is not silent).
pub fn tune_tcp(stream: &TcpStream) {
    tune_tcp_with(stream, socket_buffer());
}

// By Pavel Shakhmin (github.com/pshakhmin), PR #20.
/// [`tune_tcp`] with an explicit buffer size; `0` only disables Nagle.
pub fn tune_tcp_with(stream: &TcpStream, buffer: usize) {
    let sref = SockRef::from(stream);
    let _ = sref.set_tcp_nodelay(true);
    if buffer > 0 {
        let _ = sref.set_recv_buffer_size(buffer);
        let _ = sref.set_send_buffer_size(buffer);
    }
}

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
    mark: Option<u32>,
}

impl std::fmt::Debug for SocketFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketFactory")
            .field("binding", &self.binding)
            .field("protect", &self.protect.is_some())
            .field("mark", &self.mark)
            .finish()
    }
}

impl SocketFactory {
    /// Creates a factory; both arguments are optional.
    pub fn new(binding: Option<InterfaceBinding>, protect: Option<ProtectFn>) -> Self {
        SocketFactory {
            binding,
            protect,
            mark: None,
        }
    }

    /// Linux: marks every socket with `SO_MARK` (needs `CAP_NET_ADMIN`).
    pub fn with_mark(mut self, mark: Option<u32>) -> Self {
        self.mark = mark;
        self
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
        // By Pavel Shakhmin (github.com/pshakhmin), PR #18.
        tune_tcp(&stream);
        let sref = SockRef::from(&stream);
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
        if let Some(mark) = self.mark {
            set_mark(sock, mark)
                .map_err(|e| Error::Platform(format!("cannot set socket mark {mark}: {e}")))?;
        }
        Ok(())
    }
}

/// Looks up an interface by name (on Windows also by its friendly name).
pub fn find_interface(name: &str) -> Result<InterfaceBinding> {
    netdev::get_interfaces()
        .into_iter()
        .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name))
        .map(|i| InterfaceBinding {
            name: i.name,
            index: i.index,
        })
        .ok_or_else(|| Error::config(format!("no network interface {name:?}")))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_mark(sock: &Socket, mark: u32) -> io::Result<()> {
    sock.set_mark(mark)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_mark(_sock: &Socket, _mark: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket marks are supported on Linux only",
    ))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    // By Pavel Shakhmin (github.com/pshakhmin), PR #20.
    #[tokio::test]
    async fn zero_buffer_keeps_the_kernel_default() {
        let (client, _server) = pair().await;
        let (untuned, _other) = pair().await;
        let before = SockRef::from(&untuned).recv_buffer_size().unwrap();
        tune_tcp_with(&client, 0);
        assert_eq!(
            SockRef::from(&client).recv_buffer_size().unwrap(),
            before,
            "0 must leave SO_RCVBUF at the kernel default"
        );
        assert!(SockRef::from(&client).tcp_nodelay().unwrap(), "Nagle is off all the same");
    }

    // By Pavel Shakhmin (github.com/pshakhmin), PR #20.
    #[tokio::test]
    async fn explicit_buffer_reaches_the_kernel() {
        let (client, _server) = pair().await;
        let (untuned, _other) = pair().await;
        tune_tcp_with(&client, 128 * 1024);
        let tuned = SockRef::from(&client).recv_buffer_size().unwrap();
        let default = SockRef::from(&untuned).recv_buffer_size().unwrap();
        assert!(tuned >= default, "tuned {tuned} < default {default}");
    }
}
