//! Which application owns a connection, by its local port (developer mode's
//! connection journal): Windows — the TCP/UDP owner tables; Linux — `/proc`;
//! macOS — unknown.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::devlog::{OwnerLookup, OwnerQuery};

/// This platform's owner lookup, if it has one.
pub fn owner_lookup() -> Option<Arc<dyn OwnerLookup>> {
    #[cfg(any(windows, target_os = "linux"))]
    return Some(Arc::new(Owners::default()));
    #[cfg(not(any(windows, target_os = "linux")))]
    None
}

/// Sockets by (udp, local port): their local addresses and owners (a PID on
/// Windows, a socket inode on Linux).
type Table = HashMap<(bool, u16), Vec<(IpAddr, u64)>>;

/// Picks the socket bound to `ip` itself, else to any address, else any.
fn pick(rows: &[(IpAddr, u64)], ip: IpAddr) -> Option<u64> {
    let ip = ip.to_canonical();
    rows.iter()
        .find(|(a, _)| a.to_canonical() == ip)
        .or_else(|| rows.iter().find(|(a, _)| a.is_unspecified()))
        .or_else(|| rows.first())
        .map(|(_, o)| *o)
}

#[derive(Default)]
struct Owners {
    names: parking_lot::Mutex<HashMap<u64, Option<String>>>,
}

impl OwnerLookup for Owners {
    fn owners(&self, queries: &[OwnerQuery]) -> Vec<Option<String>> {
        let table = os::table(queries.iter().any(|q| !q.udp), queries.iter().any(|q| q.udp));
        let ids: Vec<Option<u64>> = queries
            .iter()
            .map(|q| table.get(&(q.udp, q.src.port())).and_then(|rows| pick(rows, q.src.ip())))
            .collect();
        let mut names = self.names.lock();
        // PIDs and inodes are reused: the cache lives for one call on Linux.
        if cfg!(target_os = "linux") || names.len() > 4096 {
            names.clear();
        }
        let missing: Vec<u64> = ids.iter().flatten().filter(|id| !names.contains_key(id)).copied().collect();
        for (id, name) in os::names(&missing) {
            names.insert(id, name);
        }
        ids.iter().map(|id| id.and_then(|id| names.get(&id).cloned().flatten())).collect()
    }
}

#[cfg(windows)]
mod os {
    use super::Table;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    /// One owner table (`dwNumEntries` then the rows), 8-byte aligned.
    #[allow(unsafe_code)]
    fn fetch(udp: bool, af: u32) -> Option<Vec<u64>> {
        let mut size = 0u32;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            let ptr = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() };
            // SAFETY: `ptr` is null with `size` 0, or a buffer of at least `size` bytes.
            let rc = unsafe {
                if udp {
                    GetExtendedUdpTable(ptr, &mut size, 0, af, UDP_TABLE_OWNER_PID, 0)
                } else {
                    GetExtendedTcpTable(ptr, &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
                }
            };
            match rc {
                0 if !buf.is_empty() => return Some(buf),
                0 => return None,
                ERROR_INSUFFICIENT_BUFFER => buf = vec![0u64; (size as usize).div_ceil(8) + 64],
                _ => return None,
            }
        }
        None
    }

    /// The rows of a fetched table.
    #[allow(unsafe_code)]
    fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
        let bytes = std::mem::size_of_val(buf);
        let n = buf.first().map_or(0, |w| (*w & 0xffff_ffff) as usize);
        // The rows follow the u32 count, aligned to the row type (at most 4 here).
        let offset = std::mem::align_of::<T>().max(4);
        if offset + n * std::mem::size_of::<T>() > bytes {
            return Vec::new();
        }
        // SAFETY: the buffer holds `n` rows of `T` (plain old data) at `offset`,
        // checked against its length above.
        unsafe {
            let first = buf.as_ptr().cast::<u8>().add(offset).cast::<T>();
            (0..n).map(|i| std::ptr::read_unaligned(first.add(i))).collect()
        }
    }

    fn port(p: u32) -> u16 {
        u16::from_be((p & 0xffff) as u16)
    }

    pub(super) fn table(tcp: bool, udp: bool) -> Table {
        let mut t = Table::new();
        let mut add = |udp: bool, ip: IpAddr, p: u32, pid: u32| t.entry((udp, port(p))).or_default().push((ip, u64::from(pid)));
        if tcp {
            if let Some(b) = fetch(false, AF_INET) {
                for r in rows::<MIB_TCPROW_OWNER_PID>(&b) {
                    add(false, IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))), r.dwLocalPort, r.dwOwningPid);
                }
            }
            if let Some(b) = fetch(false, AF_INET6) {
                for r in rows::<MIB_TCP6ROW_OWNER_PID>(&b) {
                    add(false, IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), r.dwLocalPort, r.dwOwningPid);
                }
            }
        }
        if udp {
            if let Some(b) = fetch(true, AF_INET) {
                for r in rows::<MIB_UDPROW_OWNER_PID>(&b) {
                    add(true, IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))), r.dwLocalPort, r.dwOwningPid);
                }
            }
            if let Some(b) = fetch(true, AF_INET6) {
                for r in rows::<MIB_UDP6ROW_OWNER_PID>(&b) {
                    add(true, IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), r.dwLocalPort, r.dwOwningPid);
                }
            }
        }
        t
    }

    /// Executable names of the PIDs.
    #[allow(unsafe_code)]
    pub(super) fn names(pids: &[u64]) -> Vec<(u64, Option<String>)> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        };
        pids.iter()
            .map(|&pid| {
                let name = match pid {
                    0 => Some("System Idle".to_string()),
                    4 => Some("System".to_string()),
                    _ => {
                        // SAFETY: plain calls with a live buffer; the handle is closed.
                        unsafe {
                            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
                            if h.is_null() {
                                None
                            } else {
                                let mut buf = [0u16; 1024];
                                let mut len = buf.len() as u32;
                                let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
                                CloseHandle(h);
                                (ok != 0).then(|| {
                                    let path = String::from_utf16_lossy(&buf[..len as usize]);
                                    path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string()
                                })
                            }
                        }
                    }
                };
                (pid, name)
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::Table;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// `0100007F:1F90` → (127.0.0.1, 8080).
    pub(super) fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
        let (ip, port) = s.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let ip = match ip.len() {
            8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_le_bytes())),
            32 => {
                let mut b = [0u8; 16];
                for (i, chunk) in b.chunks_mut(4).enumerate() {
                    let word = u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16).ok()?;
                    chunk.copy_from_slice(&word.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return None,
        };
        Some((ip, port))
    }

    pub(super) fn table(tcp: bool, udp: bool) -> Table {
        let mut t = Table::new();
        let files = [("tcp", false), ("tcp6", false), ("udp", true), ("udp6", true)];
        for (file, is_udp) in files {
            if (is_udp && !udp) || (!is_udp && !tcp) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(format!("/proc/net/{file}")) else { continue };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                let (Some(local), Some(inode)) = (cols.get(1), cols.get(9)) else { continue };
                let (Some((ip, port)), Ok(inode)) = (parse_addr(local), inode.parse::<u64>()) else { continue };
                if inode != 0 {
                    t.entry((is_udp, port)).or_default().push((ip, inode));
                }
            }
        }
        t
    }

    /// Process names of the socket inodes: the `/proc/<pid>/fd` links that
    /// point at them (other users' processes need root).
    pub(super) fn names(inodes: &[u64]) -> Vec<(u64, Option<String>)> {
        let mut found: HashMap<u64, String> = HashMap::new();
        if !inodes.is_empty()
            && let Ok(procs) = std::fs::read_dir("/proc")
        {
            'procs: for p in procs.flatten() {
                let pid = p.file_name();
                let Some(pid) = pid.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
                let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
                for fd in fds.flatten() {
                    let Ok(link) = std::fs::read_link(fd.path()) else { continue };
                    let link = link.to_string_lossy();
                    let Some(inode) = link.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) else { continue };
                    let Ok(inode) = inode.parse::<u64>() else { continue };
                    if inodes.contains(&inode) && !found.contains_key(&inode) {
                        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                        found.insert(inode, comm.trim().to_string());
                        if found.len() == inodes.len() {
                            break 'procs;
                        }
                    }
                }
            }
        }
        inodes.iter().map(|i| (*i, found.get(i).cloned().filter(|n| !n.is_empty()))).collect()
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod os {
    use super::Table;
    pub(super) fn table(_tcp: bool, _udp: bool) -> Table {
        Table::new()
    }
    pub(super) fn names(ids: &[u64]) -> Vec<(u64, Option<String>)> {
        ids.iter().map(|i| (*i, None)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_on_the_address_itself_wins() {
        let rows = vec![("0.0.0.0".parse().unwrap(), 1), ("10.0.0.1".parse().unwrap(), 2), ("127.0.0.1".parse().unwrap(), 3)];
        assert_eq!(pick(&rows, "127.0.0.1".parse().unwrap()), Some(3));
        assert_eq!(pick(&rows, "::ffff:10.0.0.1".parse().unwrap()), Some(2));
        assert_eq!(pick(&rows, "192.168.1.1".parse().unwrap()), Some(1));
        assert_eq!(pick(&[], "192.168.1.1".parse().unwrap()), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_addresses_parse() {
        assert_eq!(os::parse_addr("0100007F:1F90"), Some(("127.0.0.1".parse().unwrap(), 8080)));
        assert_eq!(
            os::parse_addr("00000000000000000000000001000000:0050"),
            Some(("::1".parse().unwrap(), 80))
        );
    }

    /// This process's own listening socket is found by its port.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn own_sockets_are_found() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let q = OwnerQuery { udp: false, src: addr, dst: None };
        let name = owner_lookup().unwrap().owners(&[q]).remove(0);
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy().to_string();
        let name = name.unwrap();
        assert!(exe.starts_with(&name) || name.starts_with(&exe[..exe.len().min(15)]), "{name} vs {exe}");
    }
}
