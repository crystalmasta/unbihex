use crate::error::IpStackError;
use etherparse::{Ipv4Header, Ipv6Header, NetSlice, SlicedPacket, TcpHeader, UdpHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: bool,
}

impl NetworkTuple {
    pub fn new(src: SocketAddr, dst: SocketAddr, tcp: bool) -> Self {
        NetworkTuple { src, dst, tcp }
    }
}

impl std::fmt::Display for NetworkTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tcp = if self.tcp { "TCP" } else { "UDP" };
        write!(f, "{} {} -> {}", tcp, self.src, self.dst)
    }
}

pub mod tcp_flags {
    pub const CWR: u8 = 0b10000000;
    pub const ECE: u8 = 0b01000000;
    pub const URG: u8 = 0b00100000;
    pub const ACK: u8 = 0b00010000;
    pub const PSH: u8 = 0b00001000;
    pub const RST: u8 = 0b00000100;
    pub const SYN: u8 = 0b00000010;
    pub const FIN: u8 = 0b00000001;
}

#[derive(Debug, Clone)]
pub(crate) enum IpHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

#[derive(Debug, Clone)]
pub(crate) enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub(crate) ip: IpHeader,
    pub(crate) transport: TransportHeader,
    pub(crate) payload: Option<Vec<u8>>,
}

impl NetworkPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, IpStackError> {
        let p = SlicedPacket::from_ip(buf).map_err(|_| IpStackError::InvalidPacket)?;
        let ip = p.net.ok_or(IpStackError::InvalidPacket)?;

        let (ip, ip_payload) = match ip {
            NetSlice::Ipv4(ip) => (IpHeader::Ipv4(ip.header().to_header()), ip.payload().payload),
            NetSlice::Ipv6(ip) => (IpHeader::Ipv6(ip.header().to_header()), ip.payload().payload),
            NetSlice::Arp(_) => return Err(IpStackError::UnsupportedTransportProtocol),
        };
        let (transport, payload) = match p.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => (TransportHeader::Tcp(h.to_header()), h.payload()),
            Some(etherparse::TransportSlice::Udp(u)) => (TransportHeader::Udp(u.to_header()), u.payload()),
            _ => (TransportHeader::Unknown, ip_payload),
        };
        let payload = if payload.is_empty() { None } else { Some(payload.to_vec()) };

        Ok(NetworkPacket { ip, transport, payload })
    }
    pub(crate) fn transport_header(&self) -> &TransportHeader {
        &self.transport
    }
    pub fn src_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.source_port,
            TransportHeader::Tcp(tcp) => tcp.source_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.source)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.source)), port),
        }
    }
    pub fn dst_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.destination_port,
            TransportHeader::Tcp(tcp) => tcp.destination_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.destination)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.destination)), port),
        }
    }
    pub fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.src_addr(),
            dst: self.dst_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn reverse_network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.dst_addr(),
            dst: self.src_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, IpStackError> {
        let mut buf = Vec::new();
        match self.ip {
            IpHeader::Ipv4(ref ip) => ip.write(&mut buf)?,
            IpHeader::Ipv6(ref ip) => ip.write(&mut buf)?,
        }
        match self.transport {
            TransportHeader::Tcp(ref h) => h.write(&mut buf)?,
            TransportHeader::Udp(ref h) => h.write(&mut buf)?,
            _ => {}
        };

        if let Some(payload) = &self.payload {
            buf.extend_from_slice(payload);
        }
        Ok(buf)
    }
    pub fn ttl(&self) -> u8 {
        match &self.ip {
            IpHeader::Ipv4(ip) => ip.time_to_live,
            IpHeader::Ipv6(ip) => ip.hop_limit,
        }
    }
}

pub fn tcp_header_fmt(header: &TcpHeader) -> String {
    let mut flags = String::new();
    if header.cwr {
        flags.push_str("CWR ");
    }
    if header.ece {
        flags.push_str("ECE ");
    }
    if header.urg {
        flags.push_str("URG ");
    }
    if header.ack {
        flags.push_str("ACK ");
    }
    if header.psh {
        flags.push_str("PSH ");
    }
    if header.rst {
        flags.push_str("RST ");
    }
    if header.syn {
        flags.push_str("SYN ");
    }
    if header.fin {
        flags.push_str("FIN ");
    }
    format!(
        "TcpHeader {{ seq: {}, ack: {}, flags: {} }}",
        header.sequence_number,
        header.acknowledgment_number,
        flags.trim()
    )
}

pub fn tcp_header_flags(inner: &TcpHeader) -> u8 {
    let mut flags = 0;
    if inner.cwr {
        flags |= tcp_flags::CWR;
    }
    if inner.ece {
        flags |= tcp_flags::ECE;
    }
    if inner.urg {
        flags |= tcp_flags::URG;
    }
    if inner.ack {
        flags |= tcp_flags::ACK;
    }
    if inner.psh {
        flags |= tcp_flags::PSH;
    }
    if inner.rst {
        flags |= tcp_flags::RST;
    }
    if inner.syn {
        flags |= tcp_flags::SYN;
    }
    if inner.fin {
        flags |= tcp_flags::FIN;
    }

    flags
}

// pub struct UdpPacket {
//     header: UdpHeader,
// }

// impl UdpPacket {
//     pub fn inner(&self) -> &UdpHeader {
//         &self.header
//     }
// }

// impl From<&UdpHeader> for UdpPacket {
//     fn from(header: &UdpHeader) -> Self {
//         UdpPacket {
//             header: header.clone(),
//         }
//     }
// }

#[cfg(test)]
pub mod tests {
    use super::*;
    use criterion::Criterion;
    use rand::random;
    use std::time::Duration;

    fn create_raw_packet(mtu: usize) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4(random(), random(), random())
            .tcp(random(), random(), random(), random())
            .fin()
            .psh()
            .ack(random());

        let payload_len = mtu - builder.size(0);
        assert_eq!(mtu, builder.size(payload_len));
        let payload: Vec<u8> = (0..payload_len).map(|_| random()).collect();

        let mut buf = Vec::new();
        builder.write(&mut buf, &payload[..]).unwrap();
        assert_eq!(mtu, buf.len());
        buf
    }

    fn create_packet(mtu: usize) -> NetworkPacket {
        let packet = create_raw_packet(mtu);
        NetworkPacket::parse(packet.as_slice()).unwrap()
    }

    fn benchmarks(c: &mut Criterion) {
        for mtu in [64, 1500, 4096, 16384, 65515] {
            let buf = create_raw_packet(mtu);
            c.bench_function(format!("decode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = std::hint::black_box(&buf[..]);
                    let _packet = NetworkPacket::parse(packet).unwrap();
                })
            });
        }

        for mtu in [64, 1500, 4096, 16384, 65515] {
            let packet = create_packet(mtu);
            c.bench_function(format!("encode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = std::hint::black_box(&packet);
                    let _packet = packet.to_bytes();
                })
            });
        }
    }

    #[test]
    fn bench() {
        // `cargo test --profile bench -j1 -- --nocapture bench -- <benchmark_filter>
        // This workaround allows benchmarking private interfaces with `criterion` in stable rust.
        let args: Vec<String> = std::env::args().collect();
        let filter = args
            .windows(3)
            .filter(|p| p.len() >= 2 && p[0].ends_with("bench") && p[1] == "--")
            .map(|s| s.get(2).unwrap_or(&"".to_string()).clone())
            .next();
        let filter = match filter {
            Some(f) => f,
            None => return,
        };
        let profile_time = args
            .windows(2)
            .filter(|p| p.len() == 2 && p[0] == "--profile-time")
            .map(|s| s[1].as_str())
            .next();

        let mut c = Criterion::default()
            .with_output_color(true)
            .without_plots()
            .with_filter(filter)
            .warm_up_time(Duration::from_secs_f32(0.5))
            .measurement_time(Duration::from_secs_f32(0.5))
            .profile_time(profile_time.map(|s| Duration::from_secs_f32(s.parse().unwrap())));

        benchmarks(&mut c);

        Criterion::default().final_summary();
    }
}
