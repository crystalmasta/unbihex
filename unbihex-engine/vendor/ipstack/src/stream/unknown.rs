use crate::{
    IpStackError, PacketSender, TTL,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header};
use std::net::IpAddr;

/// A stream for unknown transport layer protocols.
///
/// This type handles network packets with transport protocols that are not TCP or UDP
/// (e.g., ICMP, IGMP, ESP, etc.). It provides methods to inspect the packet details
/// and send responses.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::UnknownTransport(unknown) = ip_stack.accept().await? {
///     println!("Unknown transport protocol: {:?}", unknown.ip_protocol());
///     println!("Source: {}", unknown.src_addr());
///     println!("Destination: {}", unknown.dst_addr());
///     println!("Payload: {} bytes", unknown.payload().len());
///     
///     // Send a response
///     unknown.send(vec![0x08, 0x00, 0x00, 0x00])?;
/// }
/// # Ok(())
/// # }
/// ```
pub struct IpStackUnknownTransport {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    payload: Vec<u8>,
    protocol: IpNumber,
    mtu: u16,
    packet_sender: PacketSender,
}

impl IpStackUnknownTransport {
    pub(crate) fn new(src_addr: IpAddr, dst_addr: IpAddr, payload: Vec<u8>, ip: &IpHeader, mtu: u16, packet_sender: PacketSender) -> Self {
        let protocol = match ip {
            IpHeader::Ipv4(ip) => ip.protocol,
            IpHeader::Ipv6(ip) => ip.next_header,
        };
        IpStackUnknownTransport {
            src_addr,
            dst_addr,
            payload,
            protocol,
            mtu,
            packet_sender,
        }
    }

    /// Returns the source IP address of the packet.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUnknownTransport;
    /// # fn example(unknown: &IpStackUnknownTransport) {
    /// let src = unknown.src_addr();
    /// println!("Source: {}", src);
    /// # }
    /// ```
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    /// Returns the destination IP address of the packet.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUnknownTransport;
    /// # fn example(unknown: &IpStackUnknownTransport) {
    /// let dst = unknown.dst_addr();
    /// println!("Destination: {}", dst);
    /// # }
    /// ```
    pub fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    /// Returns the payload of the packet.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUnknownTransport;
    /// # fn example(unknown: &IpStackUnknownTransport) {
    /// let payload = unknown.payload();
    /// println!("Payload: {} bytes", payload.len());
    /// # }
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the IP protocol number of the packet.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUnknownTransport;
    /// # fn example(unknown: &IpStackUnknownTransport) {
    /// let protocol = unknown.ip_protocol();
    /// println!("Protocol: {:?}", protocol);
    /// # }
    /// ```
    pub fn ip_protocol(&self) -> IpNumber {
        self.protocol
    }

    /// Send a response packet.
    ///
    /// This method sends one or more packets with the given payload, automatically
    /// fragmenting the data if it exceeds the MTU.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload to send
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be sent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUnknownTransport;
    /// # fn example(unknown: &IpStackUnknownTransport) -> std::io::Result<()> {
    /// // Send an ICMP echo reply
    /// unknown.send(vec![0x08, 0x00, 0x00, 0x00])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(&self, mut payload: Vec<u8>) -> std::io::Result<()> {
        loop {
            let packet = self.create_rev_packet(&mut payload)?;
            self.packet_sender
                .send(packet)
                .map_err(|e| std::io::Error::other(format!("send error: {e}")))?;
            if payload.is_empty() {
                return Ok(());
            }
        }
    }

    /// Create a reverse packet for sending a response.
    ///
    /// This method creates a packet with swapped source and destination addresses,
    /// suitable for sending responses to received packets. If the payload exceeds
    /// the MTU, only a portion of the payload is consumed and included in the packet.
    ///
    /// # Arguments
    ///
    /// * `payload` - A mutable reference to the payload vector. If the payload exceeds
    ///   the MTU, data is drained from the front. Otherwise, the entire vector is taken.
    ///
    /// # Returns
    ///
    /// Returns a `NetworkPacket` with the reversed addresses and up to MTU bytes of payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be constructed.
    pub fn create_rev_packet(&self, payload: &mut Vec<u8>) -> std::io::Result<NetworkPacket> {
        match (self.dst_addr, self.src_addr) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, TTL, self.protocol, dst.octets(), src.octets()).map_err(IpStackError::from)?;
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);

                let p = if payload.len() > line_buffer as usize {
                    payload.drain(0..line_buffer as usize).collect::<Vec<u8>>()
                } else {
                    std::mem::take(payload)
                };
                ip_h.set_payload_len(p.len()).map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: Some(p),
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: self.protocol,
                    hop_limit: TTL,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);
                let p = if payload.len() > line_buffer as usize {
                    payload.drain(0..line_buffer as usize).collect::<Vec<u8>>()
                } else {
                    std::mem::take(payload)
                };
                ip_h.set_payload_length(p.len()).map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: Some(p),
                })
            }
            _ => unreachable!(),
        }
    }
}
