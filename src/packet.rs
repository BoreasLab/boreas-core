use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use etherparse::{IpEcn, NetSlice, SlicedPacket, TransportSlice};

use crate::{InternalEndpoint, path::checksum};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        source_port: u16,
        destination_port: u16,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
    },
    Icmp,
    Other,
    Fragment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub ecn: IpEcn,
    pub transport: Transport,
    /// Where the transport payload begins in the parsed buffer, and how long
    /// it is.
    ///
    /// An offset rather than a slice, because this is a `Copy` summary that
    /// deliberately outlives the borrow it came from; a caller still holding
    /// the bytes indexes with it, and one that does not cannot. Zero-length
    /// for the transports that have no payload this parser names.
    pub payload_at: u16,
    pub payload_len: u16,
}

impl IngressPacket {
    /// The transport payload, given the very bytes this packet was parsed
    /// from. `None` when `packet` is not those bytes.
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let at = usize::from(self.payload_at);
        packet.get(at..at + usize::from(self.payload_len))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    Malformed(etherparse::err::packet::SliceError),
    MissingNetworkLayer,
    UnsupportedNetworkLayer,
    /// A packet larger than an IP header can describe. Unreachable from the
    /// wire — the length fields are 16 bits — and refused rather than
    /// truncated so the offsets in `IngressPacket` are always exact.
    Oversized,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed packet: {error}"),
            Self::MissingNetworkLayer => f.write_str("packet has no network layer"),
            Self::UnsupportedNetworkLayer => f.write_str("unsupported network layer"),
            Self::Oversized => f.write_str("packet exceeds what an IP header can describe"),
        }
    }
}

impl Error for PacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::MissingNetworkLayer | Self::UnsupportedNetworkLayer | Self::Oversized => None,
        }
    }
}

impl IngressPacket {
    pub fn parse(packet: &[u8]) -> Result<Self, PacketError> {
        let sliced = SlicedPacket::from_ip(packet).map_err(PacketError::Malformed)?;
        let net = sliced.net.ok_or(PacketError::MissingNetworkLayer)?;

        let (source, destination, ecn, fragmented) = match net {
            NetSlice::Ipv4(ipv4) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
                ipv4.header().ecn(),
                ipv4.is_payload_fragmented(),
            ),
            NetSlice::Ipv6(ipv6) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
                ipv6.header().ecn(),
                ipv6.is_payload_fragmented(),
            ),
            NetSlice::Arp(_) => return Err(PacketError::UnsupportedNetworkLayer),
        };

        let (transport, payload) = if fragmented {
            (Transport::Fragment, None)
        } else {
            match sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => (
                    Transport::Tcp {
                        source_port: tcp.source_port(),
                        destination_port: tcp.destination_port(),
                    },
                    Some(tcp.payload()),
                ),
                Some(TransportSlice::Udp(udp)) => (
                    Transport::Udp {
                        source_port: udp.source_port(),
                        destination_port: udp.destination_port(),
                    },
                    Some(udp.payload()),
                ),
                Some(TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_)) => {
                    (Transport::Icmp, None)
                }
                Some(TransportSlice::Igmp(_)) | None => (Transport::Other, None),
            }
        };

        let (payload_at, payload_len) = match payload {
            // `payload` is a subslice of `packet`, so the difference of their
            // start addresses is its offset. Both fit a `u16` for any packet an
            // IP header can describe.
            Some(payload) => (
                u16::try_from(payload.as_ptr() as usize - packet.as_ptr() as usize)
                    .map_err(|_| PacketError::Oversized)?,
                u16::try_from(payload.len()).map_err(|_| PacketError::Oversized)?,
            ),
            None => (0, 0),
        };

        Ok(Self {
            source,
            destination,
            ecn,
            transport,
            payload_at,
            payload_len,
        })
    }
}

/// Bytes of IP and UDP header, per family.
const IPV4_UDP_HEADER: usize = 20 + 8;
const IPV6_UDP_HEADER: usize = 40 + 8;

/// The largest payload each family's headers leave room for inside the
/// 16-bit length fields.
const MAX_IPV4_UDP_PAYLOAD: usize = u16::MAX as usize - IPV4_UDP_HEADER;
const MAX_IPV6_UDP_PAYLOAD: usize = u16::MAX as usize - 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The endpoints are not of the same address family. Unreachable for a
    /// reply built from one received packet, and an error rather than a guess
    /// because there is no correct guess.
    MixedFamilies,
    PayloadTooLarge,
    OutputTooSmall,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MixedFamilies => "source and destination are different address families",
            Self::PayloadTooLarge => "payload exceeds what an IP header can describe",
            Self::OutputTooSmall => "output buffer is too small",
        })
    }
}

impl Error for WriteError {}

/// The number of bytes [`write_udp`] needs for `payload_len` payload bytes.
pub fn udp_datagram_len(family: IpAddr, payload_len: usize) -> usize {
    let header = match family {
        IpAddr::V4(_) => IPV4_UDP_HEADER,
        IpAddr::V6(_) => IPV6_UDP_HEADER,
    };
    header + payload_len
}

/// Writes one whole UDP datagram — IP header, UDP header, payload — into
/// `out`, returning its length.
///
/// The dual of [`IngressPacket::parse`], and the only place this crate
/// originates a packet rather than forwarding one. Checksums are computed in
/// full: a locally synthesized datagram has no incremental predecessor to
/// adjust from, and the UDP checksum is written for IPv4 as well as IPv6 even
/// though IPv4 permits omitting it, because a stub resolver behind a
/// middlebox is exactly the client that will notice a zero.
///
/// O(payload length), and allocation-free.
pub fn write_udp(
    out: &mut [u8],
    source: InternalEndpoint,
    destination: InternalEndpoint,
    payload: &[u8],
) -> Result<usize, WriteError> {
    match (source.address, destination.address) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => write_udp_v4(
            out,
            (source_ip, source.port),
            (destination_ip, destination.port),
            payload,
        ),
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => write_udp_v6(
            out,
            (source_ip, source.port),
            (destination_ip, destination.port),
            payload,
        ),
        _ => Err(WriteError::MixedFamilies),
    }
}

fn write_udp_v4(
    out: &mut [u8],
    source: (Ipv4Addr, u16),
    destination: (Ipv4Addr, u16),
    payload: &[u8],
) -> Result<usize, WriteError> {
    if payload.len() > MAX_IPV4_UDP_PAYLOAD {
        return Err(WriteError::PayloadTooLarge);
    }
    let total = IPV4_UDP_HEADER + payload.len();
    let datagram = out.get_mut(..total).ok_or(WriteError::OutputTooSmall)?;
    datagram.fill(0);

    datagram[0] = 0x45; // IPv4, five 32-bit words of header, no options
    datagram[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // Don't Fragment: this datagram is built to fit the tunnel we chose.
    datagram[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    datagram[8] = 64; // hop budget
    datagram[9] = UDP_PROTOCOL;
    datagram[12..16].copy_from_slice(&source.0.octets());
    datagram[16..20].copy_from_slice(&destination.0.octets());
    let header_sum = checksum(&[&datagram[..20]]);
    datagram[10..12].copy_from_slice(&header_sum.to_be_bytes());

    write_udp_header(&mut datagram[20..], source.1, destination.1, payload);
    let udp_len = (8 + payload.len()) as u16;
    let sum = checksum(&[
        &source.0.octets(),
        &destination.0.octets(),
        &[0, UDP_PROTOCOL],
        &udp_len.to_be_bytes(),
        &datagram[20..],
    ]);
    datagram[26..28].copy_from_slice(&transmitted_checksum(sum));
    Ok(total)
}

fn write_udp_v6(
    out: &mut [u8],
    source: (Ipv6Addr, u16),
    destination: (Ipv6Addr, u16),
    payload: &[u8],
) -> Result<usize, WriteError> {
    if payload.len() > MAX_IPV6_UDP_PAYLOAD {
        return Err(WriteError::PayloadTooLarge);
    }
    let total = IPV6_UDP_HEADER + payload.len();
    let datagram = out.get_mut(..total).ok_or(WriteError::OutputTooSmall)?;
    datagram.fill(0);

    datagram[0] = 0x60; // IPv6, no traffic class or flow label
    let udp_len = (8 + payload.len()) as u16;
    datagram[4..6].copy_from_slice(&udp_len.to_be_bytes());
    datagram[6] = UDP_PROTOCOL;
    datagram[7] = 64; // hop budget
    datagram[8..24].copy_from_slice(&source.0.octets());
    datagram[24..40].copy_from_slice(&destination.0.octets());

    write_udp_header(&mut datagram[40..], source.1, destination.1, payload);
    let sum = checksum(&[
        &source.0.octets(),
        &destination.0.octets(),
        &u32::from(udp_len).to_be_bytes(),
        &[0, 0, 0, UDP_PROTOCOL],
        &datagram[40..],
    ]);
    datagram[46..48].copy_from_slice(&transmitted_checksum(sum));
    Ok(total)
}

const UDP_PROTOCOL: u8 = 17;

fn write_udp_header(out: &mut [u8], source_port: u16, destination_port: u16, payload: &[u8]) {
    out[0..2].copy_from_slice(&source_port.to_be_bytes());
    out[2..4].copy_from_slice(&destination_port.to_be_bytes());
    out[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out[6..8].fill(0);
    out[8..].copy_from_slice(payload);
}

/// RFC 768: a computed UDP checksum of zero is transmitted as all ones,
/// because zero on the wire is the sentinel for "not computed".
fn transmitted_checksum(sum: u16) -> [u8; 2] {
    if sum == 0 {
        [0xff, 0xff]
    } else {
        sum.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_complete_packets_and_quarantines_fragments() {
        let ipv4_udp = [
            0x45, 0x03, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];
        assert_eq!(
            IngressPacket::parse(&ipv4_udp).map(|packet| (
                packet.source,
                packet.destination,
                packet.ecn,
                packet.transport,
            )),
            Ok((
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                IpEcn::CongestionExperienced,
                Transport::Udp {
                    source_port: 1234,
                    destination_port: 53,
                },
            ))
        );

        let mut ipv4_fragment = ipv4_udp;
        ipv4_fragment[6] = 0x20;
        assert_eq!(
            IngressPacket::parse(&ipv4_fragment).map(|packet| packet.transport),
            Ok(Transport::Fragment)
        );

        let mut ipv6_tcp = [0_u8; 60];
        ipv6_tcp[0] = 0x60;
        ipv6_tcp[4..6].copy_from_slice(&20_u16.to_be_bytes());
        ipv6_tcp[6] = 6;
        ipv6_tcp[7] = 64;
        ipv6_tcp[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6_tcp[24..40].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        ipv6_tcp[40..42].copy_from_slice(&443_u16.to_be_bytes());
        ipv6_tcp[42..44].copy_from_slice(&50_000_u16.to_be_bytes());
        ipv6_tcp[52] = 0x50;
        assert_eq!(
            IngressPacket::parse(&ipv6_tcp).map(|packet| packet.transport),
            Ok(Transport::Tcp {
                source_port: 443,
                destination_port: 50_000,
            })
        );

        assert!(matches!(
            IngressPacket::parse(&[0x45]),
            Err(PacketError::Malformed(_))
        ));
    }
}
