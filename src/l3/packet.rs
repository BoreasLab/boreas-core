use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use etherparse::{IpEcn, NetSlice, SlicedPacket, TransportSlice};

use crate::{InternalEndpoint, wire::checksum};

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
    Icmp(IcmpClass),
    Other,
    Fragment,
}

/// Classifies ICMP messages without applying IPv6's type-bit rule to IPv4.
///
/// RFC 1122 §3.2.2 and RFC 4443 §2.4 (e) forbid answering an error with an
/// error. IPv4 uses an explicit list, while IPv6 uses the high bit of the
/// type.
///
/// RFC 4443 §2.1 gives ICMPv6 a structural answer: *"Error messages are
/// identified as such by a zero in the high-order bit of the message Type field
/// value. Thus, error messages have message Types from 0 to 127."* ICMPv4 has
/// no such bit; RFC 1122 §3.2.2 names its error messages as a closed list.
/// Applying IPv6's rule to IPv4 would classify Echo Request, type 8, as an
/// error and suppress `ping -M do`, a common manual path-MTU check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpClass {
    /// An ICMPv4 error type from RFC 1122's list, or an ICMPv6 type below 128.
    Error,
    /// A request, reply, notification, or other non-error ICMP message.
    Informational,
}

/// Applies RFC 1122 §3.2.2's IPv4 error list. The gaps are intentional: IPv4
/// has no type bit that can replace the list.
fn icmpv4_class(type_u8: u8) -> IcmpClass {
    match type_u8 {
        3 | 4 | 5 | 11 | 12 => IcmpClass::Error,
        _ => IcmpClass::Informational,
    }
}

/// Applies RFC 4443 §2.1 to every possible IPv6 type, including unassigned
/// values.
fn icmpv6_class(type_u8: u8) -> IcmpClass {
    if type_u8 < 128 {
        IcmpClass::Error
    } else {
        IcmpClass::Informational
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub ecn: IpEcn,
    pub transport: Transport,
    /// The payload's location in the original packet. Storing coordinates
    /// keeps this `Copy` summary independent of the input borrow.
    pub payload_at: u16,
    pub payload_len: u16,
}

impl IngressPacket {
    /// Borrows the transport payload from the packet used for parsing.
    /// Returns `None` when the coordinates are outside the supplied bytes.
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
    /// A wire length or payload offset cannot be represented exactly in the
    /// summary type.
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
                Some(TransportSlice::Icmpv4(icmp)) => (
                    Transport::Icmp(icmpv4_class(icmp.type_u8())),
                    Some(icmp.payload()),
                ),
                Some(TransportSlice::Icmpv6(icmp)) => (
                    Transport::Icmp(icmpv6_class(icmp.type_u8())),
                    Some(icmp.payload()),
                ),
                Some(TransportSlice::Igmp(_)) | None => (Transport::Other, None),
            }
        };

        let (payload_at, payload_len) = match payload {
            // The parser returns a subslice of the original input. Keep only
            // its coordinates so the result remains copyable.
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

const IPV4_UDP_HEADER: usize = 20 + 8;
const IPV6_UDP_HEADER: usize = 40 + 8;

const MAX_IPV4_UDP_PAYLOAD: usize = u16::MAX as usize - IPV4_UDP_HEADER;
const MAX_IPV6_UDP_PAYLOAD: usize = u16::MAX as usize - 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The endpoints use different address families; no valid header can be
    /// selected without guessing.
    MixedFamilies,
    PayloadTooLarge,
    OutputTooSmall,
    /// The reported bytes are not a parseable packet and cannot be quoted.
    Unquotable,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MixedFamilies => "source and destination are different address families",
            Self::PayloadTooLarge => "payload exceeds what an IP header can describe",
            Self::OutputTooSmall => "output buffer is too small",
            Self::Unquotable => "the bytes to report on are not a packet",
        })
    }
}

impl Error for WriteError {}

/// Reports whether an oversized packet requires an explicit fragmentation failure.
///
/// IPv6 has no in-network fragmentation (RFC 8200 §4.5), so every IPv6 packet
/// answers yes; IPv4 answers from the DF bit. A malformed or truncated header
/// answers no, so no error is synthesized for bytes that were not understood.
pub fn forbids_fragmentation(packet: &[u8]) -> bool {
    match packet.first().map(|version| version >> 4) {
        Some(4) => packet.get(6).is_some_and(|flags| flags & 0x40 != 0),
        Some(6) => true,
        _ => false,
    }
}

/// Upper bounds for ICMP errors generated for an oversized packet. IPv4 uses
/// RFC 1812's 576-byte limit; IPv6 uses the minimum MTU from RFC 4443 §2.4(c).
const MAX_ICMPV4_ERROR: usize = 576;
const MAX_ICMPV6_ERROR: usize = 1280;

/// Writes an ICMP Packet Too Big message quoting `quoted`.
///
/// A packet can fit the device-facing MTU while exceeding the tunnel's inner
/// path MTU. TCP is constrained earlier by SYN MSS clamping; this error gives
/// datagram transports such as QUIC feedback to reduce their size.
pub fn write_too_big(
    out: &mut [u8],
    quoted: &[u8],
    next_hop_mtu: u16,
) -> Result<usize, WriteError> {
    write_icmp_error(out, quoted, IcmpError::TooBig { next_hop_mtu })
}

/// Writes an ICMP Time Exceeded message quoting `quoted`, whose hop count
/// ran out here (RFC 792, RFC 4443 section 3.3).
pub fn write_time_exceeded(out: &mut [u8], quoted: &[u8]) -> Result<usize, WriteError> {
    write_icmp_error(out, quoted, IcmpError::TimeExceeded)
}

/// The ICMP errors this hop generates.
#[derive(Clone, Copy)]
enum IcmpError {
    TooBig { next_hop_mtu: u16 },
    TimeExceeded,
}

/// The generated source is the quoted packet's destination. That is the peer
/// the client already knows, since the device-facing side has no router
/// address of its own to advertise.
///
/// Work is proportional to the bounded quoted length and uses no allocation
/// beyond the builder's own state.
fn write_icmp_error(out: &mut [u8], quoted: &[u8], error: IcmpError) -> Result<usize, WriteError> {
    let parsed = IngressPacket::parse(quoted).map_err(|_| WriteError::Unquotable)?;
    // IPv4 and IPv6 builders expose different concrete types, so finish each
    // family in its own match arm.
    match (parsed.destination, parsed.source) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let kind = match error {
                IcmpError::TooBig { next_hop_mtu } => {
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                            next_hop_mtu,
                        },
                    )
                }
                IcmpError::TimeExceeded => etherparse::Icmpv4Type::TimeExceeded(
                    etherparse::icmpv4::TimeExceededCode::TtlExceededInTransit,
                ),
            };
            let builder =
                etherparse::PacketBuilder::ipv4(source.octets(), destination.octets(), ICMP_TTL)
                    .icmpv4(kind);
            let quote = &quoted[..quoted.len().min(MAX_ICMPV4_ERROR - builder.size(0))];
            emit(out, builder.size(quote.len()), |mut into| {
                builder.write(&mut into, quote)
            })
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let kind = match error {
                IcmpError::TooBig { next_hop_mtu } => etherparse::Icmpv6Type::PacketTooBig {
                    mtu: u32::from(next_hop_mtu),
                },
                IcmpError::TimeExceeded => etherparse::Icmpv6Type::TimeExceeded(
                    etherparse::icmpv6::TimeExceededCode::HopLimitExceeded,
                ),
            };
            let builder =
                etherparse::PacketBuilder::ipv6(source.octets(), destination.octets(), ICMP_TTL)
                    .icmpv6(kind);
            let quote = &quoted[..quoted.len().min(MAX_ICMPV6_ERROR - builder.size(0))];
            emit(out, builder.size(quote.len()), |mut into| {
                builder.write(&mut into, quote)
            })
        }
        _ => Err(WriteError::MixedFamilies),
    }
}

/// Spends one hop (RFC 791 section 3.2, RFC 8200 section 3): the hops left
/// after this one, or `None` for a packet that is not IP. A packet arriving
/// with one hop is spent here, and `Some(0)` tells the caller to drop it and
/// say so (RFC 1812 section 4.2.2.9). The IPv4 header checksum is updated
/// in place (RFC 1624).
pub fn spend_hop(packet: &mut [u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let left = packet[8].saturating_sub(1);
            if left == 0 {
                return Some(0);
            }
            packet[8] = left;
            // The (TTL, protocol) word fell by 0x0100: the complement sum
            // rises by the same, carried end around.
            let check = u32::from(u16::from_be_bytes([packet[10], packet[11]])) + 0x0100;
            let check = (check & 0xffff) + (check >> 16);
            packet[10..12].copy_from_slice(&(check as u16).to_be_bytes());
            Some(left)
        }
        6 if packet.len() >= 40 => {
            let left = packet[7].saturating_sub(1);
            if left > 0 {
                packet[7] = left;
            }
            Some(left)
        }
        _ => None,
    }
}

/// Restricts a builder to the output prefix it reported before writing.
fn emit(
    out: &mut [u8],
    len: usize,
    write: impl FnOnce(&mut [u8]) -> Result<(), etherparse::err::packet::BuildWriteError>,
) -> Result<usize, WriteError> {
    let into = out.get_mut(..len).ok_or(WriteError::OutputTooSmall)?;
    write(into).map_err(|_| WriteError::OutputTooSmall)?;
    Ok(len)
}

/// Default hop limit for locally generated ICMP errors.
const ICMP_TTL: u8 = 64;

/// Returns the complete datagram size for a payload of `payload_len` bytes.
pub fn udp_datagram_len(family: IpAddr, payload_len: usize) -> usize {
    let header = match family {
        IpAddr::V4(_) => IPV4_UDP_HEADER,
        IpAddr::V6(_) => IPV6_UDP_HEADER,
    };
    header + payload_len
}

/// Writes an IP header, UDP header, and payload into `out`.
///
/// This is the packet-writing counterpart to [`IngressPacket::parse`]. It
/// computes complete IP and UDP checksums, including the optional IPv4 UDP
/// checksum, because the datagram has no prior checksum to update.
///
/// It runs in O(payload length) time without allocation.
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

/// Encodes RFC 768's zero-checksum escape: computed zero is sent as `0xffff`,
/// while wire zero means that no checksum was computed.
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
