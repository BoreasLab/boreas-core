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
    Icmp(IcmpClass),
    Other,
    Fragment,
}

/// Whether an ICMP message reports a failure or asks a question.
///
/// It exists for one rule — RFC 1122 §3.2.2 and RFC 4443 §2.4 (e) both forbid
/// answering an error with an error — and **the two families decide it
/// differently, which is the trap this type exists to close.**
///
/// RFC 4443 §2.1 gives ICMPv6 a structural answer: *"Error messages are
/// identified as such by a zero in the high-order bit of the message Type field
/// value. Thus, error messages have message Types from 0 to 127."* ICMPv4 has
/// no such bit and never did; RFC 1122 §3.2.2 names its error messages as a
/// closed list instead. Applying IPv6's rule to IPv4 would read Echo Request —
/// type 8 — as an error and silently stop answering `ping -M do`, which is one
/// of the few things a user can run to discover a path MTU by hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpClass {
    /// Destination Unreachable, Redirect, Source Quench, Time Exceeded,
    /// Parameter Problem, and every ICMPv6 type below 128.
    Error,
    /// Echo, Timestamp, Address Mask, Router and Neighbor Discovery — anything
    /// that is a question rather than a complaint.
    Informational,
}

/// RFC 1122 §3.2.2's list, verbatim: Destination Unreachable (3), Source Quench
/// (4), Redirect (5), Time Exceeded (11), Parameter Problem (12). A list, not a
/// range, because IPv4 has no bit that says so.
fn icmpv4_class(type_u8: u8) -> IcmpClass {
    match type_u8 {
        3 | 4 | 5 | 11 | 12 => IcmpClass::Error,
        _ => IcmpClass::Informational,
    }
}

/// RFC 4443 §2.1: the high-order bit of the type *is* the classification, so
/// this is total over all 256 values and stays correct for types IANA has not
/// assigned yet.
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
    /// An ICMP error was asked for about bytes that are not a packet. There is
    /// nothing to quote and therefore nothing the sender could authenticate.
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

/// Whether the sender forbade fragmentation, and so must be told when a packet
/// does not fit rather than have it silently disappear.
///
/// IPv6 has no in-network fragmentation at all (RFC 8200 §4.5), so every IPv6
/// packet answers yes; IPv4 answers on the DF bit. A malformed or truncated
/// header answers no, which forwards the packet to whatever will reject it
/// properly instead of synthesizing an error about bytes this did not
/// understand.
pub fn forbids_fragmentation(packet: &[u8]) -> bool {
    match packet.first().map(|version| version >> 4) {
        Some(4) => packet.get(6).is_some_and(|flags| flags & 0x40 != 0),
        Some(6) => true,
        _ => false,
    }
}

/// The largest ICMP error each family may be, so the message that reports a
/// path is never itself too big for it. RFC 1812 §4.3.2.3 asks for as much of
/// the original as fits in 576 bytes; RFC 4443 §2.4 (c) caps at the IPv6
/// minimum MTU.
const MAX_ICMPV4_ERROR: usize = 576;
const MAX_ICMPV6_ERROR: usize = 1280;

/// Writes an ICMP Packet Too Big for `quoted`, offering `next_hop_mtu`.
///
/// **The one error this crate originates.** A client's TUN is as wide as the
/// session's path MTU, the tunnel is narrower by the egress's overhead, and a
/// packet in between is one the client may legitimately send and this session
/// cannot carry. TCP never reaches it — its MSS was clamped on the SYN — so
/// what this serves is QUIC, which sets DF and discovers its path by exactly
/// this message (RFC 8899). Dropping instead is a black hole the sender has no
/// way to see.
///
/// **The source address is the quoted packet's own destination.** A router
/// would use its own interface address; Boreas has no address on the client's
/// link to use. Every stack authenticates one of these by the packet it quotes
/// rather than by who sent it (RFC 1122 §4.2.3.9 for TCP, RFC 8899 §4.6.2 for
/// datagram transports), so quoting is what makes it credible, and a source
/// the client was already talking to is the one that cannot be mistaken for a
/// different path.
///
/// O(quoted length), bounded by the family's ceiling above, and allocation-free
/// apart from the builder's own.
pub fn write_too_big(
    out: &mut [u8],
    quoted: &[u8],
    next_hop_mtu: u16,
) -> Result<usize, WriteError> {
    let parsed = IngressPacket::parse(quoted).map_err(|_| WriteError::Unquotable)?;
    // The two builders are different types with the same shape, so each arm
    // finishes its own message rather than being unified through a trait that
    // exists nowhere but here.
    match (parsed.destination, parsed.source) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let builder =
                etherparse::PacketBuilder::ipv4(source.octets(), destination.octets(), ICMP_TTL)
                    .icmpv4(etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                            next_hop_mtu,
                        },
                    ));
            let quote = &quoted[..quoted.len().min(MAX_ICMPV4_ERROR - builder.size(0))];
            emit(out, builder.size(quote.len()), |mut into| {
                builder.write(&mut into, quote)
            })
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let builder =
                etherparse::PacketBuilder::ipv6(source.octets(), destination.octets(), ICMP_TTL)
                    .icmpv6(etherparse::Icmpv6Type::PacketTooBig {
                        mtu: u32::from(next_hop_mtu),
                    });
            let quote = &quoted[..quoted.len().min(MAX_ICMPV6_ERROR - builder.size(0))];
            emit(out, builder.size(quote.len()), |mut into| {
                builder.write(&mut into, quote)
            })
        }
        _ => Err(WriteError::MixedFamilies),
    }
}

/// Runs one builder's `write` against exactly the prefix of `out` it claimed,
/// so a builder that wrote a different length than it reported cannot go
/// unnoticed and cannot scribble past what the caller offered.
fn emit(
    out: &mut [u8],
    len: usize,
    write: impl FnOnce(&mut [u8]) -> Result<(), etherparse::err::packet::BuildWriteError>,
) -> Result<usize, WriteError> {
    let into = out.get_mut(..len).ok_or(WriteError::OutputTooSmall)?;
    write(into).map_err(|_| WriteError::OutputTooSmall)?;
    Ok(len)
}

/// Hop limit on a locally originated ICMP error. 64 is the IANA-recommended
/// default and what every host stack writes.
const ICMP_TTL: u8 = 64;

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
