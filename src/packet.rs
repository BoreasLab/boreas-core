use std::net::IpAddr;

use etherparse::{IpEcn, NetSlice, SlicedPacket, TransportSlice};

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
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    Malformed(etherparse::err::packet::SliceError),
    MissingNetworkLayer,
    UnsupportedNetworkLayer,
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

        let transport = if fragmented {
            Transport::Fragment
        } else {
            match sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => Transport::Tcp {
                    source_port: tcp.source_port(),
                    destination_port: tcp.destination_port(),
                },
                Some(TransportSlice::Udp(udp)) => Transport::Udp {
                    source_port: udp.source_port(),
                    destination_port: udp.destination_port(),
                },
                Some(TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_)) => Transport::Icmp,
                Some(TransportSlice::Igmp(_)) | None => Transport::Other,
            }
        };

        Ok(Self {
            source,
            destination,
            ecn,
            transport,
        })
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
