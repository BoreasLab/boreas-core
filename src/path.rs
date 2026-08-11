//! Path MTU handling: TCP MSS clamping on SYN, and authentication of inbound
//! ICMP Packet Too Big messages against known flows.

use crate::{IngressPacket, InternalEndpoint, MIN_QUIC_MTU, Mtu, Transport, UdpFlowTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathUpdate {
    pub next_hop_mtu: u16,
}

/// A PTB is actionable only when it quotes a packet from a known flow and does
/// not try to push the path below RFC 9000's floor. Forged sub-1200 messages
/// (CVE-2024-53259) can otherwise disable QUIC with a single unauthenticated
/// packet, so an unmatched or below-floor message changes nothing.
pub fn validate_ptb<V>(
    quoted: &IngressPacket,
    offered_mtu: u16,
    flows: &UdpFlowTable<V>,
) -> Option<PathUpdate> {
    if offered_mtu < MIN_QUIC_MTU {
        return None;
    }

    let source_port = match quoted.transport {
        Transport::Udp { source_port, .. } | Transport::Tcp { source_port, .. } => source_port,
        Transport::Icmp | Transport::Other | Transport::Fragment => return None,
    };

    flows
        .contains(&InternalEndpoint {
            address: quoted.source,
            port: source_port,
        })
        .then_some(PathUpdate {
            next_hop_mtu: offered_mtu,
        })
}

/// Rewrites the MSS option of a SYN packet toward the tunnel's real budget.
/// Returns whether a clamp was applied; absence of a clampable MSS is not an
/// error. The TCP checksum is recomputed in full: two changed bytes do not
/// justify maintaining the incremental-adjustment path.
pub fn clamp_mss(packet: &mut [u8], inner_mtu: Mtu) -> bool {
    match packet.first().map(|version| version >> 4) {
        Some(4) => clamp_ipv4(packet, inner_mtu.get().saturating_sub(40)),
        Some(6) => clamp_ipv6(packet, inner_mtu.get().saturating_sub(60)),
        _ => false,
    }
}

fn clamp_ipv4(packet: &mut [u8], clamp: u16) -> bool {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl + 20 || packet[9] != 6 {
        return false;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total > packet.len() || total < ihl + 20 {
        return false;
    }

    let Some(mss_at) = mss_above(&packet[ihl..total], clamp).map(|at| ihl + at) else {
        return false;
    };
    packet[mss_at..mss_at + 2].copy_from_slice(&clamp.to_be_bytes());

    let tcp_len = (total - ihl) as u16;
    packet[ihl + 16..ihl + 18].fill(0);
    let sum = checksum(&[
        &packet[12..16],
        &packet[16..20],
        &[0, 6],
        &tcp_len.to_be_bytes(),
        &packet[ihl..total],
    ]);
    packet[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());
    true
}

fn clamp_ipv6(packet: &mut [u8], clamp: u16) -> bool {
    // ponytail: extension headers between the fixed header and TCP skip the
    // clamp; such SYNs are rare and pass through unharmed, just unclamped.
    if packet.len() < 60 || packet[6] != 6 {
        return false;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total = 40 + payload_len;
    if total > packet.len() {
        return false;
    }

    let Some(mss_at) = mss_above(&packet[40..total], clamp).map(|at| 40 + at) else {
        return false;
    };
    packet[mss_at..mss_at + 2].copy_from_slice(&clamp.to_be_bytes());

    packet[56..58].fill(0);
    let sum = checksum(&[
        &packet[8..24],
        &packet[24..40],
        &(payload_len as u32).to_be_bytes(),
        &[0, 0, 0, 6],
        &packet[40..total],
    ]);
    packet[56..58].copy_from_slice(&sum.to_be_bytes());
    true
}

/// Byte range of the MSS value inside a TCP segment, when a SYN advertises one
/// above `clamp`.
fn mss_above(segment: &[u8], clamp: u16) -> Option<usize> {
    if segment.len() < 20 || segment[13] & 0x02 == 0 {
        return None;
    }
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < 20 || header_len > segment.len() {
        return None;
    }

    let mut option = 20;
    while option < header_len {
        match segment[option] {
            0 => return None,
            1 => option += 1,
            kind => {
                let length = usize::from(*segment.get(option + 1)?);
                if length < 2 || option + length > header_len {
                    return None;
                }
                if kind == 2 {
                    let value = u16::from_be_bytes([segment[option + 2], segment[option + 3]]);
                    return (value > clamp).then_some(option + 2);
                }
                option += length;
            }
        }
    }
    None
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut pending_high = None;
    for part in parts {
        let mut bytes = part.iter().copied();
        if let Some(high) = pending_high.take() {
            match bytes.next() {
                Some(low) => sum += u32::from(u16::from_be_bytes([high, low])),
                None => pending_high = Some(high),
            }
        }
        while let Some(high) = bytes.next() {
            match bytes.next() {
                Some(low) => sum += u32::from(u16::from_be_bytes([high, low])),
                None => pending_high = Some(high),
            }
        }
    }
    if let Some(high) = pending_high {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    #[test]
    fn forged_ptb_cannot_lower_path_state() {
        let start = Instant::now();
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 12_345,
        };
        let mut flows = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();
        let _ = flows.get_or_insert_with(endpoint, start, || ());

        let quoted = IngressPacket {
            source: endpoint.address,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            ecn: etherparse::IpEcn::default(),
            transport: Transport::Udp {
                source_port: endpoint.port,
                destination_port: 443,
            },
        };

        // CVE-2024-53259 shape: a sub-1200 PTB must never disable QUIC.
        assert_eq!(validate_ptb(&quoted, 576, &flows), None);
        assert_eq!(validate_ptb(&quoted, MIN_QUIC_MTU - 1, &flows), None);

        // Quoting an unknown flow changes nothing.
        let unmatched = IngressPacket {
            source: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            ..quoted
        };
        assert_eq!(validate_ptb(&unmatched, 1400, &flows), None);

        // Non-TCP/UDP quoted transports are not flows at all.
        let icmp = IngressPacket {
            transport: Transport::Icmp,
            ..quoted
        };
        assert_eq!(validate_ptb(&icmp, 1400, &flows), None);

        // A genuine PTB against a known flow is actionable.
        assert_eq!(
            validate_ptb(&quoted, 1400, &flows),
            Some(PathUpdate { next_hop_mtu: 1400 })
        );
    }

    fn ipv4_syn(mss: u16) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 44, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
        ];
        packet.extend_from_slice(&1234_u16.to_be_bytes());
        packet.extend_from_slice(&443_u16.to_be_bytes());
        packet.extend_from_slice(&[0; 8]); // sequence and acknowledgment
        // data offset 6, SYN, window, checksum (computed below), urgent pointer
        packet.extend_from_slice(&[0x60, 0x02, 0x04, 0x00, 0, 0, 0, 0]);
        packet.extend_from_slice(&[2, 4]); // MSS option header
        packet.extend_from_slice(&mss.to_be_bytes());
        let tcp_len = 24_u16;
        let sum = checksum(&[
            &packet[12..16],
            &packet[16..20],
            &[0, 6],
            &tcp_len.to_be_bytes(),
            &packet[20..44],
        ]);
        packet[36..38].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    #[test]
    fn clamps_ipv4_syn_mss_and_fixes_checksum() {
        let mtu = Mtu::new(1400).unwrap();
        let mut packet = ipv4_syn(1460);
        assert!(clamp_mss(&mut packet, mtu));
        assert_eq!(&packet[42..44], &1360_u16.to_be_bytes());

        let ip = etherparse::Ipv4Slice::from_slice(&packet).unwrap();
        let tcp = etherparse::TcpSlice::from_slice(ip.payload().payload).unwrap();
        assert_eq!(
            tcp.checksum(),
            tcp.calc_checksum_ipv4(
                ip.header().source_addr().octets(),
                ip.header().destination_addr().octets()
            )
            .unwrap(),
            "clamped segment must carry a valid checksum"
        );

        // Already at or below the clamp: untouched.
        assert!(!clamp_mss(&mut packet, mtu));
        let mut not_syn = ipv4_syn(1460);
        not_syn[33] = 0x10; // ACK only
        assert!(!clamp_mss(&mut not_syn, mtu));
        let mut udp = ipv4_syn(1460);
        udp[9] = 17;
        assert!(!clamp_mss(&mut udp, mtu));
    }

    #[test]
    fn clamps_ipv6_syn_mss() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 24, 6, 64];
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        packet.extend_from_slice(&1234_u16.to_be_bytes());
        packet.extend_from_slice(&443_u16.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&[0x60, 0x02, 0x04, 0x00, 0, 0, 0, 0]);
        packet.extend_from_slice(&[2, 4]);
        packet.extend_from_slice(&1440_u16.to_be_bytes());
        let sum = checksum(&[
            &packet[8..24],
            &packet[24..40],
            &24_u32.to_be_bytes(),
            &[0, 0, 0, 6],
            &packet[40..64],
        ]);
        packet[56..58].copy_from_slice(&sum.to_be_bytes());

        let mtu = Mtu::new(1400).unwrap();
        assert!(clamp_mss(&mut packet, mtu));
        assert_eq!(&packet[62..64], &1340_u16.to_be_bytes());

        let ip = etherparse::Ipv6Slice::from_slice(&packet).unwrap();
        let tcp = etherparse::TcpSlice::from_slice(ip.payload().payload).unwrap();
        assert_eq!(
            tcp.checksum(),
            tcp.calc_checksum_ipv6(
                ip.header().source_addr().octets(),
                ip.header().destination_addr().octets()
            )
            .unwrap(),
            "clamped segment must carry a valid checksum"
        );
    }
}
