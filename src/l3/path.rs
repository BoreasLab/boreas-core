//! Path MTU decisions: clamp TCP SYN MSS and authenticate inbound ICMP Packet
//! Too Big messages against known flows.

use crate::{
    IngressPacket, InternalEndpoint, MIN_QUIC_MTU, Mtu, Transport, UdpFlowTable,
    wire::{Reader, checksum},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathUpdate {
    pub next_hop_mtu: u16,
}

/// Accepts a PTB only when its quote identifies a known flow and its MTU meets
/// the minimum usable QUIC datagram size. Other messages leave path state
/// unchanged.
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
        Transport::Icmp(_) | Transport::Other | Transport::Fragment => return None,
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

/// Clamps a TCP SYN's MSS to the tunnel's packet budget.
///
/// Returns `true` only when a valid MSS option was changed. Recomputing the
/// complete TCP checksum keeps the write independent of its old checksum.
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

/// TCP option kinds inspected by this module. Other kinds are skipped using
/// their length fields.
const OPTION_END: u8 = 0;
const OPTION_NOOP: u8 = 1;
const OPTION_MSS: u8 = 2;
/// `SYN` in the TCP flags byte.
const FLAG_SYN: u8 = 0x02;

/// A TCP option whose payload is inside the segment's declared header.
/// Construction is private to the bounded option parser.
struct TcpOption<'a> {
    kind: u8,
    /// Offset of the payload within the source segment.
    at: usize,
    /// Payload after the kind and length bytes.
    value: &'a [u8],
}

/// Parses TCP options as a total iterator of bounded records.
///
/// The option bytes are attacker-controlled. Every read is bounded by the
/// declared data offset and the available slice. A record that does not fit
/// ends iteration, while single-byte options are consumed here.
///
/// The four-bit data offset caps the work at a 60-byte TCP header, and every
/// successful step advances the reader.
fn tcp_options(segment: &[u8]) -> impl Iterator<Item = TcpOption<'_>> {
    let header_len = usize::from(segment.get(12).copied().unwrap_or(0) >> 4) * 4;
    // Invalid data offsets produce no option bytes.
    let options = segment.get(20..header_len).unwrap_or_default();

    let mut reader = Reader::new(options);
    std::iter::from_fn(move || {
        loop {
            match reader.u8()? {
                OPTION_END => return None,
                OPTION_NOOP => {}
                kind => {
                    // The option length includes its two-byte header. Refusing
                    // lengths below two also guarantees progress.
                    let length = usize::from(reader.u8()?).checked_sub(2)?;
                    let at = 20 + reader.position();
                    return Some(TcpOption {
                        kind,
                        at,
                        value: reader.take(length)?,
                    });
                }
            }
        }
    })
}

/// Finds an MSS value above `clamp` in a SYN segment.
///
/// Returns `None` for non-SYN segments, missing or truncated options, and MSS
/// values that already fit the clamp.
fn mss_above(segment: &[u8], clamp: u16) -> Option<usize> {
    if segment.get(13).is_none_or(|flags| flags & FLAG_SYN == 0) {
        return None;
    }

    let mss = tcp_options(segment).find(|option| option.kind == OPTION_MSS)?;
    // RFC 9293 fixes the MSS value at two bytes; a shorter value is malformed.
    let advertised = Reader::new(mss.value).u16()?;
    (advertised > clamp).then_some(mss.at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    /// A TCP header whose option region is exactly `options`, wrapped in the
    /// smallest IPv4 SYN that carries it. Data offset is derived, so the
    /// header always ends precisely where the options do — the alignment that
    /// makes an over-read observable.
    fn syn_with_options(options: &[u8]) -> Vec<u8> {
        assert!(
            options.len().is_multiple_of(4),
            "TCP headers are 4-byte aligned"
        );
        let total = 20 + 20 + options.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = (((20 + options.len()) / 4) as u8) << 4;
        packet[33] = 0x02; // SYN
        packet[40..].copy_from_slice(options);
        packet
    }

    #[test]
    fn a_malformed_option_list_declines_rather_than_reading_past_it() {
        // Each of these once had, or could have had, a read beyond the header.
        // The parser's contract is total: every one of them is simply "no
        // clampable MSS here", and the packet passes through unharmed.
        let hostile: [&[u8]; 6] = [
            // MSS claiming a two-byte header and no value: the regression case.
            &[1, 1, 2, 2],
            // MSS truncated to three bytes at the very end of the header.
            &[1, 2, 3, 0xff],
            // Zero length, which would otherwise never advance the cursor.
            &[2, 0, 0, 0],
            // A length that runs past the end of the option region.
            &[2, 40, 0x05, 0xb4],
            // End-of-options before the MSS that follows it.
            &[0, 2, 4, 0x05],
            // Nothing but padding.
            &[1, 1, 1, 1],
        ];

        for options in hostile {
            let mut packet = syn_with_options(options);
            let before = packet.clone();
            assert!(
                !clamp_mss(&mut packet, Mtu::new(1500).unwrap()),
                "options {options:?} must not report a clamp"
            );
            assert_eq!(packet, before, "options {options:?} must pass unmodified");
        }
    }

    #[test]
    fn a_well_formed_mss_option_still_clamps_after_any_padding() {
        // The counterpart to the test above: totality must not have been
        // bought by refusing the option the clamp exists to find. 1460 is the
        // classic Ethernet advertisement; the clamp is 1500 - 60 - 40.
        let variants: [&[u8]; 3] = [
            &[2, 4, 0x05, 0xb4],
            &[1, 1, 2, 4, 0x05, 0xb4, 1, 1],
            &[3, 3, 7, 1, 2, 4, 0x05, 0xb4],
        ];

        for options in variants {
            let mut packet = syn_with_options(options);
            assert!(
                clamp_mss(&mut packet, Mtu::new(1400).unwrap()),
                "options {options:?} carry a clampable MSS"
            );
            let clamped = packet
                .windows(2)
                .any(|pair| u16::from_be_bytes([pair[0], pair[1]]) == 1360);
            assert!(clamped, "options {options:?} must be rewritten to 1360");
        }
    }

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
            payload_at: 0,
            payload_len: 0,
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
            transport: Transport::Icmp(crate::IcmpClass::Informational),
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
