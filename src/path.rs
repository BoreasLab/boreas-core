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

/// TCP option kinds this module names. The remaining kinds are skipped by
/// length, which is what the option list's TLV framing is for.
const OPTION_END: u8 = 0;
const OPTION_NOOP: u8 = 1;
const OPTION_MSS: u8 = 2;
/// `SYN` in the TCP flags byte.
const FLAG_SYN: u8 = 0x02;

/// One length-checked TCP option. Constructing this value *is* the proof that
/// `value` lies inside the segment's declared header: the parser below is the
/// only constructor, and it yields nothing it could not slice. Consumers
/// therefore index `value` freely.
struct TcpOption<'a> {
    kind: u8,
    /// Offset of `value` within the segment that produced it.
    at: usize,
    /// The option's payload, with its kind and length bytes removed.
    value: &'a [u8],
}

/// Parses the TCP option region as a total iterator of length-checked records.
///
/// This is the trust boundary for the option list: the bytes are attacker-
/// chosen, so every read is bounded by the data-offset field, which is itself
/// bounded by the slice. A record that does not fit ends the iteration instead
/// of panicking, and single-byte options (`END`, `NOOP`) are consumed here so
/// no consumer has to know they exist.
///
/// O(header length), which the 4-bit data offset caps at 60 bytes. Every step
/// advances `at` by at least one, so the iterator always terminates.
fn tcp_options(segment: &[u8]) -> impl Iterator<Item = TcpOption<'_>> {
    let header_len = usize::from(segment.get(12).copied().unwrap_or(0) >> 4) * 4;
    // An inverted or over-long range yields `None`, so a nonsense data offset
    // simply produces an empty option list.
    let options = segment.get(20..header_len).unwrap_or_default();

    let mut at = 0;
    std::iter::from_fn(move || {
        loop {
            match *options.get(at)? {
                OPTION_END => return None,
                OPTION_NOOP => at += 1,
                kind => {
                    let length = usize::from(*options.get(at + 1)?);
                    // `at + 2 > at + length` when `length < 2`, and the range
                    // slice rejects that as it rejects running off the end, so
                    // one `get` enforces both bounds. `length >= 2` on success
                    // is what guarantees progress.
                    let value = options.get(at + 2..at + length)?;
                    let option = TcpOption {
                        kind,
                        at: 20 + at + 2,
                        value,
                    };
                    at += length;
                    return Some(option);
                }
            }
        }
    })
}

/// Offset, within `segment`, of the MSS value a SYN advertises above `clamp`.
/// `None` when the segment is not a SYN, carries no MSS option, carries a
/// truncated one, or already sits at or below the clamp.
fn mss_above(segment: &[u8], clamp: u16) -> Option<usize> {
    if segment.get(13).is_none_or(|flags| flags & FLAG_SYN == 0) {
        return None;
    }

    let mss = tcp_options(segment).find(|option| option.kind == OPTION_MSS)?;
    // RFC 9293: the MSS option's value is exactly two bytes. A shorter one is
    // malformed, and `first_chunk` refuses it rather than reading past it.
    let advertised = u16::from_be_bytes(*mss.value.first_chunk()?);
    (advertised > clamp).then_some(mss.at)
}

/// The internet checksum (RFC 1071) over a sequence of parts, treated as one
/// byte stream. Shared with `packet::write_udp`, which needs the same sum over
/// a pseudo-header it assembles from pieces.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
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
