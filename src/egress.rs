//! Egress implementations and the sum that binds capability to layer.
//!
//! An [`EgressCapabilities`] value is a claim; an [`Egress`] is the thing the
//! claim is about. Before this module existed, `accepts` was a runtime field
//! that could disagree with the implementation it described. Now the layer is
//! the enum variant and the capabilities come from the implementation behind
//! it, so the two cannot drift apart.
//!
//! [`WireGuardEgress`] is the first packet egress: a sans-io wrapper over
//! GotaTun's `Tunn`. It performs no socket I/O of its own — every method takes
//! bytes and returns [`EgressEmit`] values for the shell to deliver — but it
//! reads the real clock for handshake and rekey timers, so it belongs to the
//! shell side of the pure-core boundary, not to [`crate::Datapath`].

use std::sync::Arc;

use etherparse::{NetSlice, SlicedPacket};
use gotatun::{
    noise::{
        Tunn, TunnResult, errors::WireGuardError, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
    tun::MtuWatcher,
    x25519::{PublicKey, StaticSecret},
};

use crate::{Accepts, CapabilityError, DatagramFidelity, EgressCapabilities, Mtu, NatBehavior};

/// An egress that accepts whole IP packets, such as WireGuard or MASQUE
/// CONNECT-IP.
pub trait PacketEgress: Send {
    /// The capability claim the planner sees. The accepted layer is not part
    /// of it: the [`Egress`] variant already says so.
    fn capabilities(&self) -> EgressCapabilities;
}

/// An egress that accepts L4 flows, such as SOCKS5 or Shadowsocks.
pub trait StreamEgress: Send {
    /// The capability claim the planner sees. The accepted layer is not part
    /// of it: the [`Egress`] variant already says so.
    fn capabilities(&self) -> EgressCapabilities;
}

/// A configured egress implementation. The variant determines the accepted
/// layer, which is what makes a mismatched `accepts` field unconstructable.
pub enum Egress {
    Packet(Box<dyn PacketEgress>),
    Stream(Box<dyn StreamEgress>),
}

impl Egress {
    /// The layer this egress accepts, derived from the variant.
    pub fn accepts(&self) -> Accepts {
        match self {
            Self::Packet(_) => Accepts::IpPackets,
            Self::Stream(_) => Accepts::Flows,
        }
    }

    /// The capability claim of the implementation behind the variant.
    pub fn capabilities(&self) -> EgressCapabilities {
        match self {
            Self::Packet(egress) => egress.capabilities(),
            Self::Stream(egress) => egress.capabilities(),
        }
    }

    /// Chains two egresses' capabilities. Layer agreement is now a genuine
    /// configuration conflict — a packet egress cannot carry a stream
    /// egress's flows — so `MixedLayers` is reported here, where the
    /// implementations are known, rather than between two bare claims.
    pub fn chain(first: &Egress, next: &Egress) -> Result<EgressCapabilities, CapabilityError> {
        if first.accepts() != next.accepts() {
            return Err(CapabilityError::MixedLayers);
        }
        first.capabilities().chain(next.capabilities())
    }
}

/// Total WireGuard encapsulation overhead over an IPv6 underlay: 40 bytes of
/// outer IPv6, 8 of UDP, and 32 of WireGuard header and authentication tag.
/// IPv4 underlays cost 60; capabilities report the worst case so the inner
/// MTU never exceeds reality on either underlay.
pub const WIREGUARD_OVERHEAD_BYTES: u16 = 80;

/// Match GotaTun's own device: handshake initiations per second per peer.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Static configuration for one WireGuard peer. Keys are fixed-size arrays,
/// so validity is structural and there is nothing to validate at runtime.
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Keepalive interval in seconds; `None` disables it.
    pub persistent_keepalive: Option<u16>,
    /// The tunnel MTU, used to pad data packets to a 16-byte multiple without
    /// exceeding it, per the WireGuard protocol's padding rule.
    pub inner_mtu: Mtu,
}

/// What the sans-io egress produced, for the shell to deliver. Keeping the
/// two destinations in one sum means a handler's caller cannot lose half of a
/// handshake exchange: a decapsulation can legitimately produce both a
/// handshake response for the network and a packet for the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressEmit {
    /// A UDP payload for the WireGuard peer's endpoint.
    ToNetwork(Vec<u8>),
    /// A decrypted IP packet for the datapath's egress side.
    ToTunnel(Vec<u8>),
}

#[derive(Debug)]
pub enum EgressError {
    /// Bytes from the UDP socket that are not a WireGuard packet. Routine on a
    /// public port; the caller counts and continues.
    MalformedNetworkPacket,
    /// The tunnel itself failed, e.g. `ConnectionExpired` once the handshake
    /// has been retried past its limit.
    WireGuard(WireGuardError),
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedNetworkPacket => f.write_str("not a WireGuard packet"),
            // GotaTun's error type is a plain enum without `Display`; Debug
            // names the variant, which is what an operator needs.
            Self::WireGuard(error) => write!(f, "WireGuard failure: {error:?}"),
        }
    }
}

impl std::error::Error for EgressError {}

impl From<WireGuardError> for EgressError {
    fn from(error: WireGuardError) -> Self {
        Self::WireGuard(error)
    }
}

/// A WireGuard peer as a packet egress. Packets in, datagrams out, timers on
/// an explicit tick; the UDP socket and its endpoint live in the shell.
pub struct WireGuardEgress {
    tunn: Tunn,
    mtu: MtuWatcher,
    /// IP packets encapsulated so far. This is the fast-path counter: every
    /// one of these is a packet that bypassed local termination entirely.
    fast_path_packets: u64,
}

impl WireGuardEgress {
    pub fn new(config: WireGuardConfig) -> Self {
        let private_key = StaticSecret::from(config.private_key);
        let our_public = PublicKey::from(&private_key);
        Self {
            tunn: Tunn::new(
                private_key,
                PublicKey::from(config.peer_public_key),
                config.preshared_key,
                config.persistent_keepalive,
                IndexTable::from_os_rng(),
                Arc::new(RateLimiter::new(&our_public, HANDSHAKE_RATE_LIMIT)),
            ),
            mtu: MtuWatcher::new(config.inner_mtu.get()),
            fast_path_packets: 0,
        }
    }

    /// Encapsulates one IP packet from the tunnel. Before a session exists
    /// this emits the handshake initiation and queues the packet inside the
    /// tunnel; the queue flushes on the tick or inbound packet that completes
    /// the handshake.
    pub fn handle_tun_packet(&mut self, packet: &[u8]) -> Vec<EgressEmit> {
        self.fast_path_packets += 1;
        self.tunn
            .handle_outgoing_packet(Packet::copy_from(packet), Some(&mut self.mtu))
            .map(network_emit)
            .into_iter()
            .collect()
    }

    /// Handles one UDP payload from the peer. A malformed datagram is an
    /// observation, not a tunnel failure; a completed handshake flushes
    /// whatever was queued while it ran.
    pub fn handle_network_packet(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<EgressEmit>, EgressError> {
        let kind = Packet::copy_from(datagram)
            .try_into_wg()
            .map_err(|_| EgressError::MalformedNetworkPacket)?;

        let mut emits = match self.tunn.handle_incoming_packet(kind) {
            TunnResult::Done => Vec::new(),
            TunnResult::Err(error) => return Err(error.into()),
            TunnResult::WriteToNetwork(kind) => vec![network_emit(kind)],
            TunnResult::WriteToTunnel(packet) => {
                let bytes: &[u8] = packet.as_ref();
                if bytes.is_empty() {
                    // A keepalive answers liveness inside the protocol; it is
                    // not an IP packet and must not reach the datapath.
                    Vec::new()
                } else {
                    // Data payloads are padded to a 16-byte multiple. The IP
                    // header's own length field governs, so the tunnel is owed
                    // exactly the packet, not the padding.
                    vec![EgressEmit::ToTunnel(strip_padding(bytes).to_vec())]
                }
            }
        };
        emits.extend(self.flush_queue());
        Ok(emits)
    }

    /// Drives handshake retries, rekeys, session expiry, and keepalives.
    /// WireGuard rounds these timers to the second; GotaTun's own device
    /// ticks every 250 ms, and any cadence in that range is correct.
    pub fn tick(&mut self) -> Result<Vec<EgressEmit>, EgressError> {
        let mut emits = self
            .tunn
            .update_timers()?
            .map(network_emit)
            .into_iter()
            .collect::<Vec<_>>();
        emits.extend(self.flush_queue());
        Ok(emits)
    }

    /// The fast-path counter behind the M1 gate: every packet counted here
    /// was encapsulated directly and never entered local termination.
    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// Packets queued while no session existed, encapsulated once one does.
    fn flush_queue(&mut self) -> impl Iterator<Item = EgressEmit> + '_ {
        self.tunn
            .get_queued_packets(&mut self.mtu)
            .map(network_emit)
    }
}

impl PacketEgress for WireGuardEgress {
    fn capabilities(&self) -> EgressCapabilities {
        EgressCapabilities {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: WIREGUARD_OVERHEAD_BYTES,
            max_datagram_size: None,
            // The inner header's ECN survives encryption untouched, but no
            // outer-header marking propagates mid-tunnel, and no capture has
            // verified either direction yet. Claim nothing.
            preserves_ecn: false,
            // One peer behind one endpoint: there is no mapping to vary.
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }
}

fn network_emit(kind: WgKind) -> EgressEmit {
    let packet: Packet = kind.into();
    EgressEmit::ToNetwork(packet.as_ref().to_vec())
}

/// The exact IP packet, without WireGuard's 16-byte-alignment padding. An
/// unparseable packet passes through untouched: the datapath is the authority
/// on rejecting it, and guessing a length here would only hide its count.
fn strip_padding(packet: &[u8]) -> &[u8] {
    let Ok(sliced) = SlicedPacket::from_ip(packet) else {
        return packet;
    };
    let length = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => usize::from(ipv4.header().total_len()),
        Some(NetSlice::Ipv6(ipv6)) => 40 + usize::from(ipv6.header().payload_length()),
        _ => return packet,
    };
    packet.get(..length).unwrap_or(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(private_key: [u8; 32], peer_public_key: [u8; 32]) -> WireGuardConfig {
        WireGuardConfig {
            private_key,
            peer_public_key,
            preshared_key: None,
            persistent_keepalive: None,
            inner_mtu: Mtu::new(1420).unwrap(),
        }
    }

    /// Deterministic stand-ins for real keys; x25519 accepts any 32 bytes.
    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = StaticSecret::from([seed; 32]);
        (private.to_bytes(), PublicKey::from(&private).to_bytes())
    }

    fn pair() -> (WireGuardEgress, WireGuardEgress) {
        let (client_private, client_public) = keypair(1);
        let (server_private, server_public) = keypair(2);
        (
            WireGuardEgress::new(config(client_private, server_public)),
            WireGuardEgress::new(config(server_private, client_public)),
        )
    }

    /// Delivers one end's emits to the other, ping-ponging until neither has
    /// anything left to say — the deterministic stand-in for two shells joined
    /// by a loopback socket. Tunnel-bound packets are collected.
    fn exchange(
        client: &mut WireGuardEgress,
        server: &mut WireGuardEgress,
        initial: Vec<EgressEmit>,
    ) -> Vec<Vec<u8>> {
        fn deliver(
            target: &mut WireGuardEgress,
            incoming: &mut Vec<EgressEmit>,
            outgoing: &mut Vec<EgressEmit>,
            tunnelled: &mut Vec<Vec<u8>>,
        ) {
            for emit in incoming.drain(..) {
                match emit {
                    EgressEmit::ToNetwork(datagram) => outgoing.extend(
                        target
                            .handle_network_packet(&datagram)
                            .expect("in-band WireGuard exchange"),
                    ),
                    EgressEmit::ToTunnel(packet) => tunnelled.push(packet),
                }
            }
        }

        let mut tunnelled = Vec::new();
        let (mut to_server, mut to_client) = (initial, Vec::new());
        while !to_server.is_empty() || !to_client.is_empty() {
            deliver(server, &mut to_server, &mut to_client, &mut tunnelled);
            deliver(client, &mut to_client, &mut to_server, &mut tunnelled);
        }
        tunnelled
    }

    #[test]
    fn handshake_then_ip_packet_round_trips_byte_exact() {
        let (mut client, mut server) = pair();
        let ip_packet = [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];

        // The first packet triggers the handshake and is queued behind it.
        let first = client.handle_tun_packet(&ip_packet);
        assert!(
            first
                .iter()
                .all(|emit| matches!(emit, EgressEmit::ToNetwork(_))),
            "nothing reaches the tunnel before the handshake"
        );
        let tunnelled = exchange(&mut client, &mut server, first);
        assert_eq!(tunnelled, vec![ip_packet], "queued packet flushes intact");
        assert_eq!(client.fast_path_packets(), 1);

        // With a session established, a second packet crosses directly.
        let second = client.handle_tun_packet(&ip_packet);
        let tunnelled = exchange(&mut client, &mut server, second);
        assert_eq!(tunnelled, vec![ip_packet]);
        assert_eq!(client.fast_path_packets(), 2);
    }

    #[test]
    fn non_wireguard_datagrams_are_rejected_not_fatal() {
        let (mut client, _server) = pair();
        assert!(matches!(
            client.handle_network_packet(&[0xde, 0xad, 0xbe, 0xef]),
            Err(EgressError::MalformedNetworkPacket)
        ));
        // The tunnel still works afterwards.
        let emits = client.handle_tun_packet(&[0x45; 28]);
        assert!(!emits.is_empty());
    }

    #[test]
    fn the_reported_capabilities_match_the_implementation() {
        let (client, _server) = pair();
        let egress = Egress::Packet(Box::new(client));
        assert_eq!(egress.accepts(), Accepts::IpPackets);
        let capabilities = egress.capabilities();
        assert_eq!(capabilities.datagram_fidelity, DatagramFidelity::Native);
        assert_eq!(capabilities.overhead_bytes, WIREGUARD_OVERHEAD_BYTES);

        // A stream egress chained behind a packet egress is a configuration
        // conflict reported where the implementations are known.
        struct NoStreams;
        impl StreamEgress for NoStreams {
            fn capabilities(&self) -> EgressCapabilities {
                EgressCapabilities {
                    datagram_fidelity: DatagramFidelity::Native,
                    overhead_bytes: 0,
                    max_datagram_size: None,
                    preserves_ecn: false,
                    nat_behavior: NatBehavior::EndpointIndependent,
                }
            }
        }
        let stream = Egress::Stream(Box::new(NoStreams));
        assert_eq!(
            Egress::chain(&egress, &stream),
            Err(CapabilityError::MixedLayers)
        );
    }
}
