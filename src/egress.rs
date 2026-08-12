//! Egress implementations and the sum that binds capability to layer.
//!
//! An [`EgressCapabilities`] value is a claim; an [`Egress`] is the thing the
//! claim is about. Before this module existed, `accepts` was a runtime field
//! that could disagree with the implementation it described. Now the layer is
//! the enum variant and the capabilities come from the implementation behind
//! it, so the two cannot drift apart.
//!
//! [`PacketEgress`] is the whole sans-io interface, not just a capability
//! report: bytes in, [`EgressEmit`] values out, timers on an explicit `tick`.
//! That is what lets the reactor drive any packet egress without naming
//! WireGuard, and what makes `Box<dyn PacketEgress>` a thing you can run
//! rather than only interrogate.
//!
//! [`WireGuardEgress`] is the first implementation: a sans-io wrapper over
//! GotaTun's `Tunn`. It performs no socket I/O of its own, but it reads the
//! real clock for handshake and rekey timers, so it belongs to the shell side
//! of the pure-core boundary, not to [`crate::Datapath`].
//!
//! Every emitted buffer is [`Pooled`]. The engineering plan's per-packet
//! budget forbids a heap allocation per packet, and an egress sits on the
//! hottest path there is, so its outputs draw on the same single budget the
//! datapath's do; exhaustion is a counted drop, never a wait.

use std::{sync::Arc, time::Duration};

use gotatun::{
    noise::{
        Tunn, TunnResult, errors::WireGuardError, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
    tun::MtuWatcher,
    x25519::{PublicKey, StaticSecret},
};

use crate::{
    Accepts, BufferPool, CapabilityError, DatagramFidelity, EgressCapabilities, Mtu, NatBehavior,
    Pooled,
};

/// An egress that accepts whole IP packets, such as WireGuard or MASQUE
/// CONNECT-IP.
///
/// Emissions go into a caller-owned sink rather than a returned `Vec`, so the
/// reactor reuses one buffer for the life of the process and a packet costs no
/// allocation for the container it travels in. The sink is appended to, never
/// cleared: one call may legitimately produce a handshake response for the
/// network *and* a packet for the tunnel, and a caller batching several calls
/// keeps their order.
pub trait PacketEgress: Send {
    /// The capability claim the planner sees. The accepted layer is not part
    /// of it: the [`Egress`] variant already says so.
    fn capabilities(&self) -> EgressCapabilities;

    /// Accepts one whole IP packet from the tunnel side, bound outward.
    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    /// Accepts one datagram from the network, bound inward.
    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    /// Drives the implementation's own timers: handshake retries, rekeys,
    /// expiry, keepalives.
    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError>;

    /// How often [`tick`](Self::tick) must be called. The implementation owns
    /// its own cadence, so the shell arms a timer rather than knowing any
    /// protocol's timer granularity.
    fn tick_interval(&self) -> Duration;
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

/// GotaTun's own device ticks every 250 ms. WireGuard rounds its timers to the
/// second, so any cadence in that range is correct; this one matches the
/// reference implementation rather than inventing a number.
const WIREGUARD_TICK: Duration = Duration::from_millis(250);

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
#[derive(Debug, PartialEq, Eq)]
pub enum EgressEmit {
    /// A UDP payload for the WireGuard peer's endpoint.
    ToNetwork(Pooled),
    /// A decrypted IP packet for the datapath's egress side.
    ToTunnel(Pooled),
}

#[derive(Debug)]
pub enum EgressError {
    /// Bytes from the UDP socket that are not a WireGuard packet. Routine on a
    /// public port; the caller counts and continues.
    MalformedNetworkPacket,
    /// The shared buffer pool had no room for an emission. A drop, never a
    /// wait, on the same budget every other payload draws from.
    PoolExhausted,
    /// The tunnel itself failed, e.g. `ConnectionExpired` once the handshake
    /// has been retried past its limit.
    WireGuard(WireGuardError),
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedNetworkPacket => f.write_str("not a WireGuard packet"),
            Self::PoolExhausted => f.write_str("no pooled buffer for the emission"),
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
    pool: Arc<BufferPool>,
    /// IP packets encapsulated so far. This is the fast-path counter: every
    /// one of these is a packet that bypassed local termination entirely.
    fast_path_packets: u64,
}

impl WireGuardEgress {
    /// `pool` is the same budget the datapath draws on; its slice size must
    /// admit an encapsulated packet, which is `inner_mtu + 32` bytes.
    pub fn new(config: WireGuardConfig, pool: Arc<BufferPool>) -> Self {
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
            pool,
            fast_path_packets: 0,
        }
    }

    /// The fast-path counter behind the M1 gate: every packet counted here
    /// was encapsulated directly and never entered local termination.
    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// Packets queued while no session existed, encapsulated once one does.
    fn flush_queue(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        // Collected before the pool is touched because `get_queued_packets`
        // borrows the tunnel mutably; the queue is bounded by the tunnel's own
        // depth and is empty on every packet but the one that completes a
        // handshake.
        let queued: Vec<WgKind> = self.tunn.get_queued_packets(&mut self.mtu).collect();
        for kind in queued {
            out.push(self.network_emit(kind)?);
        }
        Ok(())
    }

    fn network_emit(&self, kind: WgKind) -> Result<EgressEmit, EgressError> {
        let packet: Packet = kind.into();
        self.pool
            .take(packet.as_ref())
            .map(EgressEmit::ToNetwork)
            .ok_or(EgressError::PoolExhausted)
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

    /// Encapsulates one IP packet from the tunnel. Before a session exists
    /// this emits the handshake initiation and queues the packet inside the
    /// tunnel; the queue flushes on the tick or inbound packet that completes
    /// the handshake. At most one emission, always network-bound.
    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        self.fast_path_packets += 1;
        let Some(kind) = self
            .tunn
            .handle_outgoing_packet(Packet::copy_from(packet), Some(&mut self.mtu))
        else {
            return Ok(());
        };
        out.push(self.network_emit(kind)?);
        Ok(())
    }

    /// Handles one UDP payload from the peer. A malformed datagram is an
    /// observation, not a tunnel failure; a completed handshake flushes
    /// whatever was queued while it ran.
    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        let kind = Packet::copy_from(datagram)
            .try_into_wg()
            .map_err(|_| EgressError::MalformedNetworkPacket)?;

        match self.tunn.handle_incoming_packet(kind) {
            TunnResult::Done => {}
            TunnResult::Err(error) => return Err(error.into()),
            TunnResult::WriteToNetwork(kind) => out.push(self.network_emit(kind)?),
            TunnResult::WriteToTunnel(packet) => {
                let bytes: &[u8] = packet.as_ref();
                // A keepalive answers liveness inside the protocol; it is not
                // an IP packet and must not reach the datapath. Data payloads
                // are padded to a 16-byte multiple, and the IP header's own
                // length field governs, so the tunnel is owed exactly the
                // packet and not the padding.
                if !bytes.is_empty() {
                    let stripped = strip_padding(bytes);
                    let pooled = self.pool.take(stripped).ok_or(EgressError::PoolExhausted)?;
                    out.push(EgressEmit::ToTunnel(pooled));
                }
            }
        }
        self.flush_queue(out)
    }

    /// Drives handshake retries, rekeys, session expiry, and keepalives.
    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        if let Some(kind) = self.tunn.update_timers()? {
            out.push(self.network_emit(kind)?);
        }
        self.flush_queue(out)
    }

    fn tick_interval(&self) -> Duration {
        WIREGUARD_TICK
    }
}

/// The exact IP packet, without WireGuard's 16-byte-alignment padding.
///
/// O(1) and allocation-free: both families state their own length at a fixed
/// offset in the fixed header, so this reads two bytes rather than running a
/// full network-and-transport parse for a number the header already carries.
/// A packet whose own header does not describe a sane length passes through
/// untouched: the datapath is the authority on rejecting it, and guessing a
/// length here would only hide its count.
fn strip_padding(packet: &[u8]) -> &[u8] {
    let declared = match packet.first().map(|version| version >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (header >= 20 && total >= header).then_some(total)
        }
        Some(6) if packet.len() >= 40 => {
            Some(40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])))
        }
        _ => None,
    };
    declared
        .and_then(|length| packet.get(..length))
        .unwrap_or(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    /// Large enough that nothing here meets the budget, so a `PoolExhausted`
    /// in these tests would be a defect rather than the congestion path.
    fn pool() -> Arc<BufferPool> {
        BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        )
    }

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

    fn pair(pool: &Arc<BufferPool>) -> (WireGuardEgress, WireGuardEgress) {
        let (client_private, client_public) = keypair(1);
        let (server_private, server_public) = keypair(2);
        (
            WireGuardEgress::new(config(client_private, server_public), Arc::clone(pool)),
            WireGuardEgress::new(config(server_private, client_public), Arc::clone(pool)),
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
                    EgressEmit::ToNetwork(datagram) => target
                        .handle_network_packet(&datagram, outgoing)
                        .expect("in-band WireGuard exchange"),
                    EgressEmit::ToTunnel(packet) => tunnelled.push(packet.to_vec()),
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
        let pool = pool();
        let (mut client, mut server) = pair(&pool);
        let ip_packet = [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];

        // The first packet triggers the handshake and is queued behind it.
        let mut first = Vec::new();
        client.handle_tun_packet(&ip_packet, &mut first).unwrap();
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
        let mut second = Vec::new();
        client.handle_tun_packet(&ip_packet, &mut second).unwrap();
        let tunnelled = exchange(&mut client, &mut server, second);
        assert_eq!(tunnelled, vec![ip_packet]);
        assert_eq!(client.fast_path_packets(), 2);

        // Every pooled buffer the exchange used has been returned: an egress
        // that leaked the budget would starve the datapath sharing it.
        assert_eq!(pool.available(), 64);
    }

    #[test]
    fn non_wireguard_datagrams_are_rejected_not_fatal() {
        let pool = pool();
        let (mut client, _server) = pair(&pool);
        let mut out = Vec::new();
        assert!(matches!(
            client.handle_network_packet(&[0xde, 0xad, 0xbe, 0xef], &mut out),
            Err(EgressError::MalformedNetworkPacket)
        ));
        assert!(out.is_empty());
        // The tunnel still works afterwards.
        client.handle_tun_packet(&[0x45; 28], &mut out).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn an_exhausted_pool_refuses_an_emission_instead_of_allocating() {
        let pool = BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );
        let (mut client, _server) = pair(&pool);
        let held = pool.take(b"the only buffer").expect("within budget");

        let mut out = Vec::new();
        assert!(matches!(
            client.handle_tun_packet(&[0x45; 28], &mut out),
            Err(EgressError::PoolExhausted)
        ));
        assert!(out.is_empty(), "a refusal emits nothing");
        assert_eq!(pool.exhausted(), 1);
        drop(held);

        // The refusal is the pool's state, not a broken egress: with the
        // budget back, an egress emits normally. It is deliberately a fresh
        // one — the dropped bytes were a handshake initiation, and WireGuard
        // recovers those from its own retry timer on `tick`, not from the
        // next packet, so re-offering to the same tunnel proves nothing.
        let (mut fresh, _server) = pair(&pool);
        fresh.handle_tun_packet(&[0x45; 28], &mut out).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn padding_is_stripped_by_the_header_the_packet_declares() {
        // IPv4: 28 declared bytes inside a 32-byte padded payload.
        let mut padded = vec![0u8; 32];
        padded[0] = 0x45;
        padded[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 28);

        // IPv6: 40 fixed bytes plus a declared 8-byte payload.
        let mut padded = vec![0u8; 64];
        padded[0] = 0x60;
        padded[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 48);

        // Nonsense passes through whole rather than being guessed at: a
        // declared length below the header, past the buffer, or on a version
        // that is neither family.
        let mut broken = vec![0u8; 32];
        broken[0] = 0x45;
        broken[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(strip_padding(&broken).len(), 32);
        broken[2..4].copy_from_slice(&9999u16.to_be_bytes());
        assert_eq!(strip_padding(&broken).len(), 32);
        assert_eq!(strip_padding(&[0x00; 32]).len(), 32);
        assert_eq!(strip_padding(&[]).len(), 0);
    }

    #[test]
    fn the_reported_capabilities_match_the_implementation() {
        let pool = pool();
        let (client, _server) = pair(&pool);
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
