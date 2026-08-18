//! MASQUE CONNECT-IP (RFC 9484) as a packet egress.
//!
//! An IP packet from the client's TUN becomes an HTTP Datagram (RFC 9297) on a
//! QUIC connection to a MASQUE proxy, and the proxy's datagrams become IP
//! packets for the client. That is the whole protocol from this crate's side:
//! CONNECT-IP is a *tunnel of whole IP packets*, which is why it implements
//! [`PacketEgress`] alongside WireGuard rather than needing a new layer.
//!
//! **`quiche` is the QUIC stack, and it is sans-io — which is why it fits.**
//! [`PacketEgress`] is bytes in, [`EgressEmit`] out, timers on an explicit
//! tick; `quiche::Connection` is exactly that shape (`recv`, `send`,
//! `on_timeout`) and performs no I/O of its own. [Verification](../docs/verification.md)
//! pre-authorised "tokio-quiche and quiche"; of the two only plain `quiche`
//! composes here, because `tokio-quiche` owns its own sockets and would fight
//! the seam the reactor already drives. It is also the stack Cloudflare's own
//! WARP MASQUE client speaks, so the wire is exercised against a real
//! deployment rather than only against a specification.
//!
//! **Two framings stack, and both are varints.** RFC 9297 puts a Quarter
//! Stream ID in front of every HTTP Datagram; RFC 9484 puts a Context ID in
//! front of the payload, where context 0 means "an IP packet". So the QUIC
//! datagram is `varint(flow_id) || varint(0) || packet`, and
//! [`encode_ip_datagram`] and [`decode_ip_datagram`] are that pure codec,
//! testable without a connection.
//!
//! **The tunnel's states are a closed sum, so an unusable tunnel cannot be
//! written to.** A *usable* flow id exists only inside
//! [`TunnelState::Established`], which is the proof that the proxy answered
//! `2xx`; there is no way to encode a datagram before that. The id is known
//! earlier than that — from the moment the request is sent — and it lives in
//! [`TunnelState::Requested`] until the answer arrives, rather than in a field
//! beside the state where the two could disagree about which phase this is in.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use quiche::h3::NameValue;

use crate::{
    BufferPool, DatagramFidelity, EgressEmit, EgressError, NatBehavior, PacketEgress,
    PathProperties, varint,
};

/// The CONNECT-IP context ID for a full IP packet, fixed by RFC 9484 §6.
const IP_PACKET_CONTEXT: u64 = 0;

/// A conservative upper bound on everything wrapped around one tunnelled IP
/// packet, used for inner-MTU arithmetic before a connection exists. Once one
/// does, [`MasqueEgress::properties`] reports the *measured* ceiling from
/// `quiche` instead, which is always the tighter and truer number.
///
/// The terms, worst case: 40 bytes of outer IPv6 and 8 of UDP; a QUIC short
/// header of 1 flag byte, up to 20 bytes of destination connection ID, and up
/// to 4 of packet number; a 16-byte AEAD tag; a DATAGRAM frame type and length
/// (1 + 2); and the two varints above (up to 4 + 1).
pub const MASQUE_OVERHEAD_BYTES: u16 = 40 + 8 + 1 + 20 + 4 + 16 + 3 + 5;

/// How often the egress is ticked when it has nothing more urgent to ask for.
/// QUIC's real timer is not a cadence — it is a deadline that moves with loss
/// recovery — so [`PacketEgress::next_deadline`] is what the reactor actually
/// arms against, and this is only the backstop.
const MASQUE_TICK: Duration = Duration::from_millis(250);

/// Static configuration for one MASQUE proxy.
pub struct MasqueConfig {
    /// The proxy's UDP endpoint.
    pub peer: SocketAddr,
    /// The local address QUIC should believe it is sending from. The socket is
    /// the shell's, so this is what the connection stamps on its packets
    /// rather than something this type binds.
    pub local: SocketAddr,
    /// The name presented in SNI and verified against the proxy's certificate.
    pub server_name: String,
    /// `:authority` for the CONNECT request.
    pub authority: String,
    /// `:path` for the CONNECT request.
    pub path: String,
    /// The `:protocol` pseudo-header. RFC 9484 registers `connect-ip`, and
    /// that is the default; Cloudflare WARP expects `cf-connect-ip`, so a
    /// deployment that targets it sets this rather than patching the crate.
    pub protocol: String,
    /// What RFC 4787 mapping behavior the *proxy* provides.
    ///
    /// Deliberately configuration and not a constant: the mapping is performed
    /// by the proxy's own NAT, so this crate cannot observe it, and a hard-coded
    /// optimistic claim would be an unmeasured assertion in the one place the
    /// planner trusts. A deployment declares what it measured.
    pub nat_behavior: NatBehavior,
}

impl MasqueConfig {
    /// The RFC 9484 registered protocol identifier.
    pub const STANDARD_PROTOCOL: &'static str = "connect-ip";
    /// What Cloudflare WARP's MASQUE deployment expects instead.
    pub const CLOUDFLARE_PROTOCOL: &'static str = "cf-connect-ip";
}

/// Why a tunnel is no longer usable. Each is terminal: the shell replaces the
/// egress or reports the failure, and none of them is retried in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The proxy answered the CONNECT request with a non-2xx status.
    Refused(u16),
    /// The QUIC connection closed, by either peer or by idle timeout.
    ConnectionClosed,
    /// The proxy's response was not a CONNECT-IP response at all.
    Malformed,
}

/// The tunnel's lifecycle. A flow id exists only once the proxy has agreed to
/// carry packets, so no code path can address a datagram before then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelState {
    /// The QUIC handshake is still in flight; no CONNECT-IP request has been
    /// sent yet.
    Connecting,
    /// The CONNECT-IP request is on the wire. `flow_id` is its request stream's
    /// quarter id, known from the moment the request is sent and load-bearing
    /// only once the proxy answers.
    ///
    /// **This is where a pending flow id belongs.** It used to sit in a field
    /// beside this enum, so `Established` with nothing pending and `Connecting`
    /// with something pending were both representable, and the transition read
    /// two values that could disagree. One of them now implies the other.
    Requested {
        flow_id: u64,
    },
    /// The proxy answered `2xx`. `flow_id` is the request stream's quarter id,
    /// which every HTTP Datagram on this tunnel carries.
    Established {
        flow_id: u64,
    },
    Closed(CloseReason),
}

/// Writes one IP packet as a CONNECT-IP HTTP Datagram payload.
///
/// `varint(flow_id) || varint(0) || packet`. O(packet length), one copy into
/// the caller's buffer and no allocation of its own.
pub fn encode_ip_datagram(flow_id: u64, packet: &[u8], out: &mut Vec<u8>) {
    out.clear();
    varint::put(flow_id, out);
    varint::put(IP_PACKET_CONTEXT, out);
    out.extend_from_slice(packet);
}

/// Reads the IP packet out of a CONNECT-IP HTTP Datagram payload.
///
/// `None` unless the datagram belongs to this tunnel's flow and carries
/// context 0: another context is a capsule this tunnel does not implement, and
/// another flow is not ours to interpret. O(1) — two varints and a slice.
pub fn decode_ip_datagram(datagram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let (flow_id, rest) = varint::get(datagram)?;
    if flow_id != expected_flow_id {
        return None;
    }
    let (context, packet) = varint::get(rest)?;
    if context != IP_PACKET_CONTEXT {
        return None;
    }
    (!packet.is_empty()).then_some(packet)
}

/// A MASQUE CONNECT-IP tunnel as a sans-io packet egress.
pub struct MasqueEgress {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    h3_config: quiche::h3::Config,
    state: TunnelState,
    config: MasqueConfig,
    pool: Arc<BufferPool>,
    /// One scratch buffer for `quiche::Connection::send`, reused for the life
    /// of the egress so a packet costs no allocation for the space it is built
    /// in. Emissions are copied out of it into pooled buffers.
    scratch: Vec<u8>,
    /// One scratch buffer for building HTTP Datagram payloads.
    datagram: Vec<u8>,
    /// IP packets successfully handed to the tunnel. The MASQUE half of the
    /// fast-path counter `WireGuardEgress` keeps.
    fast_path_packets: u64,
}

impl MasqueEgress {
    /// Builds a tunnel over an already-configured `quiche` connection.
    ///
    /// The connection is the caller's to configure — ALPN, certificate
    /// verification, datagram queues, and transport parameters are deployment
    /// policy, not this type's — so it is passed in rather than built here.
    /// [`MasqueEgress::client_config`] provides the settings CONNECT-IP requires.
    pub fn new(
        conn: quiche::Connection,
        config: MasqueConfig,
        pool: Arc<BufferPool>,
        max_packet: usize,
    ) -> Result<Self, EgressError> {
        let mut h3_config = quiche::h3::Config::new().map_err(|_| EgressError::Masque)?;
        // The CONNECT-IP request is an Extended CONNECT (RFC 9220), so the
        // `:protocol` pseudo-header is only legal once this is negotiated.
        h3_config.enable_extended_connect(true);
        Ok(Self {
            conn,
            h3: None,
            h3_config,
            state: TunnelState::Connecting,
            config,
            pool,
            scratch: vec![0u8; max_packet],
            datagram: Vec::new(),
            fast_path_packets: 0,
        })
    }

    pub fn state(&self) -> &TunnelState {
        &self.state
    }

    /// Packets this tunnel carried without local termination.
    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// A `quiche::Config` with everything CONNECT-IP needs: the h3 ALPN,
    /// datagrams enabled in both directions, and the transport limits the
    /// control stream requires. Certificate verification is the caller's to
    /// set, because a test proxy and a production one differ there and nowhere
    /// else.
    pub fn client_config(max_idle: Duration, queue: usize) -> Result<quiche::Config, EgressError> {
        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| EgressError::Masque)?;
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|_| EgressError::Masque)?;
        // Datagrams are the entire data path: without them CONNECT-IP has
        // nothing to carry packets in.
        config.enable_dgram(true, queue, queue);
        config.set_max_idle_timeout(max_idle.as_millis() as u64);
        // The request stream carries only the CONNECT exchange and capsules,
        // so these are sized for control traffic rather than bulk transfer.
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        Ok(config)
    }

    /// Everything `quiche` wants to put on the wire, as pooled emissions.
    ///
    /// Exhaustion stops the drain rather than allocating: the remaining
    /// packets stay in `quiche`'s own send buffer and leave on the next call,
    /// which is the same congestion discipline the rest of the crate follows.
    fn drain_send(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        loop {
            match self.conn.send(&mut self.scratch) {
                Ok((written, _info)) => {
                    let Some(pooled) = self.pool.take(&self.scratch[..written]) else {
                        return Err(EgressError::PoolExhausted);
                    };
                    out.push(EgressEmit::ToNetwork(pooled));
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(_) => {
                    self.state = TunnelState::Closed(CloseReason::ConnectionClosed);
                    return Ok(());
                }
            }
        }
    }

    /// Advances the HTTP/3 layer: opens it once the handshake completes, sends
    /// the CONNECT-IP request, reads the proxy's answer, and harvests inbound
    /// datagrams as IP packets.
    fn advance(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        if self.conn.is_closed() {
            self.state = TunnelState::Closed(CloseReason::ConnectionClosed);
            return Ok(());
        }
        if !self.conn.is_established() {
            return Ok(());
        }

        if self.h3.is_none() {
            let mut h3 = quiche::h3::Connection::with_transport(&mut self.conn, &self.h3_config)
                .map_err(|_| EgressError::Masque)?;
            let request = [
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":protocol", self.config.protocol.as_bytes()),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", self.config.authority.as_bytes()),
                quiche::h3::Header::new(b":path", self.config.path.as_bytes()),
                // RFC 9297: the endpoint intends to use the capsule protocol on
                // this stream, which is what makes HTTP Datagrams legal on it.
                quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            ];
            // `fin: false` — the stream stays open for capsules and is what
            // keeps the tunnel alive.
            let stream_id = h3
                .send_request(&mut self.conn, &request, false)
                .map_err(|_| EgressError::Masque)?;
            // RFC 9297 §2.1: the Quarter Stream ID is the request stream's id
            // divided by four, which is what every datagram is prefixed with.
            self.state = TunnelState::Requested {
                flow_id: stream_id / 4,
            };
            self.h3 = Some(h3);
        }

        self.poll_h3()?;
        self.drain_datagrams(out);
        Ok(())
    }

    /// Reads whatever the HTTP/3 layer has to say. The only event that moves
    /// this tunnel's state is the response to its own CONNECT request.
    fn poll_h3(&mut self) -> Result<(), EgressError> {
        let Some(h3) = self.h3.as_mut() else {
            return Ok(());
        };
        loop {
            match h3.poll(&mut self.conn) {
                Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let status = list
                        .iter()
                        .find(|header| header.name() == b":status")
                        .and_then(|header| std::str::from_utf8(header.value()).ok())
                        .and_then(|value| value.parse::<u16>().ok());
                    let requested = match self.state {
                        TunnelState::Requested { flow_id } => Some(flow_id),
                        _ => None,
                    };
                    self.state = match (status, requested) {
                        (Some(status), Some(flow_id)) if (200..300).contains(&status) => {
                            TunnelState::Established { flow_id }
                        }
                        (Some(status), _) => TunnelState::Closed(CloseReason::Refused(status)),
                        (None, _) => TunnelState::Closed(CloseReason::Malformed),
                    };
                }
                // A CONNECT-IP tunnel carries its packets in datagrams; body
                // data on the request stream is capsule traffic this tunnel
                // does not implement, and finishing the stream ends it.
                Ok((_, quiche::h3::Event::Finished)) => {
                    self.state = TunnelState::Closed(CloseReason::ConnectionClosed);
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(_) => {
                    self.state = TunnelState::Closed(CloseReason::ConnectionClosed);
                    return Ok(());
                }
            }
        }
    }

    /// Turns inbound HTTP Datagrams into tunnel-bound IP packets. A datagram
    /// for another flow or context is skipped, not an error: a proxy may
    /// legitimately multiplex more than this tunnel understands.
    fn drain_datagrams(&mut self, out: &mut Vec<EgressEmit>) {
        let TunnelState::Established { flow_id } = self.state else {
            return;
        };
        loop {
            match self.conn.dgram_recv(&mut self.scratch) {
                Ok(len) => {
                    let Some(packet) = decode_ip_datagram(&self.scratch[..len], flow_id) else {
                        continue;
                    };
                    match self.pool.take(packet) {
                        Some(pooled) => out.push(EgressEmit::ToTunnel(pooled)),
                        // The budget is spent; the packet is a counted drop at
                        // the shell, exactly as a forwarded packet would be.
                        None => return,
                    }
                }
                Err(_) => return,
            }
        }
    }
}

impl PacketEgress for MasqueEgress {
    fn properties(&self) -> PathProperties {
        // Once the connection is up, `quiche` knows the real datagram ceiling;
        // before that there is only the static estimate. Reporting the
        // measured number when it exists is what keeps the inner MTU honest.
        let max_datagram_size = self
            .conn
            .dgram_max_writable_len()
            .and_then(|len| u16::try_from(len.saturating_sub(usize::from(PREFIX_BYTES))).ok());
        PathProperties {
            // CONNECT-IP carries whole IP packets, so a client's QUIC datagram
            // crosses as itself rather than being re-framed onto a stream.
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: MASQUE_OVERHEAD_BYTES,
            max_datagram_size,
            // The inner header's ECN crosses verbatim, but nothing propagates
            // it to the outer QUIC packet and no capture has verified either
            // direction. Claim nothing, as WireGuard does.
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        if let TunnelState::Established { flow_id } = self.state {
            encode_ip_datagram(flow_id, packet, &mut self.datagram);
            // A datagram that does not fit the path cannot be fragmented: QUIC
            // forbids it. Dropping is the honest answer and the reason
            // `max_datagram_size` is reported to the planner at all.
            if self.conn.dgram_send(&self.datagram).is_ok() {
                self.fast_path_packets += 1;
            }
        }
        // Before the tunnel is up the packet is dropped rather than queued: the
        // client's own retransmission is a better buffer than one here, and an
        // unbounded queue is what this crate refuses everywhere else.
        self.drain_send(out)
    }

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        // `recv` needs a mutable buffer and may rewrite it in place, so the
        // caller's borrowed datagram is copied into scratch space first.
        let mut owned = datagram.to_vec();
        let info = quiche::RecvInfo {
            from: self.config.peer,
            to: self.config.local,
        };
        match self.conn.recv(&mut owned, info) {
            Ok(_) => {}
            // Anything can arrive on a public UDP port; a datagram this
            // connection cannot parse is an observation, not a tunnel failure.
            Err(_) => return Err(EgressError::MalformedNetworkPacket),
        }
        self.advance(out)?;
        self.drain_send(out)
    }

    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        self.conn.on_timeout();
        self.advance(out)?;
        self.drain_send(out)
    }

    fn tick_interval(&self) -> Duration {
        MASQUE_TICK
    }

    /// QUIC's timer is a moving deadline set by loss recovery, not a cadence,
    /// so this is the number the reactor must actually arm against; a fixed
    /// interval would either burn wakeups or miss a retransmission.
    fn next_deadline(&self) -> Option<Instant> {
        self.conn.timeout().map(|left| Instant::now() + left)
    }
}

/// Worst-case bytes the two varints add in front of an IP packet: a 4-byte
/// flow id and a 1-byte context.
const PREFIX_BYTES: u16 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_datagram_codec_round_trips_and_refuses_what_is_not_ours() {
        let packet = [0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];
        // Every varint width the flow id can take, so the prefix length is
        // exercised rather than assumed.
        for flow_id in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut encoded = Vec::new();
            encode_ip_datagram(flow_id, &packet, &mut encoded);
            assert_eq!(
                decode_ip_datagram(&encoded, flow_id),
                Some(&packet[..]),
                "flow {flow_id} must round-trip"
            );
            // A datagram belonging to another flow is not ours to interpret.
            assert_eq!(decode_ip_datagram(&encoded, flow_id.wrapping_add(1)), None);
        }

        // Context 1 is a capsule this tunnel does not implement.
        let mut other_context = Vec::new();
        varint::put(4, &mut other_context);
        varint::put(1, &mut other_context);
        other_context.extend_from_slice(&packet);
        assert_eq!(decode_ip_datagram(&other_context, 4), None);

        // Truncated input is `None`, never a panic: these bytes are untrusted.
        assert_eq!(decode_ip_datagram(&[], 0), None);
        assert_eq!(decode_ip_datagram(&[0x40], 0), None);
        let mut empty_payload = Vec::new();
        varint::put(4, &mut empty_payload);
        varint::put(0, &mut empty_payload);
        assert_eq!(decode_ip_datagram(&empty_payload, 4), None);
    }

    /// A minimal MASQUE proxy: a real `quiche` server that accepts one
    /// CONNECT-IP request and reflects every IP packet it is given back down
    /// the same flow. Enough to prove the wire, and nothing more.
    struct Proxy {
        conn: quiche::Connection,
        h3: Option<quiche::h3::Connection>,
        flow_id: Option<u64>,
        scratch: Vec<u8>,
    }

    impl Proxy {
        /// Feeds one client datagram in and returns everything the proxy wants
        /// to send back.
        fn exchange(&mut self, incoming: Option<&[u8]>) -> Vec<Vec<u8>> {
            if let Some(datagram) = incoming {
                let mut owned = datagram.to_vec();
                let info = quiche::RecvInfo {
                    from: client_addr(),
                    to: proxy_addr(),
                };
                let _ = self.conn.recv(&mut owned, info);
            }

            if self.conn.is_established() && self.h3.is_none() {
                let mut config = quiche::h3::Config::new().unwrap();
                config.enable_extended_connect(true);
                self.h3 = quiche::h3::Connection::with_transport(&mut self.conn, &config).ok();
            }

            if let Some(h3) = self.h3.as_mut() {
                while let Ok((stream_id, event)) = h3.poll(&mut self.conn) {
                    if let quiche::h3::Event::Headers { list, .. } = event {
                        // Answer only a well-formed CONNECT-IP request, so the
                        // test proves the client sent one.
                        let method = header(&list, b":method");
                        let protocol = header(&list, b":protocol");
                        assert_eq!(method.as_deref(), Some("CONNECT"));
                        assert_eq!(protocol.as_deref(), Some(MasqueConfig::STANDARD_PROTOCOL));
                        let response = [quiche::h3::Header::new(b":status", b"200")];
                        h3.send_response(&mut self.conn, stream_id, &response, false)
                            .unwrap();
                        self.flow_id = Some(stream_id / 4);
                    }
                }
            }

            // Reflect every IP packet back on the same flow.
            if let Some(flow_id) = self.flow_id {
                while let Ok(len) = self.conn.dgram_recv(&mut self.scratch) {
                    let Some(packet) = decode_ip_datagram(&self.scratch[..len], flow_id) else {
                        continue;
                    };
                    let mut echoed = Vec::new();
                    encode_ip_datagram(flow_id, packet, &mut echoed);
                    let _ = self.conn.dgram_send(&echoed);
                }
            }

            let mut out = Vec::new();
            loop {
                let mut buf = vec![0u8; 1350];
                match self.conn.send(&mut buf) {
                    Ok((written, _)) => {
                        buf.truncate(written);
                        out.push(buf);
                    }
                    Err(_) => break,
                }
            }
            out
        }
    }

    fn header(list: &[quiche::h3::Header], name: &[u8]) -> Option<String> {
        list.iter()
            .find(|header| header.name() == name)
            .and_then(|header| String::from_utf8(header.value().to_vec()).ok())
    }

    fn client_addr() -> SocketAddr {
        "192.0.2.10:44444".parse().unwrap()
    }

    fn proxy_addr() -> SocketAddr {
        "198.51.100.7:443".parse().unwrap()
    }

    /// The credentials `quiche` loads from disk, from the shared test
    /// helpers: `quiche` offers no in-memory form, and two modules need one.
    fn proxy_certificate() -> (
        std::path::PathBuf,
        std::path::PathBuf,
        crate::testing::TempDir,
    ) {
        crate::testing::self_signed("proxy.example")
    }

    /// The P17 mechanism gate, in process: a real QUIC handshake, a real
    /// Extended CONNECT carrying `:protocol = connect-ip`, and an IP packet
    /// that crosses as an HTTP Datagram and comes back byte-identical.
    #[test]
    fn an_ip_packet_round_trips_through_a_real_connect_ip_tunnel() {
        let (cert_path, key_path, _dir) = proxy_certificate();

        let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        server_config
            .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
            .unwrap();
        server_config
            .load_priv_key_from_pem_file(key_path.to_str().unwrap())
            .unwrap();
        server_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        server_config.enable_dgram(true, 64, 64);
        server_config.set_max_idle_timeout(5_000);
        server_config.set_initial_max_data(1_000_000);
        server_config.set_initial_max_stream_data_bidi_local(100_000);
        server_config.set_initial_max_stream_data_bidi_remote(100_000);
        server_config.set_initial_max_stream_data_uni(100_000);
        server_config.set_initial_max_streams_bidi(16);
        server_config.set_initial_max_streams_uni(16);

        let mut client_config = MasqueEgress::client_config(Duration::from_secs(5), 64).unwrap();
        // The proxy's certificate is self-signed for this test; production
        // verification is the caller's to configure, which is exactly why
        // `client_config` does not decide it.
        client_config.verify_peer(false);

        let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
        let client_conn = quiche::connect(
            Some("proxy.example"),
            &scid,
            client_addr(),
            proxy_addr(),
            &mut client_config,
        )
        .unwrap();

        let server_scid = quiche::ConnectionId::from_ref(&[0xab; 16]);
        let server_conn = quiche::accept(
            &server_scid,
            None,
            proxy_addr(),
            client_addr(),
            &mut server_config,
        )
        .unwrap();
        let mut proxy = Proxy {
            conn: server_conn,
            h3: None,
            flow_id: None,
            scratch: vec![0u8; 2048],
        };

        let pool = BufferPool::new(
            std::num::NonZeroUsize::new(2048).unwrap(),
            std::num::NonZeroUsize::new(256).unwrap(),
        );
        let config = MasqueConfig {
            peer: proxy_addr(),
            local: client_addr(),
            server_name: "proxy.example".to_owned(),
            authority: "proxy.example".to_owned(),
            path: "/".to_owned(),
            protocol: MasqueConfig::STANDARD_PROTOCOL.to_owned(),
            nat_behavior: NatBehavior::EndpointIndependent,
        };
        let mut egress = MasqueEgress::new(client_conn, config, Arc::clone(&pool), 1350).unwrap();

        // Drive the handshake and the CONNECT exchange to completion.
        let mut out = Vec::new();
        egress.tick(&mut out).unwrap();
        for _ in 0..16 {
            let mut to_proxy = Vec::new();
            for emit in out.drain(..) {
                match emit {
                    EgressEmit::ToNetwork(bytes) => to_proxy.push(bytes.to_vec()),
                    EgressEmit::ToTunnel(_) => panic!("nothing is tunnelled yet"),
                }
            }
            let mut replies = Vec::new();
            if to_proxy.is_empty() {
                replies.extend(proxy.exchange(None));
            }
            for datagram in &to_proxy {
                replies.extend(proxy.exchange(Some(datagram)));
            }
            for reply in replies {
                let _ = egress.handle_network_packet(&reply, &mut out);
            }
            if matches!(egress.state(), TunnelState::Established { .. }) {
                break;
            }
        }
        assert!(
            matches!(egress.state(), TunnelState::Established { .. }),
            "the proxy accepted CONNECT-IP, state is {:?}",
            egress.state()
        );

        // Once the tunnel is up the planner sees a real datagram ceiling
        // rather than only the static estimate.
        let properties = egress.properties();
        assert_eq!(properties.datagram_fidelity, DatagramFidelity::Native);
        assert!(
            properties.max_datagram_size.is_some_and(|size| size > 0),
            "an established tunnel reports its measured ceiling"
        );

        // The gate: a whole IP packet crosses as an HTTP Datagram and returns
        // byte-identical.
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];
        out.clear();
        egress.handle_tun_packet(&packet, &mut out).unwrap();
        assert_eq!(egress.fast_path_packets(), 1);

        let mut returned: Vec<Vec<u8>> = Vec::new();
        for _ in 0..8 {
            let mut to_proxy = Vec::new();
            for emit in out.drain(..) {
                match emit {
                    EgressEmit::ToNetwork(bytes) => to_proxy.push(bytes.to_vec()),
                    EgressEmit::ToTunnel(bytes) => returned.push(bytes.to_vec()),
                }
            }
            let mut replies = Vec::new();
            for datagram in &to_proxy {
                replies.extend(proxy.exchange(Some(datagram)));
            }
            for reply in replies {
                let _ = egress.handle_network_packet(&reply, &mut out);
            }
            if !returned.is_empty() {
                break;
            }
        }
        for emit in out.drain(..) {
            if let EgressEmit::ToTunnel(bytes) = emit {
                returned.push(bytes.to_vec());
            }
        }
        assert_eq!(
            returned,
            vec![packet.to_vec()],
            "the tunnelled packet came back exactly as it went out"
        );
    }
}
