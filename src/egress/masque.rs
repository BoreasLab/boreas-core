//! MASQUE CONNECT-IP (RFC 9484) packet egress.
//!
//! TUN packets become HTTP Datagrams on a QUIC connection, and peer datagrams
//! become packets for the client. `quiche` supplies the sans-IO QUIC state;
//! [`PacketEgress`] supplies bytes and explicit timer ticks around it.
//!
//! HTTP Datagrams carry `varint(flow_id) || varint(0) || packet`: RFC 9297's
//! Quarter Stream ID followed by RFC 9484's IP-packet context. A flow ID is
//! usable only in [`TunnelState::Established`], after a successful CONNECT.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use quiche::h3::NameValue;

use crate::{
    BufferPool, DatagramFidelity, EgressEmit, EgressError, NatBehavior, PacketEgress,
    PathProperties,
    wire::{Reader, Writer},
};

/// RFC 9484 context ID for a complete IP packet.
const IP_PACKET_CONTEXT: u64 = 0;

/// Static worst-case encapsulation overhead before a connection is established.
/// An established connection reports its measured ceiling from `quiche`.
pub const MASQUE_OVERHEAD_BYTES: u16 = 40 + 8 + 1 + 20 + 4 + 16 + 3 + 5;

/// Backstop tick interval when QUIC has no more precise deadline.
const MASQUE_TICK: Duration = Duration::from_millis(250);

/// Configuration for one MASQUE proxy.
pub struct MasqueConfig {
    /// Proxy UDP endpoint.
    pub peer: SocketAddr,
    /// Local address reported to QUIC; this type does not bind it.
    pub local: SocketAddr,
    /// SNI and certificate-verification name.
    pub server_name: String,
    /// CONNECT request authority.
    pub authority: String,
    /// CONNECT request path.
    pub path: String,
    /// CONNECT request protocol identifier.
    pub protocol: String,
    /// RFC 4787 mapping behavior provided by the proxy.
    pub nat_behavior: NatBehavior,
}

impl MasqueConfig {
    /// RFC 9484 protocol identifier.
    pub const STANDARD_PROTOCOL: &'static str = "connect-ip";
    /// Cloudflare WARP protocol identifier.
    pub const CLOUDFLARE_PROTOCOL: &'static str = "cf-connect-ip";
}

/// Terminal reason a tunnel is no longer usable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// CONNECT returned a non-2xx status.
    Refused(u16),
    /// QUIC connection closed.
    ConnectionClosed,
    /// Response was not a valid CONNECT-IP response.
    Malformed,
}

/// MASQUE tunnel lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelState {
    /// QUIC handshake in progress; no CONNECT request sent.
    Connecting,
    /// CONNECT request sent; waiting for the response.
    Requested {
        flow_id: u64,
    },
    /// CONNECT accepted; `flow_id` prefixes every HTTP Datagram.
    Established {
        flow_id: u64,
    },
    Closed(CloseReason),
}

/// Writes one IP packet as a CONNECT-IP HTTP Datagram payload.
pub fn encode_ip_datagram(flow_id: u64, packet: &[u8], out: &mut Vec<u8>) {
    out.clear();
    Writer::new(out)
        .varint(flow_id)
        .varint(IP_PACKET_CONTEXT)
        .bytes(packet);
}

/// Reads an IP packet belonging to the expected flow and context.
pub fn decode_ip_datagram(datagram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let mut reader = Reader::new(datagram);
    if reader.varint()? != expected_flow_id {
        return None;
    }
    if reader.varint()? != IP_PACKET_CONTEXT {
        return None;
    }
    let packet = reader.rest();
    (!packet.is_empty()).then_some(packet)
}

/// Sans-IO MASQUE CONNECT-IP packet egress.
pub struct MasqueEgress {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    h3_config: quiche::h3::Config,
    state: TunnelState,
    config: MasqueConfig,
    pool: Arc<BufferPool>,
    /// Reusable buffer for QUIC packets; emissions are copied into pool buffers.
    scratch: Vec<u8>,
    /// Reusable buffer for HTTP Datagram payloads.
    datagram: Vec<u8>,
    /// IP packets handed to the tunnel without local termination.
    fast_path_packets: u64,
}

impl MasqueEgress {
    /// Builds a tunnel around an already-configured `quiche` connection.
    /// The caller owns ALPN, certificate verification, queues, and transport
    /// parameters; [`MasqueEgress::client_config`] supplies CONNECT-IP defaults.
    pub fn new(
        conn: quiche::Connection,
        config: MasqueConfig,
        pool: Arc<BufferPool>,
        max_packet: usize,
    ) -> Result<Self, EgressError> {
        let mut h3_config = quiche::h3::Config::new().map_err(|_| EgressError::Masque)?;
        // CONNECT-IP uses the RFC 9220 extended CONNECT form.
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

    /// Number of packets carried without local termination.
    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// Builds a QUIC configuration with HTTP/3, bidirectional datagrams, and
    /// transport limits for the CONNECT control stream. The caller configures
    /// certificate verification.
    pub fn client_config(max_idle: Duration, queue: usize) -> Result<quiche::Config, EgressError> {
        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| EgressError::Masque)?;
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|_| EgressError::Masque)?;
        // CONNECT-IP carries packets only through QUIC datagrams.
        config.enable_dgram(true, queue, queue);
        config.set_max_idle_timeout(max_idle.as_millis() as u64);
        // The request stream carries control traffic, not packet payloads.
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        Ok(config)
    }

    /// Drains QUIC output into pooled emissions.
    /// Pool exhaustion leaves unsent data in `quiche` for the next call.
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

    /// Advances HTTP/3, sends CONNECT-IP after the handshake, and drains peer
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
                // RFC 9297 requires this indication for HTTP Datagrams.
                quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            ];
            // Keep the request stream open for the tunnel lifetime.
            let stream_id = h3
                .send_request(&mut self.conn, &request, false)
                .map_err(|_| EgressError::Masque)?;
            // RFC 9297 uses the request stream ID divided by four as the prefix.
            self.state = TunnelState::Requested {
                flow_id: stream_id / 4,
            };
            self.h3 = Some(h3);
        }

        self.poll_h3()?;
        self.drain_datagrams(out);
        Ok(())
    }

    /// Processes HTTP/3 events relevant to this tunnel's CONNECT request.
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
                // The request stream carries no packet body; finishing it closes
                // the tunnel.
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

    /// Converts matching HTTP Datagrams into tunnel-bound IP packets. Other
    /// flows and contexts are ignored because the proxy may multiplex them.
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
                        // Stop when the packet pool cannot accept another packet.
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
        // Use the measured QUIC ceiling once available; otherwise use the
        // pre-connection estimate.
        let max_datagram_size = self
            .conn
            .dgram_max_writable_len()
            .and_then(|len| u16::try_from(len.saturating_sub(usize::from(PREFIX_BYTES))).ok());
        PathProperties {
            // Whole IP packets retain datagram boundaries through CONNECT-IP.
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: MASQUE_OVERHEAD_BYTES,
            max_datagram_size,
            // ECN preservation is not established for either direction.
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
            // QUIC datagrams cannot be fragmented; an oversized packet is
            // dropped and the planner receives the reported size limit.
            if self.conn.dgram_send(&self.datagram).is_ok() {
                self.fast_path_packets += 1;
            }
        }
        // Do not queue packets while CONNECT is pending; retransmission belongs
        // to the client and this egress has no unbounded buffer.
        self.drain_send(out)
    }

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        // `recv` may rewrite its input, so copy the caller's datagram first.
        let mut owned = datagram.to_vec();
        let info = quiche::RecvInfo {
            from: self.config.peer,
            to: self.config.local,
        };
        match self.conn.recv(&mut owned, info) {
            Ok(_) => {}
            // An unparsable packet on the shared UDP path is not a tunnel error.
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

    /// Returns QUIC's loss-recovery deadline for reactor scheduling.
    fn next_deadline(&self) -> Option<Instant> {
        self.conn.timeout().map(|left| Instant::now() + left)
    }
}

/// Maximum prefix size for a flow ID and the IP-packet context.
const PREFIX_BYTES: u16 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_datagram_codec_round_trips_and_refuses_what_is_not_ours() {
        let packet = [0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];
        // Cover every encoded width used by flow IDs.
        for flow_id in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut encoded = Vec::new();
            encode_ip_datagram(flow_id, &packet, &mut encoded);
            assert_eq!(
                decode_ip_datagram(&encoded, flow_id),
                Some(&packet[..]),
                "flow {flow_id} must round-trip"
            );
            // A different flow is not this tunnel's payload.
            assert_eq!(decode_ip_datagram(&encoded, flow_id.wrapping_add(1)), None);
        }

        // Context 1 is not an IP packet. These literal bytes check the wire
        // representation independently of the encoder.
        let mut other_context = vec![0x04, 0x01];
        other_context.extend_from_slice(&packet);
        assert_eq!(decode_ip_datagram(&other_context, 4), None);

        // Untrusted truncated input must return `None`, not panic.
        assert_eq!(decode_ip_datagram(&[], 0), None);
        assert_eq!(decode_ip_datagram(&[0x40], 0), None);
        // Flow 4 and context 0 without a packet is incomplete.
        assert_eq!(decode_ip_datagram(&[0x04, 0x00], 4), None);
    }

    /// Minimal real `quiche` proxy for one CONNECT-IP request and packet echo.
    struct Proxy {
        conn: quiche::Connection,
        h3: Option<quiche::h3::Connection>,
        flow_id: Option<u64>,
        scratch: Vec<u8>,
    }

    impl Proxy {
        /// Feeds one client datagram and returns the proxy's pending output.
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
                        // The assertions verify the client's CONNECT request.
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

            // Echo matching packets on the same flow.
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

    /// Creates the certificate files required by `quiche`'s test server.
    fn proxy_certificate() -> (
        std::path::PathBuf,
        std::path::PathBuf,
        crate::testing::TempDir,
    ) {
        crate::testing::self_signed("proxy.example")
    }

    /// Verifies a real QUIC handshake, Extended CONNECT, and packet echo.
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
        // The test proxy is self-signed; production verification belongs to the
        // caller of `client_config`.
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

        // Drive the handshake and CONNECT exchange.
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

        // An established tunnel exposes the measured datagram ceiling.
        let properties = egress.properties();
        assert_eq!(properties.datagram_fidelity, DatagramFidelity::Native);
        assert!(
            properties.max_datagram_size.is_some_and(|size| size > 0),
            "an established tunnel reports its measured ceiling"
        );

        // Verify that a whole IP packet crosses and returns byte-identically.
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
