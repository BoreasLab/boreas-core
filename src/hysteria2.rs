//! Hysteria2 as a stream egress.
//!
//! One QUIC connection to the server, authenticated once, carrying every flow
//! as a bidirectional stream. That shape is what makes it worth having: on a
//! lossy long-RTT path a proxy that multiplexes over QUIC does not head-of-line
//! block one flow behind another's retransmit, which every TCP-carried protocol
//! in this crate does.
//!
//! **There is no specification, so the reference implementation is the
//! specification.** Hysteria2 is defined by its implementation rather than by
//! an RFC, so every constant and every field order here was read out of
//! [sing-quic](https://github.com/SagerNet/sing-quic)'s `hysteria2` package
//! before it was written, and then checked against a running server by
//! `tests/interop.rs`. A protocol with no written-down wire format is one where
//! self-testing proves the least.
//!
//! **Authentication is an ordinary HTTP/3 request, and then HTTP/3 is done.**
//! The client `POST`s to `https://hysteria/auth` with the password in a header
//! and expects status **233**, which is not an HTTP status code — it is a
//! sentinel chosen so that anything scanning the endpoint, including a browser,
//! gets a response indistinguishable from a plain web server's. After that the
//! connection carries raw streams; see [`crate::quic`] for why the HTTP/3 layer
//! must be dropped before the first one is opened.
//!
//! **Padding is mandatory on both messages**, which is a lesson this crate has
//! already paid for once: Shadowsocks 2022 rejected our sessions because a
//! header with neither payload nor padding leaks its length exactly. Hysteria2
//! pads for the same reason, and the sizes here are the reference's own ranges
//! rather than invented ones, because a *different* padding distribution is
//! itself a fingerprint.

use std::{net::SocketAddr, ops::Range, time::Duration};

use ring::rand::SecureRandom;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::{
    AsyncStream, BoxFuture, DatagramFidelity, Decoded, EgressCapabilities, EgressError,
    NatBehavior, Prefixed, ProxyError, StreamEgress, Target, TunnelBypass,
    quic::{Handshake, QuicConnection, client_config},
    varint,
};

/// The `:authority` and `:path` the authentication request carries. Fixed
/// strings, not a real host: the request never leaves the QUIC connection it is
/// sent on, so the authority names the protocol rather than a name to resolve.
const AUTH_AUTHORITY: &str = "hysteria";
const AUTH_PATH: &str = "/auth";

/// Header names, lowercase because HTTP/3 requires it.
const HEADER_AUTH: &[u8] = b"hysteria-auth";
const HEADER_CC_RX: &[u8] = b"hysteria-cc-rx";
const HEADER_PADDING: &[u8] = b"hysteria-padding";
/// Whether the server will carry datagrams. Read and reported rather than
/// acted on, because this egress does not implement Hysteria2's UDP yet.
const HEADER_UDP: &str = "hysteria-udp";

/// Authentication succeeded. Deliberately not a real HTTP status: a probe that
/// is not a Hysteria2 client sees an ordinary rejection instead.
const STATUS_AUTH_OK: u16 = 233;

/// The frame type that opens a TCP proxy stream.
const FRAME_TCP_REQUEST: u64 = 0x401;

/// Ceilings from the reference, which exist so a hostile server cannot make a
/// client allocate without bound. They are checked here for the same reason:
/// a length is a promise from an untrusted peer.
const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_MESSAGE_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;

/// Padding sizes, half-open exactly as the reference writes them. Matching the
/// distribution matters as much as padding at all: a client whose padding is
/// uniformly the wrong width is more identifiable than one that does not pad.
const AUTH_PADDING: Range<usize> = 256..2048;
const REQUEST_PADDING: Range<usize> = 64..512;

/// The alphabet the reference pads with. ASCII alphanumerics, so the padding
/// looks like the header values around it rather than like a block of entropy.
const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// How long a connection may sit idle before QUIC closes it. The reference uses
/// 30 seconds with a 10-second keepalive; this is the same ceiling, and the
/// driver's timer handles the rest.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Random padding of a length drawn from `range`.
///
/// Both the length and the contents are random, and both come from the same
/// CSPRNG the rest of the crate uses. O(range.end).
fn padding(range: Range<usize>) -> Result<Vec<u8>, ProxyError> {
    let random = ring::rand::SystemRandom::new();
    let mut choice = [0u8; 2];
    random.fill(&mut choice).map_err(|_| ProxyError::Crypto)?;
    let span = range.end - range.start;
    let length = range.start + usize::from(u16::from_be_bytes(choice)) % span;

    let mut bytes = vec![0u8; length];
    random.fill(&mut bytes).map_err(|_| ProxyError::Crypto)?;
    for byte in &mut bytes {
        // Modulo bias over a 62-symbol alphabet is irrelevant here: the padding
        // conveys nothing, and only its length is observable on the wire.
        *byte = PADDING_ALPHABET[usize::from(*byte) % PADDING_ALPHABET.len()];
    }
    Ok(bytes)
}

/// Writes the frame that opens a proxy stream.
///
/// `varint(0x401) || varint(len) || address || varint(len) || padding`, where
/// the address is the target's text form — `host:port`, with an IPv6 literal
/// bracketed. Hysteria2 sends a *string* rather than a typed address, which is
/// why this shares nothing with SOCKS5's or VLESS's encoders.
///
/// Padding is a parameter rather than generated here so the encoder stays pure
/// and its output is a function of its inputs, which is what lets a test assert
/// the layout byte for byte.
///
/// O(address length + padding length).
pub fn encode_tcp_request(target: &Target, padding: &[u8], out: &mut Vec<u8>) {
    let address = target.to_string();
    varint::put(FRAME_TCP_REQUEST, out);
    varint::put(address.len() as u64, out);
    out.extend_from_slice(address.as_bytes());
    varint::put(padding.len() as u64, out);
    out.extend_from_slice(padding);
}

/// What the server answered when asked to open a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpResponse {
    pub ok: bool,
    /// The server's explanation when it refused. Empty on success, and capped
    /// at the protocol's 2048-byte ceiling by the decoder.
    pub message: String,
}

/// Reads the response frame: `status || vstring(message) || vbytes(padding)`.
///
/// [`Decoded::Incomplete`] for every proper prefix, so a caller can read and
/// retry; the `consumed` count is what lets it keep the payload that followed.
///
/// O(message length + padding length), and it allocates only for the message.
pub fn decode_tcp_response(bytes: &[u8]) -> Result<Decoded<TcpResponse>, ProxyError> {
    let Some((&status, rest)) = bytes.split_first() else {
        return Ok(Decoded::Incomplete);
    };
    let Some((message_len, rest)) = varint::get(rest) else {
        return Ok(Decoded::Incomplete);
    };
    if message_len > MAX_MESSAGE_LEN {
        return Err(ProxyError::Header);
    }
    let Some(message) = rest.get(..message_len as usize) else {
        return Ok(Decoded::Incomplete);
    };
    let rest = &rest[message_len as usize..];
    let Some((padding_len, rest)) = varint::get(rest) else {
        return Ok(Decoded::Incomplete);
    };
    if padding_len > MAX_PADDING_LEN {
        return Err(ProxyError::Header);
    }
    if rest.len() < padding_len as usize {
        return Ok(Decoded::Incomplete);
    }
    // A message that is not UTF-8 is a malformed frame rather than a lossy
    // one: it is the server's own diagnostic text, and mangling it would put
    // replacement characters into an operator's logs.
    let message = std::str::from_utf8(message)
        .map_err(|_| ProxyError::Header)?
        .to_owned();
    Ok(Decoded::Complete {
        value: TcpResponse {
            // The reference treats every non-zero status as a refusal.
            ok: status == 0,
            message,
        },
        consumed: bytes.len() - rest.len() + padding_len as usize,
    })
}

/// Static configuration for one Hysteria2 server.
pub struct Hysteria2Config {
    /// The server's UDP endpoint.
    pub server: SocketAddr,
    /// The name presented in SNI and verified against the server's certificate.
    pub server_name: String,
    /// The shared password, sent verbatim in the authentication header.
    pub password: String,
    /// What RFC 4787 mapping behavior the server's own egress provides.
    ///
    /// Configuration for the same reason MASQUE's and SOCKS5's are: the mapping
    /// belongs to the server and is unobservable from here, so the planner is
    /// entitled to a measured claim rather than an optimistic constant.
    pub nat_behavior: NatBehavior,
}

/// Builds the `quiche::Config` for one connection.
///
/// A factory rather than a value because `quiche::Config` is neither `Clone`
/// nor reusable across connections, and this egress redials when its connection
/// dies. Certificate verification is set here, by the caller, for the same
/// reason it is for MASQUE: a test server and a production one differ there and
/// nowhere else.
pub type QuicConfigFactory = Box<dyn Fn() -> Result<quiche::Config, EgressError> + Send + Sync>;

/// A Hysteria2 server as a stream egress.
pub struct Hysteria2Egress<B> {
    config: Hysteria2Config,
    bypass: B,
    quic: QuicConfigFactory,
    /// The shared connection every flow rides on. An async mutex because
    /// establishing one awaits, and because two flows arriving together must
    /// produce *one* connection rather than two — the second waits and finds
    /// the first's.
    connection: Mutex<Option<QuicConnection>>,
    /// Cancels the driver task. Held here so the connection's lifetime is the
    /// egress's: dropping the egress ends the task rather than leaving it
    /// holding a socket nobody can reach.
    shutdown: CancellationToken,
}

impl<B> Drop for Hysteria2Egress<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<B: TunnelBypass> Hysteria2Egress<B> {
    pub fn new(config: Hysteria2Config, bypass: B, quic: QuicConfigFactory) -> Self {
        Self {
            config,
            bypass,
            quic,
            connection: Mutex::new(None),
            shutdown: CancellationToken::new(),
        }
    }

    /// A `quiche::Config` with Hysteria2's ALPN and the idle timeout the
    /// reference uses, ready for a caller to set verification on.
    pub fn quic_config() -> Result<quiche::Config, EgressError> {
        client_config(quiche::h3::APPLICATION_PROTOCOL, IDLE_TIMEOUT)
    }

    /// The live connection, dialling and authenticating one if there is none.
    ///
    /// Holding the lock across the handshake is deliberate: it is what makes
    /// concurrent first flows share a connection instead of racing to build
    /// two, and a second connection would mean a second authentication and a
    /// second socket for no gain.
    async fn connection(&self) -> Result<QuicConnection, EgressError> {
        let mut held = self.connection.lock().await;
        if let Some(connection) = held.as_ref()
            && connection.is_alive()
        {
            return Ok(connection.clone());
        }

        let socket = self.bypass.udp(self.config.server).await?;
        let mut handshake = Handshake::establish(
            socket,
            self.config.server,
            &self.config.server_name,
            (self.quic)()?,
        )
        .await?;

        let pad = padding(AUTH_PADDING)?;
        let response = handshake
            .http3(&[
                quiche::h3::Header::new(b":method", b"POST"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", AUTH_AUTHORITY.as_bytes()),
                quiche::h3::Header::new(b":path", AUTH_PATH.as_bytes()),
                quiche::h3::Header::new(HEADER_AUTH, self.config.password.as_bytes()),
                // Zero means "I do not know my own receive bandwidth, use
                // congestion control". Honest: this client runs `quiche`'s
                // CUBIC rather than Hysteria's Brutal, which is a sender-side
                // rate the server would otherwise trust us to have measured.
                quiche::h3::Header::new(HEADER_CC_RX, b"0"),
                quiche::h3::Header::new(HEADER_PADDING, &pad),
            ])
            .await?;

        if response.status != STATUS_AUTH_OK {
            return Err(ProxyError::AuthFailed.into());
        }
        let connection = handshake.drive(self.shutdown.clone());
        *held = Some(connection.clone());
        Ok(connection)
    }

    /// Whether the server said it will carry datagrams. Recorded for when
    /// Hysteria2's UDP lands; nothing reads it yet, and [`Self::capabilities`]
    /// says so rather than claiming otherwise.
    pub fn udp_header() -> &'static str {
        HEADER_UDP
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for Hysteria2Egress<B> {
    fn capabilities(&self) -> EgressCapabilities {
        EgressCapabilities {
            // Hysteria2 does carry datagrams, and this egress does not yet
            // implement them. The claim describes the code, not the protocol:
            // `associate` refuses, and those two must agree or the planner
            // steers a QUIC flow into an egress that will drop it.
            datagram_fidelity: DatagramFidelity::None,
            // A terminated path re-originates the byte stream, so the client's
            // packet size stops existing and there is no per-packet header to
            // charge for.
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            if target.to_string().len() as u64 > MAX_ADDRESS_LEN {
                return Err(ProxyError::Address.into());
            }
            let connection = self.connection().await?;
            let mut stream = connection.open_bidi().await?;

            let mut request = Vec::with_capacity(128);
            encode_tcp_request(target, &padding(REQUEST_PADDING)?, &mut request);
            stream.write_all(&request).await?;
            stream.flush().await?;

            // **The response is read here rather than lazily**, which costs one
            // round trip before `connect` returns and buys an honest error: a
            // refusal becomes a failed dial, as it does for SOCKS5, instead of
            // surfacing later as an unexplained read error on a stream the
            // caller has already committed to.
            let mut buf = Vec::with_capacity(256);
            let mut chunk = [0u8; 512];
            let response = loop {
                match decode_tcp_response(&buf)? {
                    Decoded::Complete { value, consumed } => {
                        buf.drain(..consumed);
                        break value;
                    }
                    Decoded::Incomplete => {}
                }
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(EgressError::Io(std::io::ErrorKind::UnexpectedEof));
                }
                buf.extend_from_slice(&chunk[..read]);
            };
            if !response.ok {
                return Err(ProxyError::Denied(response.message).into());
            }
            // Anything past the response frame is the target's first payload,
            // which coalesces into the same stream write for every server-first
            // protocol. Replaying it is what keeps a banner from vanishing.
            Ok(Box::new(Prefixed::new(buf, stream)) as Box<dyn AsyncStream>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainName;

    /// The request layout, byte for byte, against a hand-written expectation.
    /// Padding is passed in rather than generated so this is a total function
    /// of its inputs and the assertion can be exact.
    #[test]
    fn a_tcp_request_is_the_frame_type_then_two_length_prefixed_fields() {
        let target = Target::Domain {
            host: DomainName::new("example.com").unwrap(),
            port: 443,
        };
        let mut out = Vec::new();
        encode_tcp_request(&target, b"pad", &mut out);
        assert_eq!(
            out,
            [
                // 0x401 needs the two-byte varint form: 0x40 | 0x04, 0x01.
                &[0x44, 0x01][..],
                &[15][..],
                b"example.com:443",
                &[3][..],
                b"pad",
            ]
            .concat()
        );
    }

    /// An IPv6 target must be bracketed, because the address form is a *string*
    /// and `::1:443` would otherwise be ambiguous with the address itself. This
    /// is `SocketAddr`'s own `Display`, and the test pins that it stays so.
    #[test]
    fn an_ipv6_target_is_bracketed_in_the_address_string() {
        let target = Target::Ip("[::1]:8080".parse().unwrap());
        let mut out = Vec::new();
        encode_tcp_request(&target, b"", &mut out);
        assert!(
            out.windows(10).any(|window| window == b"[::1]:8080"),
            "encoded as {out:?}"
        );
    }

    /// The law every streaming decoder in this crate obeys: no proper prefix
    /// decodes, the whole message does, and `consumed` is exact so the caller
    /// can keep what followed.
    #[test]
    fn every_proper_prefix_of_a_response_is_incomplete() {
        let mut frame = vec![0u8];
        varint::put(2, &mut frame);
        frame.extend_from_slice(b"ok");
        varint::put(4, &mut frame);
        frame.extend_from_slice(b"pppp");

        for cut in 0..frame.len() {
            assert_eq!(
                decode_tcp_response(&frame[..cut]),
                Ok(Decoded::Incomplete),
                "a {cut}-byte prefix decoded"
            );
        }
        assert_eq!(
            decode_tcp_response(&frame),
            Ok(Decoded::Complete {
                value: TcpResponse {
                    ok: true,
                    message: "ok".to_owned(),
                },
                consumed: frame.len(),
            })
        );

        // The payload that follows must be reported as surplus rather than
        // swallowed, which is the whole point of `consumed`.
        let mut with_payload = frame.clone();
        with_payload.extend_from_slice(b"SSH-2.0-OpenSSH");
        assert_eq!(
            decode_tcp_response(&with_payload),
            Ok(Decoded::Complete {
                value: TcpResponse {
                    ok: true,
                    message: "ok".to_owned(),
                },
                consumed: frame.len(),
            })
        );
    }

    /// A refusal carries the server's reason, and a non-zero status is what
    /// makes it a refusal.
    #[test]
    fn a_non_zero_status_is_a_refusal_carrying_its_message() {
        let mut frame = vec![1u8];
        varint::put(7, &mut frame);
        frame.extend_from_slice(b"refused");
        varint::put(0, &mut frame);
        let Ok(Decoded::Complete { value, .. }) = decode_tcp_response(&frame) else {
            panic!("the frame is complete");
        };
        assert!(!value.ok);
        assert_eq!(value.message, "refused");
    }

    /// Lengths are a promise from an untrusted peer, so a server claiming a
    /// message larger than the protocol's ceiling is rejected rather than
    /// allocated for.
    #[test]
    fn a_length_beyond_the_protocol_ceiling_is_refused_not_allocated() {
        let mut frame = vec![0u8];
        varint::put(MAX_MESSAGE_LEN + 1, &mut frame);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));

        let mut frame = vec![0u8];
        varint::put(0, &mut frame);
        varint::put(MAX_PADDING_LEN + 1, &mut frame);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));
    }

    /// Padding must land inside the reference's range and use its alphabet: a
    /// client that pads differently is distinguishable from one that does not
    /// pad, which defeats the point.
    #[test]
    fn padding_stays_inside_the_reference_range_and_alphabet() {
        for _ in 0..64 {
            let bytes = padding(REQUEST_PADDING).unwrap();
            assert!(
                REQUEST_PADDING.contains(&bytes.len()),
                "length {} outside {REQUEST_PADDING:?}",
                bytes.len()
            );
            assert!(bytes.iter().all(|byte| PADDING_ALPHABET.contains(byte)));
        }
    }
}
