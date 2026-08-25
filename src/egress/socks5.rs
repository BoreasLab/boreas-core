//! SOCKS5 (RFC 1928) stream egress with UDP ASSOCIATE.
//!
//! Codecs decode complete values or report [`Decoded::Incomplete`]; the driver
//! owns sockets and supplies more bytes. Domain targets remain unresolved so
//! the proxy performs resolution in its own network. UDP associations retain
//! their TCP control connection for the association's lifetime.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use crate::{
    Association, AsyncStream, BoxFuture, DatagramFidelity, DatagramSink, DatagramSource, Decoded,
    DomainName, EgressError, NatBehavior, PathProperties, Prefixed, StreamEgress, Target,
    TunnelBypass,
    wire::{Reader, Writer},
};

/// SOCKS5 protocol version.
const VERSION: u8 = 5;
/// RFC 1929 sub-negotiation version.
const AUTH_VERSION: u8 = 1;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;

/// Errors reported by a responding SOCKS5 peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// Unexpected protocol version.
    Version(u8),
    /// Server-supplied refusal reason.
    Denied(String),
    /// The proxy accepted none of the authentication methods offered.
    NoAcceptableMethod,
    /// The proxy selected a method that was never offered.
    UnexpectedMethod(u8),
    /// Username/password authentication was rejected.
    AuthFailed,
    /// RFC 1928 request refusal.
    Refused(Reply),
    /// Invalid address representation.
    Address,
    /// Fragmented UDP datagram, which this client does not reassemble.
    Fragmented,
    /// Authenticated-encryption failure.
    Crypto,
    /// Invalid proxy header.
    Header,
    /// Peer clock outside the accepted window.
    Stale { skew: u64 },
    /// Response salt did not match the request.
    SaltMismatch,
    /// Payload was passed to a codec without a write frame.
    Unframed,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(version) => write!(f, "peer is not SOCKS5 (version {version})"),
            Self::Denied(reason) => write!(f, "server refused the stream: {reason}"),
            Self::NoAcceptableMethod => f.write_str("no acceptable authentication method"),
            Self::UnexpectedMethod(method) => write!(f, "proxy chose unoffered method {method}"),
            Self::AuthFailed => f.write_str("authentication rejected"),
            Self::Refused(reply) => write!(f, "request refused: {reply:?}"),
            Self::Address => f.write_str("malformed address"),
            Self::Fragmented => f.write_str("fragmented datagram"),
            Self::Crypto => f.write_str("AEAD failure"),
            Self::Header => f.write_str("malformed header"),
            Self::Stale { skew } => write!(f, "peer clock differs by {skew}s"),
            Self::SaltMismatch => f.write_str("response echoed another session's salt"),
            Self::Unframed => f.write_str("codec frames nothing it writes"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// RFC 1928 section 6 reply codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Other(u8),
}

impl Reply {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Succeeded,
            1 => Self::GeneralFailure,
            2 => Self::NotAllowed,
            3 => Self::NetworkUnreachable,
            4 => Self::HostUnreachable,
            5 => Self::ConnectionRefused,
            6 => Self::TtlExpired,
            7 => Self::CommandNotSupported,
            8 => Self::AddressTypeNotSupported,
            other => Self::Other(other),
        }
    }
}

/// Appends a target in RFC 1928 address form: `ATYP || ADDR || PORT`.
pub fn encode_address(target: &Target, out: &mut Vec<u8>) {
    let mut writer = Writer::new(out);
    match target {
        Target::Ip(SocketAddr::V4(address)) => writer.u8(ATYP_IPV4).bytes(&address.ip().octets()),
        Target::Ip(SocketAddr::V6(address)) => writer.u8(ATYP_IPV6).bytes(&address.ip().octets()),
        // DomainName guarantees that the length fits one octet.
        Target::Domain { host, .. } => writer.u8(ATYP_DOMAIN).vector_u8(host.as_str().as_bytes()),
    };
    writer.u16(target.port());
}

/// Reads an address in RFC 1928 form.
///
/// Short input is incomplete; unknown types and invalid names are errors.
pub fn decode_address(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(atyp) = reader.u8() else {
        return Ok(Decoded::Incomplete);
    };
    // The address type determines the body width; the port follows every form.
    let body = match atyp {
        ATYP_IPV4 => reader.take(4),
        ATYP_IPV6 => reader.take(16),
        ATYP_DOMAIN => reader.vector_u8(),
        _ => return Err(ProxyError::Address),
    };
    let (Some(body), Some(port)) = (body, reader.u16()) else {
        return Ok(Decoded::Incomplete);
    };

    let mut body = Reader::new(body);
    let target = match atyp {
        ATYP_IPV4 => Target::Ip(SocketAddr::new(
            IpAddr::V4(body.ipv4().ok_or(ProxyError::Address)?),
            port,
        )),
        ATYP_IPV6 => Target::Ip(SocketAddr::new(
            IpAddr::V6(body.ipv6().ok_or(ProxyError::Address)?),
            port,
        )),
        _ => Target::Domain {
            host: std::str::from_utf8(body.rest())
                .ok()
                .and_then(|name| DomainName::new(name).ok())
                .ok_or(ProxyError::Address)?,
            port,
        },
    };
    Ok(Decoded::Complete {
        value: target,
        consumed: reader.position(),
    })
}

/// RFC 1929 username/password credentials.
///
/// Both fields must contain 1 to 255 bytes.
#[derive(Clone, Debug)]
pub struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// Username length is outside RFC 1929's `1..=255` range.
    Username(usize),
    Password(usize),
}

impl Credentials {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialsError> {
        let (username, password) = (username.into(), password.into());
        match (username.len(), password.len()) {
            (length, _) if !(1..=255).contains(&length) => Err(CredentialsError::Username(length)),
            (_, length) if !(1..=255).contains(&length) => Err(CredentialsError::Password(length)),
            _ => Ok(Self { username, password }),
        }
    }
}

/// Writes the greeting, offering username/password only when configured.
fn encode_greeting(credentials: Option<&Credentials>, out: &mut Vec<u8>) {
    let mut writer = Writer::new(out);
    writer.u8(VERSION);
    match credentials {
        Some(_) => writer.bytes(&[2, METHOD_NONE, METHOD_USERPASS]),
        None => writer.bytes(&[1, METHOD_NONE]),
    };
}

/// Reads the two-byte method selection.
fn decode_method_selection(bytes: &[u8]) -> Result<Decoded<u8>, ProxyError> {
    let Some(&[version, method]) = Reader::new(bytes).array::<2>() else {
        return Ok(Decoded::Incomplete);
    };
    if version != VERSION {
        return Err(ProxyError::Version(version));
    }
    match method {
        METHOD_UNACCEPTABLE => Err(ProxyError::NoAcceptableMethod),
        METHOD_NONE | METHOD_USERPASS => Ok(Decoded::Complete {
            value: method,
            consumed: 2,
        }),
        other => Err(ProxyError::UnexpectedMethod(other)),
    }
}

fn encode_request(command: u8, target: &Target, out: &mut Vec<u8>) {
    Writer::new(out).u8(VERSION).u8(command).u8(0); // RSV
    encode_address(target, out);
}

/// Reads a reply whose bound address supplies its own length.
fn decode_reply(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(&[version, code, _reserved]) = reader.array::<3>() else {
        return Ok(Decoded::Incomplete);
    };
    if version != VERSION {
        return Err(ProxyError::Version(version));
    }
    let reply = Reply::from_byte(code);
    if reply != Reply::Succeeded {
        return Err(ProxyError::Refused(reply));
    }
    match decode_address(reader.rest())? {
        Decoded::Incomplete => Ok(Decoded::Incomplete),
        Decoded::Complete { value, consumed } => Ok(Decoded::Complete {
            value,
            consumed: 3 + consumed,
        }),
    }
}

/// Writes the RFC 1928 section 7 datagram header and payload.
pub fn encode_datagram(target: &Target, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    Writer::new(out).bytes(&[0, 0, 0]); // RSV, RSV, FRAG
    encode_address(target, out);
    Writer::new(out).bytes(payload);
}

/// Reads a relayed datagram and rejects fragmentation.
pub fn decode_datagram(bytes: &[u8]) -> Result<(Target, &[u8]), ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(&[_, _, fragment]) = reader.array::<3>() else {
        return Err(ProxyError::Address);
    };
    if fragment != 0 {
        return Err(ProxyError::Fragmented);
    }
    let rest = reader.rest();
    match decode_address(rest)? {
        Decoded::Incomplete => Err(ProxyError::Address),
        Decoded::Complete { value, consumed } => Ok((value, &rest[consumed..])),
    }
}

/// Configuration for one SOCKS5 proxy.
pub struct Socks5Config {
    /// Proxy TCP endpoint.
    pub proxy: SocketAddr,
    /// Optional RFC 1929 credentials.
    pub credentials: Option<Credentials>,
    /// RFC 4787 mapping behavior provided by the UDP relay.
    pub nat_behavior: NatBehavior,
}

/// Pure RFC 1928 negotiation state machine.
///
/// The machine tracks its input offset because the driver may supply several
/// protocol messages in one buffer.
struct Negotiate<'a> {
    credentials: Option<&'a Credentials>,
    command: u8,
    target: &'a Target,
    phase: Phase,
    /// How much of the offered input earlier phases have consumed.
    at: usize,
}

/// Current negotiation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Greeting written; waiting for method selection.
    Selecting,
    /// Credentials written; waiting for authentication status.
    Authenticating,
    /// Command written; waiting for the reply.
    Requesting,
}

impl<'a> Negotiate<'a> {
    fn new(credentials: Option<&'a Credentials>, command: u8, target: &'a Target) -> Self {
        Self {
            credentials,
            command,
            target,
            phase: Phase::Selecting,
            at: 0,
        }
    }
}

impl crate::Negotiation for Negotiate<'_> {
    /// Address reported by the proxy after the request.
    type Output = Target;

    /// Advances negotiation using the bytes currently available.
    fn advance(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Decoded<Target>, ProxyError> {
        loop {
            // Continue from the first byte not consumed by an earlier phase.
            let rest = input.get(self.at..).unwrap_or_default();
            match self.phase {
                Phase::Selecting if self.at == 0 && input.is_empty() && out.is_empty() => {
                    encode_greeting(self.credentials, out);
                    return Ok(Decoded::Incomplete);
                }
                Phase::Selecting => {
                    let Decoded::Complete { value, consumed } = decode_method_selection(rest)?
                    else {
                        return Ok(Decoded::Incomplete);
                    };
                    self.at += consumed;
                    match value {
                        METHOD_USERPASS => {
                            // USERPASS is valid only when credentials were offered.
                            let credentials = self
                                .credentials
                                .ok_or(ProxyError::UnexpectedMethod(METHOD_USERPASS))?;
                            encode_credentials(credentials, out);
                            self.phase = Phase::Authenticating;
                        }
                        _ => {
                            encode_request(self.command, self.target, out);
                            self.phase = Phase::Requesting;
                        }
                    }
                }
                Phase::Authenticating => {
                    let Some(&[version, status]) = Reader::new(rest).array::<2>() else {
                        return Ok(Decoded::Incomplete);
                    };
                    if version != AUTH_VERSION {
                        return Err(ProxyError::Version(version));
                    }
                    if status != 0 {
                        return Err(ProxyError::AuthFailed);
                    }
                    self.at += 2;
                    encode_request(self.command, self.target, out);
                    self.phase = Phase::Requesting;
                }
                Phase::Requesting => {
                    let Decoded::Complete { value, consumed } = decode_reply(rest)? else {
                        return Ok(Decoded::Incomplete);
                    };
                    return Ok(Decoded::Complete {
                        value,
                        consumed: self.at + consumed,
                    });
                }
            }
        }
    }
}

/// Writes the RFC 1929 username/password sub-negotiation.
fn encode_credentials(credentials: &Credentials, out: &mut Vec<u8>) {
    // Credentials validates both lengths before they reach the wire.
    Writer::new(out)
        .u8(AUTH_VERSION)
        .vector_u8(credentials.username.as_bytes())
        .vector_u8(credentials.password.as_bytes());
}

/// SOCKS5 stream and UDP egress.
///
/// The bypass keeps the proxy connection outside Boreas's own tunnel.
pub struct Socks5Egress<B> {
    config: Socks5Config,
    bypass: B,
}

impl<B: TunnelBypass> Socks5Egress<B> {
    pub fn new(config: Socks5Config, bypass: B) -> Self {
        Self { config, bypass }
    }

    /// Connects to the proxy and completes RFC 1928 negotiation.
    async fn exchange(
        &self,
        command: u8,
        target: &Target,
    ) -> Result<(tokio::net::TcpStream, Target, Vec<u8>), EgressError> {
        let mut stream =
            crate::within(crate::Wait::TcpConnect, self.bypass.tcp(self.config.proxy)).await?;
        let mut machine = Negotiate::new(self.config.credentials.as_ref(), command, target);
        let (bound, surplus) = crate::negotiate(&mut stream, &mut machine).await?;
        Ok((stream, bound, surplus))
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for Socks5Egress<B> {
    fn properties(&self) -> PathProperties {
        PathProperties {
            // UDP relay preserves datagram boundaries.
            datagram_fidelity: DatagramFidelity::Native,
            // Stream egress has no packet encapsulation overhead.
            overhead_bytes: 0,
            // SOCKS5 does not advertise the relay's datagram ceiling.
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
            // CONNECT does not use the proxy's bound address.
            let (stream, _bound, surplus) = self.exchange(CMD_CONNECT, target).await?;
            // Preserve bytes read beyond the negotiation reply.
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }

    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            // RFC 1928 section 7 permits an unspecified client address.
            let unspecified = Target::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            let (control, relay, _surplus) = self.exchange(CMD_UDP_ASSOCIATE, &unspecified).await?;
            // The relay address must already be an IP address.
            let Target::Ip(relay) = relay else {
                return Err(ProxyError::Address.into());
            };
            let socket = self.bypass.udp(relay).await?;
            // RFC 1928 section 7 ties association lifetime to the control stream.
            let shared = Arc::new(Relay {
                socket,
                _control: control,
            });
            Ok(Association {
                source: Box::new(Socks5Source {
                    relay: Arc::clone(&shared),
                    // One association-owned buffer handles the largest UDP payload.
                    framed: vec![0u8; MAX_UDP_PAYLOAD],
                }),
                sink: shared,
            })
        })
    }
}

/// Largest payload representable by a UDP length field.
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;

/// UDP relay and its lifetime-bound control connection.
struct Relay {
    socket: tokio::net::UdpSocket,
    /// Held open for the association lifetime.
    _control: tokio::net::TcpStream,
}

impl DatagramSink for Relay {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            // Sized once for the worst case this call can produce — the header
            // is at most `4 + 256 + 2` bytes — so the encode never reallocates.
            let mut framed = Vec::with_capacity(payload.len() + MAX_DATAGRAM_HEADER);
            encode_datagram(target, payload, &mut framed);
            whole_datagram(self.socket.send(&framed).await?, framed.len())
        })
    }
}

/// Receiving half of a SOCKS5 association.
struct Socks5Source {
    relay: Arc<Relay>,
    framed: Vec<u8>,
}

/// Maximum SOCKS5 UDP header size.
const MAX_DATAGRAM_HEADER: usize = 4 + 1 + 255 + 2;

/// Requires a datagram send to write the complete message.
fn whole_datagram(written: usize, expected: usize) -> Result<(), EgressError> {
    if written == expected {
        return Ok(());
    }
    Err(EgressError::Io(std::io::ErrorKind::WriteZero))
}

impl DatagramSource for Socks5Source {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            let read = self.relay.socket.recv(&mut self.framed).await?;
            let (from, payload) = decode_datagram(&self.framed[..read])?;
            if payload.len() > buf.len() {
                return Err(EgressError::DatagramTooLarge {
                    required: payload.len(),
                });
            }
            buf[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), from))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str, port: u16) -> Target {
        Target::Domain {
            host: DomainName::new(name).unwrap(),
            port,
        }
    }

    #[test]
    fn the_name_refinement_rejects_what_no_length_octet_can_describe() {
        assert_eq!(DomainName::new(""), Err(crate::DomainNameError::Empty));
        assert_eq!(
            DomainName::new("a".repeat(256)),
            Err(crate::DomainNameError::TooLong(256))
        );
        assert_eq!(
            DomainName::new("bad\0name"),
            Err(crate::DomainNameError::Interior)
        );
        // 255 bytes is the maximum encodable length.
        assert!(DomainName::new("a".repeat(255)).is_ok());
    }

    #[test]
    fn every_address_form_round_trips() {
        let targets = [
            Target::Ip("192.0.2.1:443".parse().unwrap()),
            Target::Ip("[2001:db8::1]:8443".parse().unwrap()),
            domain("example.com", 80),
            // Exercise the maximum domain length.
            domain(&"a".repeat(255), 65535),
        ];
        for target in targets {
            let mut encoded = Vec::new();
            encode_address(&target, &mut encoded);
            assert_eq!(
                decode_address(&encoded),
                Ok(Decoded::Complete {
                    value: target.clone(),
                    consumed: encoded.len(),
                }),
                "{target} must round-trip"
            );

            // Every proper prefix is incomplete.
            for split in 0..encoded.len() {
                assert_eq!(
                    decode_address(&encoded[..split]),
                    Ok(Decoded::Incomplete),
                    "{target} truncated to {split} bytes is incomplete"
                );
            }
        }
    }

    #[test]
    fn an_unknown_address_type_is_refused_rather_than_guessed() {
        assert_eq!(
            decode_address(&[0x02, 1, 2, 3, 4]),
            Err(ProxyError::Address)
        );
        // Invalid UTF-8 is an address error.
        assert_eq!(
            decode_address(&[ATYP_DOMAIN, 2, 0xff, 0xfe, 0, 80]),
            Err(ProxyError::Address)
        );
    }

    #[test]
    fn a_refusal_carries_its_reply_code_and_a_short_reply_waits() {
        // Known and unknown reply codes remain distinguishable.
        for (byte, expected) in [
            (1u8, Reply::GeneralFailure),
            (2, Reply::NotAllowed),
            (5, Reply::ConnectionRefused),
            (9, Reply::Other(9)),
        ] {
            let reply = [VERSION, byte, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
            assert_eq!(decode_reply(&reply), Err(ProxyError::Refused(expected)));
        }

        // A truncated success is incomplete rather than refused.
        let full = [VERSION, 0, 0, ATYP_IPV4, 192, 0, 2, 1, 0x01, 0xbb];
        assert_eq!(decode_reply(&full[..6]), Ok(Decoded::Incomplete));
        assert_eq!(
            decode_reply(&full),
            Ok(Decoded::Complete {
                value: Target::Ip("192.0.2.1:443".parse().unwrap()),
                consumed: 10,
            })
        );

        // A different protocol version is reported explicitly.
        assert_eq!(decode_reply(&[4, 0, 0]), Err(ProxyError::Version(4)));
    }

    #[test]
    fn method_selection_distinguishes_refusal_from_an_unoffered_choice() {
        assert_eq!(decode_method_selection(&[VERSION]), Ok(Decoded::Incomplete));
        assert_eq!(
            decode_method_selection(&[VERSION, METHOD_NONE]),
            Ok(Decoded::Complete {
                value: METHOD_NONE,
                consumed: 2
            })
        );
        assert_eq!(
            decode_method_selection(&[VERSION, METHOD_UNACCEPTABLE]),
            Err(ProxyError::NoAcceptableMethod)
        );
        // An unoffered method is rejected.
        assert_eq!(
            decode_method_selection(&[VERSION, 0x01]),
            Err(ProxyError::UnexpectedMethod(0x01))
        );
    }

    #[test]
    fn a_relayed_datagram_round_trips_and_a_fragment_is_refused() {
        let target = domain("example.com", 53);
        let payload = b"\x12\x34\x01\x00";
        let mut framed = Vec::new();
        encode_datagram(&target, payload, &mut framed);
        assert_eq!(decode_datagram(&framed), Ok((target, &payload[..])));

        // Fragmented datagrams are refused.
        framed[2] = 1;
        assert_eq!(decode_datagram(&framed), Err(ProxyError::Fragmented));
    }

    #[test]
    fn the_greeting_offers_authentication_only_when_it_can_perform_it() {
        let mut anonymous = Vec::new();
        encode_greeting(None, &mut anonymous);
        assert_eq!(anonymous, vec![VERSION, 1, METHOD_NONE]);

        let credentials = Credentials::new("user", "secret").unwrap();
        let mut authenticated = Vec::new();
        encode_greeting(Some(&credentials), &mut authenticated);
        assert_eq!(
            authenticated,
            vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS]
        );

        // Both credential lengths must fit RFC 1929's `1..=255` range.
        for (username, password, expected) in [
            (
                "u".repeat(256),
                "p".to_owned(),
                CredentialsError::Username(256),
            ),
            (String::new(), "p".to_owned(), CredentialsError::Username(0)),
            (
                "u".to_owned(),
                "p".repeat(256),
                CredentialsError::Password(256),
            ),
            ("u".to_owned(), String::new(), CredentialsError::Password(0)),
        ] {
            assert_eq!(
                Credentials::new(username.clone(), password.clone()).map(|_| ()),
                Err(expected),
                "{}/{}",
                username.len(),
                password.len()
            );
        }
    }

    /// Exercises negotiation without a socket.
    #[test]
    fn the_unauthenticated_exchange_greets_requests_and_reads_its_reply() {
        use crate::Negotiation;
        let target = Target::Domain {
            host: crate::DomainName::new("example.com").unwrap(),
            port: 443,
        };
        let mut machine = Negotiate::new(None, CMD_CONNECT, &target);

        // No input starts the greeting.
        let mut greeting = Vec::new();
        assert!(matches!(
            machine.advance(&[], &mut greeting).unwrap(),
            Decoded::Incomplete
        ));
        assert_eq!(greeting, [VERSION, 1, METHOD_NONE]);

        // No authentication causes the request to follow.
        let mut request = Vec::new();
        assert!(matches!(
            machine
                .advance(&[VERSION, METHOD_NONE], &mut request)
                .unwrap(),
            Decoded::Incomplete
        ));
        let mut expected = Vec::new();
        encode_request(CMD_CONNECT, &target, &mut expected);
        assert_eq!(request, expected);

        // The reply completes negotiation and reports consumed input.
        let mut wire = vec![VERSION, METHOD_NONE];
        let reply_at = wire.len();
        wire.extend_from_slice(&[VERSION, 0, 0]);
        encode_address(&Target::Ip("198.51.100.7:1080".parse().unwrap()), &mut wire);
        let consumed_total = wire.len();
        wire.extend_from_slice(b"220 banner\r\n");

        let mut nothing = Vec::new();
        let Decoded::Complete { value, consumed } = machine.advance(&wire, &mut nothing).unwrap()
        else {
            panic!("the reply completes the exchange");
        };
        assert!(nothing.is_empty(), "nothing is written after the request");
        assert_eq!(value, Target::Ip("198.51.100.7:1080".parse().unwrap()));
        assert_eq!(
            consumed, consumed_total,
            "both messages, and not one byte of the banner behind them"
        );
        assert!(reply_at < consumed, "the offset spans more than one phase");
    }

    /// Authentication adds one round trip without repeating the greeting.
    #[test]
    fn the_authenticated_exchange_adds_one_round_trip_and_repeats_nothing() {
        use crate::Negotiation;
        let credentials = Credentials::new("user", "pass").unwrap();
        let target = Target::Ip("198.51.100.9:443".parse().unwrap());
        let mut machine = Negotiate::new(Some(&credentials), CMD_CONNECT, &target);

        let mut greeting = Vec::new();
        machine.advance(&[], &mut greeting).unwrap();
        assert_eq!(
            greeting,
            [VERSION, 2, METHOD_NONE, METHOD_USERPASS],
            "both methods are offered when credentials exist"
        );

        let mut auth = Vec::new();
        machine
            .advance(&[VERSION, METHOD_USERPASS], &mut auth)
            .unwrap();
        assert_eq!(auth, b"\x01\x04user\x04pass");

        let mut request = Vec::new();
        machine
            .advance(&[VERSION, METHOD_USERPASS, AUTH_VERSION, 0], &mut request)
            .unwrap();
        let mut expected = Vec::new();
        encode_request(CMD_CONNECT, &target, &mut expected);
        assert_eq!(request, expected, "the request follows the status byte");
    }

    /// Negotiation reaches the same result for every input split.
    #[test]
    fn the_exchange_reaches_the_same_verdict_however_the_bytes_are_split() {
        use crate::Negotiation;
        let target = Target::Ip("198.51.100.9:443".parse().unwrap());
        let mut wire = vec![VERSION, METHOD_NONE, VERSION, 0, 0];
        encode_address(&Target::Ip("0.0.0.0:0".parse().unwrap()), &mut wire);

        let mut machine = Negotiate::new(None, CMD_CONNECT, &target);
        let mut verdict = None;
        for taken in 0..=wire.len() {
            let mut out = Vec::new();
            verdict = Some(machine.advance(&wire[..taken], &mut out).unwrap());
        }
        assert!(
            matches!(verdict, Some(Decoded::Complete { consumed, .. }) if consumed == wire.len()),
            "one byte at a time reaches the same place as one read"
        );
    }

    /// A proxy cannot select a method the client did not offer.
    #[test]
    fn a_method_that_was_never_offered_is_refused() {
        use crate::Negotiation;
        let target = Target::Ip("198.51.100.9:443".parse().unwrap());
        let mut machine = Negotiate::new(None, CMD_CONNECT, &target);
        machine.advance(&[], &mut Vec::new()).unwrap();
        assert!(matches!(
            machine.advance(&[VERSION, METHOD_USERPASS], &mut Vec::new()),
            Err(ProxyError::UnexpectedMethod(METHOD_USERPASS))
        ));
    }

    /// Rejected credentials end negotiation before the request.
    #[test]
    fn a_rejected_credential_ends_the_exchange() {
        use crate::Negotiation;
        let credentials = Credentials::new("user", "wrong").unwrap();
        let target = Target::Ip("198.51.100.9:443".parse().unwrap());
        let mut machine = Negotiate::new(Some(&credentials), CMD_CONNECT, &target);
        machine.advance(&[], &mut Vec::new()).unwrap();
        machine
            .advance(&[VERSION, METHOD_USERPASS], &mut Vec::new())
            .unwrap();
        assert!(matches!(
            machine.advance(
                &[VERSION, METHOD_USERPASS, AUTH_VERSION, 1],
                &mut Vec::new()
            ),
            Err(ProxyError::AuthFailed)
        ));
    }
}
