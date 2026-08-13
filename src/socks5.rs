//! SOCKS5 (RFC 1928) as a stream egress, with UDP ASSOCIATE.
//!
//! The protocol is small and entirely framed, so it splits cleanly the way the
//! rest of this crate does: a **pure codec** that turns bytes into domain
//! values and back, and a **thin driver** that owns the sockets. Everything
//! interesting — address forms, reply codes, the datagram header — is in the
//! first half and is tested without a socket.
//!
//! **Decoding is total, and "not yet" is not an error.** A reply's length
//! depends on an address type that arrives inside it, so a reader cannot know
//! in advance how many bytes to ask for. Every decoder therefore returns
//! [`Decoded::Incomplete`] rather than guessing or blocking, and the driver
//! reads more and retries. Confusing "truncated" with "malformed" is how a
//! proxy client ends up either hanging on a valid reply or accepting a
//! half-read one.
//!
//! **A name stays a name.** [`Target::Domain`] is encoded as `ATYP=3` rather
//! than resolved locally, so the exit resolves it in its own DNS view; see
//! [`Target`] for why that is a product property and not an optimisation.
//!
//! **UDP ASSOCIATE keeps its control connection.** RFC 1928 §7 ties the
//! association's lifetime to the TCP connection that requested it, so
//! [`Socks5Association`] holds that stream open and drops it with the
//! association. Losing it silently is how a UDP relay stops working minutes
//! after it appeared to start.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    AsyncStream, BoxFuture, DatagramAssociation, DatagramFidelity, DomainName, EgressCapabilities,
    EgressError, NatBehavior, Prefixed, StreamEgress, Target, TunnelBypass,
};

/// The only protocol version this crate speaks, and the only one that exists.
const VERSION: u8 = 5;
/// RFC 1929 username/password sub-negotiation carries its own version.
const AUTH_VERSION: u8 = 1;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;

/// What a SOCKS5 exchange can get wrong. Distinct from a transport failure,
/// which is [`EgressError::Io`]: this names a peer that answered, but not with
/// something this protocol admits.
/// Not `Copy`, because [`Self::Denied`] carries the server's own explanation.
/// That text is the one thing an operator has when a proxy refuses a flow for a
/// reason of its own devising, and dropping it to keep the type a machine word
/// would be trading the diagnostic for nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// A version byte that is not 5 (or not 1 in sub-negotiation). Almost
    /// always something that is not a SOCKS5 proxy at all.
    Version(u8),
    /// The server refused to open a stream and said why, in its own words.
    /// Hysteria2's refusals are free text rather than a code table.
    Denied(String),
    /// The proxy accepted none of the authentication methods offered.
    NoAcceptableMethod,
    /// The proxy selected a method that was never offered.
    UnexpectedMethod(u8),
    /// Username/password authentication was rejected.
    AuthFailed,
    /// The proxy refused the request, with RFC 1928 §6's reply code.
    Refused(Reply),
    /// An address type byte outside {1, 3, 4}, or a domain that is not UTF-8.
    Address,
    /// A datagram this association cannot deliver: RFC 1928 §7 fragmentation,
    /// which no modern proxy emits and which this client does not reassemble.
    Fragmented,
    /// An AEAD operation failed: a bad key length, or a chunk that did not
    /// authenticate. Fatal to a counter-based stream, which cannot resynchronise.
    Crypto,
    /// A Shadowsocks header that is not the shape its type claims.
    Header,
    /// A peer whose clock is too far from ours for the replay window to mean
    /// anything.
    Stale { skew: u64 },
    /// A response echoing a salt that is not the one we sent: another
    /// session's traffic, replayed at us.
    SaltMismatch,
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
        }
    }
}

impl std::error::Error for ProxyError {}

/// RFC 1928 §6 reply codes. Closed, and `Other` carries the byte rather than
/// discarding it, because a proxy may reply with a code this table predates
/// and an operator needs the number to diagnose it.
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

/// The result of decoding from a buffer that may not hold a whole message yet.
///
/// This is the type that makes a streaming parser total: the alternative is a
/// decoder that returns an error for a short read, which a caller cannot
/// distinguish from a real protocol violation and therefore cannot retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded<T> {
    /// More bytes are needed. The caller reads and calls again.
    Incomplete,
    /// A whole message, and how many bytes of the buffer it used.
    Complete { value: T, consumed: usize },
}

/// Writes a target in RFC 1928 address form: `ATYP || ADDR || PORT`.
///
/// O(address length). Appends rather than clearing, so a caller composing a
/// request header keeps what it already wrote.
pub fn encode_address(target: &Target, out: &mut Vec<u8>) {
    match target {
        Target::Ip(SocketAddr::V4(address)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&address.ip().octets());
        }
        Target::Ip(SocketAddr::V6(address)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&address.ip().octets());
        }
        Target::Domain { host, .. } => {
            out.push(ATYP_DOMAIN);
            // The length octet is safe without a check: `DomainName` cannot
            // hold more than 255 bytes, which is the invariant it exists for.
            out.push(host.wire_len());
            out.extend_from_slice(host.as_str().as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
}

/// Reads an address in RFC 1928 form.
///
/// O(address length), and allocates only for the domain form, which owns its
/// name. Total on untrusted input: every short buffer is `Incomplete` and
/// every unknown type byte is [`ProxyError::Address`].
pub fn decode_address(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let Some((&atyp, rest)) = bytes.split_first() else {
        return Ok(Decoded::Incomplete);
    };
    // Address payload length, excluding the two port bytes.
    let payload = match atyp {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => match rest.first() {
            // The length octet is itself part of the payload.
            Some(&length) => 1 + usize::from(length),
            None => return Ok(Decoded::Incomplete),
        },
        _ => return Err(ProxyError::Address),
    };
    let Some(body) = rest.get(..payload) else {
        return Ok(Decoded::Incomplete);
    };
    let Some(port_bytes) = rest.get(payload..payload + 2) else {
        return Ok(Decoded::Incomplete);
    };
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

    let target = match atyp {
        ATYP_IPV4 => {
            let octets: [u8; 4] = body.try_into().map_err(|_| ProxyError::Address)?;
            Target::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = body.try_into().map_err(|_| ProxyError::Address)?;
            Target::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        // The leading length octet is dropped; the rest is the name.
        _ => {
            let name = std::str::from_utf8(&body[1..]).map_err(|_| ProxyError::Address)?;
            let host = DomainName::new(name).map_err(|_| ProxyError::Address)?;
            Target::Domain { host, port }
        }
    };
    Ok(Decoded::Complete {
        value: target,
        // ATYP + payload + port.
        consumed: 1 + payload + 2,
    })
}

/// Credentials for RFC 1929 username/password authentication. Both halves are
/// length-prefixed by one octet on the wire, so both are bounded here.
#[derive(Clone, Debug)]
pub struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    UsernameTooLong(usize),
    PasswordTooLong(usize),
}

impl Credentials {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialsError> {
        let (username, password) = (username.into(), password.into());
        match (username.len(), password.len()) {
            (length, _) if length > 255 => Err(CredentialsError::UsernameTooLong(length)),
            (_, length) if length > 255 => Err(CredentialsError::PasswordTooLong(length)),
            _ => Ok(Self { username, password }),
        }
    }
}

/// The greeting: version, method count, methods. Offering `USERPASS` only when
/// credentials exist keeps a proxy from selecting a method this client would
/// then be unable to complete.
fn encode_greeting(credentials: Option<&Credentials>, out: &mut Vec<u8>) {
    out.push(VERSION);
    match credentials {
        Some(_) => out.extend_from_slice(&[2, METHOD_NONE, METHOD_USERPASS]),
        None => out.extend_from_slice(&[1, METHOD_NONE]),
    }
}

/// The two-byte method selection. `Incomplete` until both bytes are present.
fn decode_method_selection(bytes: &[u8]) -> Result<Decoded<u8>, ProxyError> {
    let Some(&[version, method]) = bytes.get(..2).map(|slice| {
        let pair: &[u8; 2] = slice.try_into().expect("checked length");
        pair
    }) else {
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
    out.push(VERSION);
    out.push(command);
    out.push(0); // RSV
    encode_address(target, out);
}

/// The reply: version, code, reserved, then a bound address whose length is
/// only known from its own type byte — which is exactly why this returns
/// `Incomplete` rather than taking a length.
fn decode_reply(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let Some(header) = bytes.get(..3) else {
        return Ok(Decoded::Incomplete);
    };
    if header[0] != VERSION {
        return Err(ProxyError::Version(header[0]));
    }
    let reply = Reply::from_byte(header[1]);
    if reply != Reply::Succeeded {
        return Err(ProxyError::Refused(reply));
    }
    match decode_address(&bytes[3..])? {
        Decoded::Incomplete => Ok(Decoded::Incomplete),
        Decoded::Complete { value, consumed } => Ok(Decoded::Complete {
            value,
            consumed: 3 + consumed,
        }),
    }
}

/// Writes the RFC 1928 §7 datagram header: two reserved bytes, a fragment
/// number this client never sets, then the target address.
pub fn encode_datagram(target: &Target, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&[0, 0, 0]); // RSV, RSV, FRAG
    encode_address(target, out);
    out.extend_from_slice(payload);
}

/// Reads a relayed datagram, returning where it came from and its payload.
///
/// A fragmented datagram is refused rather than reassembled: RFC 1928 makes
/// fragmentation optional, no deployed proxy emits it, and a reassembly buffer
/// keyed on an attacker-suppliable fragment number is state this crate will not
/// grow for a case that does not occur.
pub fn decode_datagram(bytes: &[u8]) -> Result<(Target, &[u8]), ProxyError> {
    let Some(header) = bytes.get(..3) else {
        return Err(ProxyError::Address);
    };
    if header[2] != 0 {
        return Err(ProxyError::Fragmented);
    }
    match decode_address(&bytes[3..])? {
        Decoded::Incomplete => Err(ProxyError::Address),
        Decoded::Complete { value, consumed } => Ok((value, &bytes[3 + consumed..])),
    }
}

/// Reads until `decode` yields a whole message, growing `buf` as needed.
///
/// The loop is what makes the codec's `Incomplete` useful: it is the one place
/// that turns "not yet" into another read, so no decoder has to know about I/O
/// and no caller has to re-implement framing. A peer that closes mid-message
/// is `UnexpectedEof` rather than a silent partial parse.
/// **`buf` carries the surplus out, and it must not be discarded.** A reply's
/// length lives inside the reply, so this reads *at least* one message and may
/// read past it — TCP does not preserve the sender's boundaries. What follows
/// the message is the connection's first payload bytes: a server-first protocol
/// sends its banner as soon as the proxy connects, and it arrives coalesced
/// into the same segment as the reply. So the message is drained from the front
/// and whatever remains stays in `buf` for the caller to replay through
/// [`Prefixed`], which is also what makes calling this twice on one connection
/// correct.
async fn read_message<S, T>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<Decoded<T>, ProxyError>,
) -> Result<T, EgressError>
where
    S: AsyncStream,
{
    let mut chunk = [0u8; 512];
    loop {
        match decode(buf)? {
            Decoded::Complete { value, consumed } => {
                buf.drain(..consumed);
                return Ok(value);
            }
            Decoded::Incomplete => {}
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(EgressError::Io(std::io::ErrorKind::UnexpectedEof));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Static configuration for one SOCKS5 proxy.
pub struct Socks5Config {
    /// The proxy's TCP endpoint.
    pub proxy: SocketAddr,
    /// Credentials, when the proxy requires RFC 1929 authentication.
    pub credentials: Option<Credentials>,
    /// What RFC 4787 mapping behavior the proxy's UDP relay provides.
    ///
    /// Configuration for the same reason MASQUE's is: the mapping is the
    /// proxy's, unobservable from here, and the planner is entitled to a
    /// measured claim rather than an optimistic constant.
    pub nat_behavior: NatBehavior,
}

/// A SOCKS5 proxy as a stream egress.
///
/// `B` is the tunnel bypass, exactly as the DNS upstreams use: the proxy's
/// socket must not travel through Boreas's own TUN, or the tunnel would carry
/// the connection that carries the tunnel.
pub struct Socks5Egress<B> {
    config: Socks5Config,
    bypass: B,
}

impl<B: TunnelBypass> Socks5Egress<B> {
    pub fn new(config: Socks5Config, bypass: B) -> Self {
        Self { config, bypass }
    }

    /// Opens a connection to the proxy and completes the greeting and, when
    /// required, authentication. Shared by both commands, because RFC 1928
    /// makes them identical up to the request byte.
    ///
    /// The buffer comes back with the negotiation's surplus still in it, so the
    /// caller keeps reading where this stopped rather than from an empty one.
    async fn negotiate(&self) -> Result<(tokio::net::TcpStream, Vec<u8>), EgressError> {
        let mut stream = self.bypass.tcp(self.config.proxy).await?;
        let mut out = Vec::with_capacity(4);
        encode_greeting(self.config.credentials.as_ref(), &mut out);
        stream.write_all(&out).await?;

        let mut buf = Vec::with_capacity(64);
        let method = read_message(&mut stream, &mut buf, decode_method_selection).await?;
        if method == METHOD_USERPASS {
            let credentials = self
                .config
                .credentials
                .as_ref()
                // The greeting offers `USERPASS` only when credentials exist,
                // so a proxy selecting it without them is the proxy choosing
                // an unoffered method.
                .ok_or(ProxyError::UnexpectedMethod(METHOD_USERPASS))?;
            out.clear();
            out.push(AUTH_VERSION);
            out.push(credentials.username.len() as u8);
            out.extend_from_slice(credentials.username.as_bytes());
            out.push(credentials.password.len() as u8);
            out.extend_from_slice(credentials.password.as_bytes());
            stream.write_all(&out).await?;

            let status = read_message(&mut stream, &mut buf, |bytes| {
                let Some(pair) = bytes.get(..2) else {
                    return Ok(Decoded::Incomplete);
                };
                if pair[0] != AUTH_VERSION {
                    return Err(ProxyError::Version(pair[0]));
                }
                Ok(Decoded::Complete {
                    value: pair[1],
                    consumed: 2,
                })
            })
            .await?;
            if status != 0 {
                return Err(ProxyError::AuthFailed.into());
            }
        }
        Ok((stream, buf))
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for Socks5Egress<B> {
    fn capabilities(&self) -> EgressCapabilities {
        EgressCapabilities {
            // The relay re-originates datagrams but preserves their boundaries
            // one for one, so a QUIC datagram crosses as itself.
            datagram_fidelity: DatagramFidelity::Native,
            // A terminated path re-originates the byte stream, so the client's
            // packet size stops existing and there is no per-packet header to
            // charge for.
            overhead_bytes: 0,
            // The relay's own datagram ceiling is not advertised by the
            // protocol, so nothing can be claimed. `plan_flow` reads an absent
            // ceiling as "cannot be shown to clear the QUIC floor" and steers,
            // which is the safe direction.
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
            let (mut stream, mut buf) = self.negotiate().await?;
            let mut out = Vec::with_capacity(32);
            encode_request(CMD_CONNECT, target, &mut out);
            stream.write_all(&out).await?;

            // The bound address the proxy reports is discarded: this client
            // never needs to name its own side of a CONNECT, and keeping it
            // would invite treating it as authoritative for the target.
            let _bound = read_message(&mut stream, &mut buf, decode_reply).await?;
            // Whatever followed the reply is the target's first payload — a
            // server-first banner, most often — so it is replayed rather than
            // dropped.
            Ok(Box::new(Prefixed::new(buf, stream)) as Box<dyn AsyncStream>)
        })
    }

    fn associate(&self) -> BoxFuture<'_, Result<Box<dyn DatagramAssociation>, EgressError>> {
        Box::pin(async move {
            let (mut control, mut buf) = self.negotiate().await?;
            // RFC 1928 §7: the address here is where *this client* will send
            // from. All-zeroes means "not yet known", which is what a client
            // behind an unpredictable source port must say.
            let unspecified = Target::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            let mut out = Vec::with_capacity(32);
            encode_request(CMD_UDP_ASSOCIATE, &unspecified, &mut out);
            control.write_all(&out).await?;

            let relay = read_message(&mut control, &mut buf, decode_reply).await?;
            // The relay must be reachable as an address; a proxy naming its
            // relay by domain would need a resolution this layer will not do.
            let Target::Ip(relay) = relay else {
                return Err(ProxyError::Address.into());
            };
            let socket = self.bypass.udp(relay).await?;
            Ok(Box::new(Socks5Association {
                socket,
                _control: control,
            }) as Box<dyn DatagramAssociation>)
        })
    }
}

/// One UDP ASSOCIATE relay, and the control connection that keeps it alive.
struct Socks5Association {
    socket: tokio::net::UdpSocket,
    /// Held, never read: RFC 1928 §7 ends the association when this closes, so
    /// its lifetime *is* the association's. Named with an underscore because
    /// holding it is the whole contribution.
    _control: tokio::net::TcpStream,
}

impl DatagramAssociation for Socks5Association {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            let mut framed = Vec::with_capacity(payload.len() + 32);
            encode_datagram(target, payload, &mut framed);
            self.socket.send(&framed).await?;
            Ok(())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            // One extra hop through a scratch buffer, because the header is
            // in front of the payload and the caller's buffer is sized for the
            // payload alone.
            let mut framed = vec![0u8; buf.len() + 512];
            let read = self.socket.recv(&mut framed).await?;
            let (from, payload) = decode_datagram(&framed[..read])?;
            let moved = payload.len().min(buf.len());
            buf[..moved].copy_from_slice(&payload[..moved]);
            Ok((moved, from))
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
        // Exactly 255 is the largest a single octet describes, so it is legal.
        assert!(DomainName::new("a".repeat(255)).is_ok());
    }

    #[test]
    fn every_address_form_round_trips() {
        let targets = [
            Target::Ip("192.0.2.1:443".parse().unwrap()),
            Target::Ip("[2001:db8::1]:8443".parse().unwrap()),
            domain("example.com", 80),
            // The longest name the wire admits, to exercise the length octet's
            // boundary rather than only its middle.
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

            // Every proper prefix is `Incomplete`, never a spurious parse:
            // this is the law that makes the streaming reader terminate on
            // exactly the right byte.
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
        // A domain that is not UTF-8 is an address error, not a panic.
        assert_eq!(
            decode_address(&[ATYP_DOMAIN, 2, 0xff, 0xfe, 0, 80]),
            Err(ProxyError::Address)
        );
    }

    #[test]
    fn a_refusal_carries_its_reply_code_and_a_short_reply_waits() {
        // Every code RFC 1928 names, plus one it does not, survives the trip
        // to the caller as a distinguishable value.
        for (byte, expected) in [
            (1u8, Reply::GeneralFailure),
            (2, Reply::NotAllowed),
            (5, Reply::ConnectionRefused),
            (9, Reply::Other(9)),
        ] {
            let reply = [VERSION, byte, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
            assert_eq!(decode_reply(&reply), Err(ProxyError::Refused(expected)));
        }

        // A success whose address has not fully arrived is incomplete, and the
        // same bytes plus the rest decode. "Not yet" and "no" are different
        // answers and the reader depends on it.
        let full = [VERSION, 0, 0, ATYP_IPV4, 192, 0, 2, 1, 0x01, 0xbb];
        assert_eq!(decode_reply(&full[..6]), Ok(Decoded::Incomplete));
        assert_eq!(
            decode_reply(&full),
            Ok(Decoded::Complete {
                value: Target::Ip("192.0.2.1:443".parse().unwrap()),
                consumed: 10,
            })
        );

        // Something that is not SOCKS5 at all is named as such.
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
        // GSSAPI is legal SOCKS5 and is never offered by this client, so a
        // proxy selecting it is choosing something it was not given.
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

        // FRAG != 0 is refused rather than reassembled.
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

        // Both halves are length-prefixed by one octet, so both are bounded.
        assert_eq!(
            Credentials::new("u".repeat(256), "p").map(|_| ()),
            Err(CredentialsError::UsernameTooLong(256))
        );
        assert_eq!(
            Credentials::new("u", "p".repeat(256)).map(|_| ()),
            Err(CredentialsError::PasswordTooLong(256))
        );
    }
}
