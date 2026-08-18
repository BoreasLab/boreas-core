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
//! association's lifetime to the TCP connection that requested it, so the
//! shared [`Relay`] holds that stream open and drops it with the last half of
//! the association. Losing it silently is how a UDP relay stops working minutes
//! after it appeared to start.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use crate::{
    Association, AsyncStream, BoxFuture, DatagramFidelity, DatagramSink, DatagramSource, Decoded,
    DomainName, EgressError, NatBehavior, PathProperties, Prefixed, StreamEgress, Target,
    TunnelBypass,
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

/// Credentials for RFC 1929 username/password authentication.
///
/// Both halves are length-prefixed by one octet on the wire, and RFC 1929's own
/// request diagram gives their widths as `1 to 255` — not `0 to 255`. An empty
/// half is therefore not a short credential but an unencodable one, and the
/// only place to find that out is a proxy that refuses the authentication with
/// no explanation of which field it disliked. The range is the type's, so a
/// configuration that cannot be put on the wire fails where it is written.
#[derive(Clone, Debug)]
pub struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// Outside RFC 1929's `1 to 255`, in either direction. The length is
    /// carried so a host can say which end of the range it missed.
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

/// RFC 1928's exchange, as a pure state machine.
///
/// Three phases, one of them conditional: greet and learn the selected method;
/// if it is username/password, authenticate; then send the command and read the
/// reply. Both commands share every step up to the request byte, which is why
/// this is one machine parameterised by the command rather than two that drift.
///
/// **The offset is the machine's own, not the driver's.** [`crate::negotiate`]
/// hands over everything received so far and drains only when the whole
/// exchange completes, so a machine spanning several messages has to remember
/// how far into that buffer its earlier phases reached. Keeping it here rather
/// than widening [`Decoded`] to carry partial progress leaves the sum the same
/// one sixty other decoders return.
struct Negotiate<'a> {
    credentials: Option<&'a Credentials>,
    command: u8,
    target: &'a Target,
    phase: Phase,
    /// How much of the offered input earlier phases have consumed.
    at: usize,
}

/// Where the exchange has reached. A closed sum, so a phase that forgot to
/// advance is a match arm that does not compile rather than a flag that
/// silently re-sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Greeting written; awaiting the method the proxy selected.
    Selecting,
    /// Credentials written; awaiting the status byte.
    Authenticating,
    /// Command written; awaiting the reply.
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
    /// The address the proxy reports it bound. A `CONNECT` caller discards it;
    /// a `UDP ASSOCIATE` caller sends its datagrams there, which is the only
    /// reason it is carried at all.
    type Output = Target;

    /// O(bytes offered) per call, over an exchange bounded to a few tens of
    /// bytes plus one address.
    fn advance(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Decoded<Target>, ProxyError> {
        loop {
            // Everything earlier phases have not already taken.
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
                            // The greeting offers `USERPASS` only when
                            // credentials exist, so a proxy selecting it
                            // without them is choosing an unoffered method.
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
                    let Some(pair) = rest.get(..2) else {
                        return Ok(Decoded::Incomplete);
                    };
                    if pair[0] != AUTH_VERSION {
                        return Err(ProxyError::Version(pair[0]));
                    }
                    if pair[1] != 0 {
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

/// RFC 1929's username/password sub-negotiation. Both lengths fit an octet
/// because [`Credentials`] refused anything longer at construction.
fn encode_credentials(credentials: &Credentials, out: &mut Vec<u8>) {
    out.push(AUTH_VERSION);
    out.push(credentials.username.len() as u8);
    out.extend_from_slice(credentials.username.as_bytes());
    out.push(credentials.password.len() as u8);
    out.extend_from_slice(credentials.password.as_bytes());
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

    /// Opens a connection to the proxy and runs RFC 1928's exchange to
    /// completion.
    ///
    /// **The sequencing is not here.** It is in [`Negotiate`], which is a pure
    /// state machine a test drives byte at a time; this opens a socket, calls
    /// [`crate::negotiate`], and hands back what the exchange established
    /// together with whatever was read past it — the target's first payload,
    /// which for a server-first protocol is its whole banner.
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
            // The bound address the proxy reports is discarded: this client
            // never needs to name its own side of a CONNECT, and keeping it
            // would invite treating it as authoritative for the target.
            let (stream, _bound, surplus) = self.exchange(CMD_CONNECT, target).await?;
            // Whatever followed the reply is the target's first payload — a
            // server-first banner, most often — so it is replayed rather than
            // dropped.
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }

    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            // RFC 1928 §7: the address here is where *this client* will send
            // from. All-zeroes means "not yet known", which is what a client
            // behind an unpredictable source port must say.
            let unspecified = Target::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            let (control, relay, _surplus) = self.exchange(CMD_UDP_ASSOCIATE, &unspecified).await?;
            // The relay must be reachable as an address; a proxy naming its
            // relay by domain would need a resolution this layer will not do.
            let Target::Ip(relay) = relay else {
                return Err(ProxyError::Address.into());
            };
            let socket = self.bypass.udp(relay).await?;
            // Both halves keep the relay and the control connection alive:
            // RFC 1928 §7 ends the association when the control connection
            // closes, so its lifetime *is* the association's and neither half
            // may outlive it.
            let shared = Arc::new(Relay {
                socket,
                _control: control,
            });
            Ok(Association {
                source: Box::new(Socks5Source {
                    relay: Arc::clone(&shared),
                    // One framing buffer for the association, sized to the
                    // largest datagram a UDP payload length can describe. Per
                    // association rather than per datagram, and exact rather
                    // than generous: nothing larger can arrive, so a payload
                    // this cannot hold does not exist.
                    framed: vec![0u8; MAX_UDP_PAYLOAD],
                }),
                sink: shared,
            })
        })
    }
}

/// The largest payload a UDP datagram can carry. The receive buffer is sized
/// to it exactly, which is what makes a short read provably the sender's
/// message rather than a truncation this client caused.
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;

/// One UDP ASSOCIATE relay, and the control connection that keeps it alive.
struct Relay {
    socket: tokio::net::UdpSocket,
    /// Held, never read: its lifetime is the association's. Named with an
    /// underscore because holding it is the whole contribution.
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

/// The receiving half: the relay plus the one framing buffer it decodes into.
struct Socks5Source {
    relay: Arc<Relay>,
    framed: Vec<u8>,
}

/// RSV(2) + FRAG(1) + ATYP(1) + the longest address (a 255-byte name behind its
/// length octet) + port(2).
const MAX_DATAGRAM_HEADER: usize = 4 + 1 + 255 + 2;

/// A datagram socket delivers a message or nothing; a partial send is a failure
/// of the send, not a smaller message.
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

        // RFC 1929's request diagram gives both halves as `1 to 255`, so both
        // ends of the range are refused. Empty is the one that mattered: it
        // encodes a zero length byte, which no conforming server reads back as
        // a credential, and the only report is an authentication that failed.
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

    /// **The exchange, with no socket anywhere.** Before the port this needed a
    /// live proxy or a mock stream; the sequencing was inside an `async fn` and
    /// the only way to reach it was to run it. Now it is a value, and a test
    /// offers it bytes.
    #[test]
    fn the_unauthenticated_exchange_greets_requests_and_reads_its_reply() {
        use crate::Negotiation;
        let target = Target::Domain {
            host: crate::DomainName::new("example.com").unwrap(),
            port: 443,
        };
        let mut machine = Negotiate::new(None, CMD_CONNECT, &target);

        // Nothing received yet: the greeting goes out.
        let mut greeting = Vec::new();
        assert!(matches!(
            machine.advance(&[], &mut greeting).unwrap(),
            Decoded::Incomplete
        ));
        assert_eq!(greeting, [VERSION, 1, METHOD_NONE]);

        // The proxy selects "no authentication", so the request follows.
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

        // The reply completes it, and the consumed count covers both messages.
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

    /// The authenticated path adds a round trip in the middle, and the machine
    /// must not re-send the greeting to reach it.
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

    /// **The property a socket-bound test cannot check cheaply.** A machine
    /// that only advances when a whole message lands in one read works against
    /// a loopback proxy and fails behind a middlebox, and the only way to know
    /// is to offer it every prefix.
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

    /// A proxy that selects a method the client never offered is refused rather
    /// than followed: answering `USERPASS` with no credentials would send an
    /// empty username to a server that asked for one.
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

    /// A rejected credential ends the exchange where it happens, rather than
    /// sending a request the proxy will refuse anyway.
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
