//! VLESS as a stream egress, over a pluggable transport.
//!
//! VLESS is a thin, stateless authentication header: a version byte, a 16-byte
//! user id, an optional addon block, a command, and a destination. It carries
//! no encryption of its own — deliberately, because it is designed to run
//! *inside* a transport that already provides it. That is the whole protocol,
//! and it is why this module is mostly a codec.
//!
//! **The transport is a seam, and that is the point.** VLESS over plain TCP,
//! over TLS, over WebSocket, over gRPC and over QUIC differ only in how the
//! byte stream underneath is obtained, so [`ProxyTransport`] names exactly that
//! and nothing else. Every one of them is an implementation of that one trait
//! in [`crate::egress::transport`] rather than a change to this file, which is what
//! lets this module stay a codec while the transport family grows.
//!
//! **The address encoding is *not* SOCKS5's, and the difference is silent.**
//! VMess and VLESS write the **port before** the address, and their type bytes
//! disagree with RFC 1928 on two of three values: `0x02` is a domain here and
//! IPv6 there, `0x03` is IPv6 here and a domain there. Reusing the SOCKS5
//! encoder would produce a header that parses successfully into the wrong
//! destination for every name and every IPv6 address. They are separate
//! functions for that reason, and the tests pin both.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    Association, AsyncStream, BoxFuture, Codec, DatagramFidelity, DatagramSink, DatagramSource,
    Decode, Decoded, DomainName, EgressError, Framed, NatBehavior, PathProperties, ProxyError,
    ProxyTransport, StreamEgress, Target, Writes,
    wire::{Reader, Writer},
};

/// The only VLESS version, and the only one the reference implementations
/// accept. VMess uses 1 for its own header; the two are unrelated numbers.
const VERSION: u8 = 0;

/// Commands, from the reference implementation. Only `Tcp` is issued here:
/// VLESS UDP needs a length-prefixed packet framing this egress does not
/// implement, and the path properties say so rather than implying it.
const COMMAND_TCP: u8 = 1;
/// UDP. **The address in the request header is the only one there is** — a
/// datagram frame on a UDP stream carries a length and a payload and nothing
/// else — so one stream serves exactly one destination. That is what shapes
/// [`VlessDatagrams`] and it is not a shortcut: Xray's own non-mux path works
/// the same way, which is why it reserves that path for DNS and reaches for
/// XUDP everywhere else.
const COMMAND_UDP: u8 = 2;

/// VMess/VLESS address family bytes. Note `Domain` and `Ipv6` relative to
/// SOCKS5: the values are swapped, which is why this table is written out.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// A VLESS user id: sixteen bytes, usually written as a hyphenated UUID.
///
/// Refined because the wire carries exactly sixteen bytes and the
/// configuration carries text: parsing once here means no encoder re-checks a
/// length, and a mistyped id fails where it is configured rather than as an
/// unexplained rejection from the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserId([u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserIdError {
    /// Not 32 hexadecimal digits once hyphens are removed.
    Length(usize),
    /// A character that is not a hexadecimal digit or a hyphen.
    Digit,
}

impl UserId {
    /// Parses the canonical hyphenated form, and equally the unhyphenated one:
    /// hyphens carry no information, so they are ignored rather than demanded
    /// in fixed positions.
    ///
    /// O(text length), no allocation.
    pub fn parse(text: &str) -> Result<Self, UserIdError> {
        let mut bytes = [0u8; 16];
        let mut digits = 0usize;
        for character in text.chars().filter(|character| *character != '-') {
            let value = character.to_digit(16).ok_or(UserIdError::Digit)? as u8;
            if digits >= 32 {
                return Err(UserIdError::Length(digits + 1));
            }
            // Two hex digits per byte, high nibble first.
            bytes[digits / 2] |= value << if digits.is_multiple_of(2) { 4 } else { 0 };
            digits += 1;
        }
        if digits != 32 {
            return Err(UserIdError::Length(digits));
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    /// The canonical 8-4-4-4-12 form, so a round trip through `parse` is the
    /// identity and a logged id is one an operator can paste into a config.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Writes a destination in VMess/VLESS form: **port first**, then the family
/// byte, then the address.
///
/// O(address length). Kept separate from the SOCKS5 encoder because the two
/// formats differ in field order *and* in two of three family bytes; sharing
/// one function would silently mis-address every name and every IPv6 host.
pub fn encode_addr_port(target: &Target, out: &mut Vec<u8>) {
    let mut writer = Writer::new(out);
    writer.u16(target.port());
    match target {
        Target::Ip(SocketAddr::V4(address)) => writer.u8(ATYP_IPV4).bytes(&address.ip().octets()),
        Target::Ip(SocketAddr::V6(address)) => writer.u8(ATYP_IPV6).bytes(&address.ip().octets()),
        // The length octet needs no check: `DomainName` bounds itself at 255.
        Target::Domain { host, .. } => writer.u8(ATYP_DOMAIN).vector_u8(host.as_str().as_bytes()),
    };
}

/// Reads a destination in VMess/VLESS form. Total on untrusted input, and
/// `Incomplete` rather than an error while bytes are still missing.
pub fn decode_addr_port(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let (Some(port), Some(atyp)) = (reader.u16(), reader.u8()) else {
        return Ok(Decoded::Incomplete);
    };
    // Port first, then the family byte: the field order is what this shares
    // nothing with the SOCKS5 decoder over. The widths below are read the same
    // way, so only the order and the family bytes differ between the two.
    let body = match atyp {
        ATYP_IPV4 => reader.take(4),
        ATYP_IPV6 => reader.take(16),
        ATYP_DOMAIN => reader.vector_u8(),
        _ => return Err(ProxyError::Address),
    };
    let Some(body) = body else {
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

/// Writes a VLESS request header.
///
/// `version || uuid || addons_len || addons || command || port || atyp ||
/// address`. The addon block is empty here: it carries the flow identifier
/// that XTLS Vision uses, which belongs with Reality rather than with plain
/// VLESS, and an empty block is the explicit "no flow" the reference expects.
pub fn encode_request(user: &UserId, target: &Target, out: &mut Vec<u8>) {
    request(user, target, COMMAND_TCP, out);
}

/// The same header with the UDP command. Separate rather than a boolean
/// parameter, because the two produce streams that behave differently enough
/// that a caller should have had to name which it wanted.
pub fn encode_datagram_request(user: &UserId, target: &Target, out: &mut Vec<u8>) {
    request(user, target, COMMAND_UDP, out);
}

fn request(user: &UserId, target: &Target, command: u8, out: &mut Vec<u8>) {
    Writer::new(out)
        .u8(VERSION)
        .bytes(user.as_bytes())
        .u8(0) // addons length: no flow
        .u8(command);
    encode_addr_port(target, out);
}

/// Reads a VLESS response header: a version and an addon block to skip.
///
/// Returns how many bytes the header used, so the caller can hand the
/// remainder to the application as payload.
pub fn decode_response(bytes: &[u8]) -> Result<Decoded<()>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(version) = reader.u8() else {
        return Ok(Decoded::Incomplete);
    };
    if version != VERSION {
        return Err(ProxyError::Version(version));
    }
    // The addon block is skipped rather than read: this client sends no flow,
    // so anything a server puts there is not addressed to it.
    if reader.vector_u8().is_none() {
        return Ok(Decoded::Incomplete);
    }
    Ok(Decoded::Complete {
        value: (),
        consumed: reader.position(),
    })
}

/// Static configuration for one VLESS server.
pub struct VlessConfig {
    pub user: UserId,
    /// The server's RFC 4787 mapping behavior, configuration for the same
    /// reason every other egress's is: it belongs to the server.
    pub nat_behavior: NatBehavior,
}

// ---------------------------------------------------------- UDP

/// One datagram on a UDP stream: a big-endian length and that many bytes.
///
/// The whole per-packet framing. No address, no session identifier, no sequence
/// number — everything that would identify a packet is instead a property of
/// the stream it arrived on.
const LENGTH_PREFIX: usize = 2;

/// The largest frame the reference writer will emit, which is its 8 KiB buffer
/// less the prefix. Read side accepts up to 65535, but writing more than a peer
/// will write is how a client discovers that a server silently drops it.
const MAX_FRAME: usize = 8192 - LENGTH_PREFIX;

/// Datagrams held for a mapping that is not draining them. Bounded and lossy,
/// as every datagram queue in this crate is.
const INBOUND_DEPTH: usize = 64;

/// The sending half of one destination's stream. Shared, because `send_to`
/// takes `&self` and every flow in the mapping writes through the same one.
type SharedSink = Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>;

/// One VLESS datagram association: a stream per destination, and one queue for
/// what comes back.
///
/// **A stream per destination is what the protocol leaves us.** The target
/// lives in the request header and a frame carries only a length, so a stream
/// is bound to one peer for its life. Every reply on it is therefore *from*
/// that peer, which is how [`DatagramSource`] can name a source at all without
/// a per-packet address to read.
///
/// The visible consequence is the NAT behaviour: a server opens its own socket
/// per stream, so two destinations see two source ports. That is what
/// `nat_behavior` on [`VlessConfig`] is for, and configuring it as anything
/// more generous than address-and-port-dependent would be a claim this shape
/// cannot support.
struct VlessDatagrams<T> {
    transport: Arc<T>,
    user: UserId,
    /// The write half of the stream serving each destination, opened on first
    /// use. An async mutex because opening one awaits, and because two flows to
    /// the same peer arriving together must produce *one* stream rather than
    /// two — the second waits and finds the first's.
    streams: Mutex<HashMap<Target, SharedSink>>,
    inbound: mpsc::Sender<(Vec<u8>, Target)>,
    /// Ends every reader task this association started. Its lifetime is the
    /// association's, so a dropped association leaves no task holding a socket.
    shutdown: CancellationToken,
}

impl<T> Drop for VlessDatagrams<T> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<T: ProxyTransport + 'static> VlessDatagrams<T> {
    /// The stream serving `target`, opening and registering one if there is
    /// none.
    ///
    /// O(1) amortised. The lock is held across the dial deliberately: it is
    /// what makes concurrent first datagrams to one peer share a stream instead
    /// of racing to build two, and a second stream would mean a second source
    /// port the peer sees.
    async fn stream(&self, target: &Target) -> Result<SharedSink, EgressError> {
        let mut held = self.streams.lock().await;
        if let Some(stream) = held.get(target) {
            return Ok(Arc::clone(stream));
        }

        let stream = self.transport.dial().await?;
        let mut request = Vec::with_capacity(64);
        encode_datagram_request(&self.user, target, &mut request);
        let (reader, mut writer) = tokio::io::split(stream);
        writer.write_all(&request).await?;
        writer.flush().await?;

        tokio::spawn(read_datagrams(
            reader,
            target.clone(),
            self.inbound.clone(),
            self.shutdown.clone(),
        ));

        let writer: SharedSink = Arc::new(Mutex::new(Box::new(writer)));
        held.insert(target.clone(), Arc::clone(&writer));
        Ok(writer)
    }
}

/// Reads one stream's frames until it ends, attributing each to the peer the
/// stream was opened for.
///
/// The response header is consumed here rather than at dial, for the reason the
/// TCP side gives: a server sends it with its first payload, which may be long
/// after the request, and waiting at dial would block on the *target* rather
/// than on the proxy.
async fn read_datagrams<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    target: Target,
    inbound: mpsc::Sender<(Vec<u8>, Target)>,
    shutdown: CancellationToken,
) {
    let mut held: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; MAX_FRAME];
    let mut header = false;

    loop {
        let read = tokio::select! {
            () = shutdown.cancelled() => break,
            read = reader.read(&mut chunk) => match read {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            },
        };
        held.extend_from_slice(&chunk[..read]);

        if !header {
            match decode_response(&held) {
                Ok(Decoded::Complete { consumed, .. }) => {
                    held.drain(..consumed);
                    header = true;
                }
                Ok(Decoded::Incomplete) => continue,
                Err(_) => break,
            }
        }

        // Every whole frame currently held. A partial one stays for the next
        // read rather than being delivered short: half a datagram is not a
        // smaller datagram.
        while let Some(length) = Reader::new(&held).u16().map(usize::from) {
            if held.len() < LENGTH_PREFIX + length {
                break;
            }
            let payload = held[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec();
            held.drain(..LENGTH_PREFIX + length);
            // A zero-length frame is what the reference writer refuses to
            // emit, so one arriving is noise rather than an empty datagram.
            if length > 0 && inbound.try_send((payload, target.clone())).is_err() {
                // The mapping is gone, or is not keeping up.
                continue;
            }
        }
    }
}

impl<T: ProxyTransport + 'static> DatagramSink for VlessDatagrams<T> {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            if payload.len() > MAX_FRAME {
                return Err(EgressError::DatagramTooLarge {
                    required: payload.len(),
                });
            }
            let stream = self.stream(target).await?;
            let mut frame = Vec::with_capacity(LENGTH_PREFIX + payload.len());
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);
            // One write for the whole frame: a length that reached the server
            // without its payload behind it would desynchronise the stream for
            // good, and there is no resynchronisation point in this framing.
            let mut writer = stream.lock().await;
            writer.write_all(&frame).await?;
            writer.flush().await?;
            Ok(())
        })
    }
}

/// The receiving half: every stream's reader feeds this one queue.
struct VlessReplies {
    inbound: mpsc::Receiver<(Vec<u8>, Target)>,
    /// Held so the streams and their reader tasks outlive this half. Without
    /// it, a caller that dropped the sink and kept the source would stop
    /// receiving the moment the last stream closed.
    _sink: Arc<dyn DatagramSink>,
}

impl DatagramSource for VlessReplies {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            let (payload, from) = self
                .inbound
                .recv()
                .await
                .ok_or(EgressError::Io(std::io::ErrorKind::BrokenPipe))?;
            let Some(into) = buf.get_mut(..payload.len()) else {
                return Err(EgressError::DatagramTooLarge {
                    required: payload.len(),
                });
            };
            into.copy_from_slice(&payload);
            Ok((payload.len(), from))
        })
    }
}

/// A VLESS server as a stream egress, over any [`ProxyTransport`].
pub struct VlessEgress<T> {
    config: VlessConfig,
    /// Shared rather than owned, because a datagram association holds one
    /// stream per destination and each is dialled through this. `new` still
    /// takes the transport by value: whether it is shared is this type's
    /// business, not its caller's.
    transport: Arc<T>,
}

impl<T: ProxyTransport> VlessEgress<T> {
    pub fn new(config: VlessConfig, transport: T) -> Self {
        Self {
            config,
            transport: Arc::new(transport),
        }
    }
}

impl<T: ProxyTransport + 'static> StreamEgress for VlessEgress<T> {
    fn properties(&self) -> PathProperties {
        PathProperties {
            // **Emulated, not native, and the distinction is the whole point.**
            // Datagram *boundaries* survive exactly -- the framing is a length
            // and a payload -- but they cross a reliable, ordered stream, so a
            // lost packet is retransmitted and everything behind it waits.
            // That is fine for DNS and wrong for QUIC, which is precisely what
            // `Emulated` tells the planner: carry the datagram flow, steer the
            // QUIC one to HTTP/2 rather than running a loss-tolerant protocol
            // over a loss-hiding transport.
            datagram_fidelity: DatagramFidelity::Emulated,
            overhead_bytes: 0,
            max_datagram_size: Some(MAX_FRAME as u16),
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    /// Opens a datagram association.
    ///
    /// **Nothing is dialled here.** A stream is bound to one destination for
    /// its life, so there is no stream to open until a datagram names where it
    /// is going; the association is a routing table and a queue, and it costs
    /// one channel until the first packet.
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_DEPTH);
            let sink = Arc::new(VlessDatagrams {
                transport: Arc::clone(&self.transport),
                user: self.config.user,
                streams: Mutex::new(HashMap::new()),
                inbound: inbound_tx,
                shutdown: CancellationToken::new(),
            });
            Ok(Association {
                source: Box::new(VlessReplies {
                    inbound: inbound_rx,
                    _sink: Arc::clone(&sink) as Arc<dyn DatagramSink>,
                }),
                sink,
            })
        })
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let mut stream = self.transport.dial().await?;
            let mut request = Vec::with_capacity(64);
            encode_request(&self.config.user, target, &mut request);
            stream.write_all(&request).await?;
            stream.flush().await?;
            // The response header is consumed lazily by the codec, for the
            // reason its own documentation gives.
            Ok(Box::new(Framed::new(stream, ResponseHeader::default())) as Box<dyn AsyncStream>)
        })
    }
}

/// Strips the response header, then gets out of the way.
///
/// **A codec rather than a negotiation, because the header does not arrive at
/// dial.** A VLESS server writes it with its first payload, which may be long
/// after the request; waiting for it in `connect` would block on the *target*
/// rather than on the proxy, and a server-first protocol behind the proxy would
/// never connect at all.
///
/// Once stripped, the stream is the payload and nothing else, which
/// [`Decode::Transparent`] says — so the steady state costs no copy in either
/// direction.
#[derive(Default)]
struct ResponseHeader {
    stripped: bool,
}

impl Codec for ResponseHeader {
    /// O(1): the header is a version byte and a length-prefixed addon block.
    fn decode<'a>(
        &mut self,
        input: &'a [u8],
        _out: &mut Vec<u8>,
    ) -> Result<Decode<'a>, ProxyError> {
        if self.stripped {
            return Ok(Decode::Transparent { rest: input });
        }
        match decode_response(input)? {
            Decoded::Complete { consumed, .. } => {
                self.stripped = true;
                // Carved out of `input`, so the header length the decoder
                // reported cannot become an index past the end of it.
                let rest = input.get(consumed..).ok_or(ProxyError::Header)?;
                Ok(Decode::Transparent { rest })
            }
            Decoded::Incomplete => Ok(Decode::Framed { rest: input }),
        }
    }

    /// **VLESS writes raw bytes.** The request header went out once, in
    /// `connect`; everything after it is the client's own stream, so it reaches
    /// the transport untouched.
    fn writes(&self) -> Writes {
        Writes::Verbatim
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
    fn a_user_id_round_trips_through_its_canonical_form() {
        let text = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let user = UserId::parse(text).unwrap();
        assert_eq!(user.to_string(), text, "display is parse's inverse");
        assert_eq!(user.as_bytes()[0], 0xb8);
        assert_eq!(user.as_bytes()[15], 0x11);

        // Hyphens carry no information, so their absence is accepted.
        assert_eq!(UserId::parse("b831381d63244d53ad4f8cda48b30811"), Ok(user));

        // And malformed input is refused where it is configured. Valid hex
        // that is simply too short is a length failure...
        assert_eq!(UserId::parse("abcdef"), Err(UserIdError::Length(6)));
        // ...while a non-hex character is caught as it is read, before any
        // length is known. The two are different faults and are named
        // separately so a configuration error points at its own cause.
        assert_eq!(UserId::parse("not-a-uuid"), Err(UserIdError::Digit));
        assert_eq!(
            UserId::parse("b831381d-6324-4d53-ad4f-8cda48b3081"),
            Err(UserIdError::Length(31))
        );
        assert_eq!(
            UserId::parse("b831381d-6324-4d53-ad4f-8cda48b3081z"),
            Err(UserIdError::Digit)
        );
        assert!(matches!(
            UserId::parse("b831381d-6324-4d53-ad4f-8cda48b308111"),
            Err(UserIdError::Length(_))
        ));
    }

    /// The trap this module exists to avoid: VLESS is not SOCKS5.
    #[test]
    fn the_address_encoding_is_vmess_shaped_and_not_socks5_shaped() {
        let target = domain("example.com", 443);
        let mut vless = Vec::new();
        encode_addr_port(&target, &mut vless);

        // Port comes first, which SOCKS5 puts last.
        assert_eq!(&vless[..2], &443u16.to_be_bytes());
        // And a domain is 0x02 here, where SOCKS5 spells it 0x03.
        assert_eq!(vless[2], 0x02);
        assert_eq!(vless[3], 11, "the name's length octet");
        assert_eq!(&vless[4..], b"example.com");

        // The same target under the SOCKS5 encoder is a different byte string;
        // if these ever agree, one of the two encoders has been broken.
        let mut socks = Vec::new();
        crate::encode_address(&target, &mut socks);
        assert_ne!(vless, socks, "the two wire formats must not converge");

        // IPv6 is 0x03 here, which is a domain in SOCKS5 — the other half of
        // the swap, and the one that would parse into nonsense rather than
        // failing loudly.
        let mut six = Vec::new();
        encode_addr_port(&Target::Ip("[2001:db8::1]:8443".parse().unwrap()), &mut six);
        assert_eq!(six[2], 0x03);
    }

    #[test]
    fn every_address_form_round_trips_and_short_input_waits() {
        let targets = [
            Target::Ip("192.0.2.1:443".parse().unwrap()),
            Target::Ip("[2001:db8::1]:8443".parse().unwrap()),
            domain("example.com", 80),
            domain(&"a".repeat(255), 65535),
        ];
        for target in targets {
            let mut encoded = Vec::new();
            encode_addr_port(&target, &mut encoded);
            assert_eq!(
                decode_addr_port(&encoded),
                Ok(Decoded::Complete {
                    value: target.clone(),
                    consumed: encoded.len(),
                })
            );
            for split in 0..encoded.len() {
                assert_eq!(
                    decode_addr_port(&encoded[..split]),
                    Ok(Decoded::Incomplete),
                    "{target} truncated to {split} bytes must wait"
                );
            }
        }
        // An unknown family is refused rather than guessed.
        assert_eq!(
            decode_addr_port(&[0, 80, 0x09, 1, 2, 3, 4]),
            Err(ProxyError::Address)
        );
    }

    #[test]
    fn a_request_header_has_the_layout_the_reference_reads() {
        let user = UserId::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let mut request = Vec::new();
        encode_request(&user, &domain("example.com", 443), &mut request);

        assert_eq!(request[0], VERSION);
        assert_eq!(&request[1..17], user.as_bytes());
        assert_eq!(request[17], 0, "no addons, so no flow");
        assert_eq!(request[18], COMMAND_TCP);
        // Then the destination, port first.
        assert_eq!(&request[19..21], &443u16.to_be_bytes());
        assert_eq!(request[21], ATYP_DOMAIN);
    }

    #[test]
    fn a_response_header_is_skipped_including_its_addons() {
        // No addons: two bytes.
        assert_eq!(
            decode_response(&[VERSION, 0]),
            Ok(Decoded::Complete {
                value: (),
                consumed: 2
            })
        );
        // Addons are skipped whole.
        assert_eq!(
            decode_response(&[VERSION, 3, 0xaa, 0xbb, 0xcc]),
            Ok(Decoded::Complete {
                value: (),
                consumed: 5
            })
        );
        // Not yet, rather than wrong.
        assert_eq!(decode_response(&[]), Ok(Decoded::Incomplete));
        assert_eq!(decode_response(&[VERSION]), Ok(Decoded::Incomplete));
        assert_eq!(
            decode_response(&[VERSION, 3, 0xaa]),
            Ok(Decoded::Incomplete)
        );
        // A version this client does not speak is named.
        assert_eq!(decode_response(&[9, 0]), Err(ProxyError::Version(9)));
    }

    /// The UDP command differs from TCP in exactly one byte, and the address
    /// still rides in the request header — which is the fact the whole
    /// stream-per-destination shape follows from.
    #[test]
    fn a_datagram_request_differs_from_a_stream_one_by_its_command() {
        let user = UserId::parse("11111111-2222-3333-4444-555555555555").unwrap();
        let target = Target::Domain {
            host: DomainName::new("example.com").unwrap(),
            port: 443,
        };

        let (mut tcp, mut udp) = (Vec::new(), Vec::new());
        encode_request(&user, &target, &mut tcp);
        encode_datagram_request(&user, &target, &mut udp);

        assert_eq!(tcp.len(), udp.len());
        assert_eq!(tcp[18], COMMAND_TCP);
        assert_eq!(udp[18], COMMAND_UDP);
        assert_eq!(&tcp[..18], &udp[..18], "version, user, and addons agree");
        assert_eq!(
            &tcp[19..],
            &udp[19..],
            "and the destination is in the header either way"
        );
    }

    /// A reader that only ever sees whole frames would pass on a stream that
    /// delivers one byte at a time, which is what a real one does. **A partial
    /// frame is held, never delivered short** — half a datagram is not a
    /// smaller datagram.
    #[tokio::test]
    async fn frames_reassemble_across_arbitrary_read_boundaries() {
        let target = Target::Ip("198.51.100.7:53".parse().unwrap());
        let payloads: [&[u8]; 3] = [b"first", b"second one", b"3"];

        // A response header, then three framed datagrams.
        let mut wire = vec![0u8, 0u8];
        for payload in payloads {
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(payload);
        }

        for chunk in [1usize, 2, 7, wire.len()] {
            let (mut writer, reader) = tokio::io::duplex(64);
            let (inbound_tx, mut inbound_rx) = mpsc::channel(8);
            let shutdown = CancellationToken::new();
            tokio::spawn(read_datagrams(
                reader,
                target.clone(),
                inbound_tx,
                shutdown.clone(),
            ));

            let wire = wire.clone();
            tokio::spawn(async move {
                for piece in wire.chunks(chunk) {
                    writer.write_all(piece).await.unwrap();
                    writer.flush().await.unwrap();
                }
                // Held open: closing would end the reader before the last
                // frame had been taken off the channel.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            });

            for expected in payloads {
                let (payload, from) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), inbound_rx.recv())
                        .await
                        .unwrap_or_else(|_| panic!("chunked by {chunk}: a frame never arrived"))
                        .expect("the channel is open");
                assert_eq!(payload, expected, "chunked by {chunk}");
                assert_eq!(
                    from, target,
                    "attributed to the peer its stream was opened for"
                );
            }
        }
    }

    /// The response header is stripped once and never re-read. A stream that
    /// re-parsed it after the first frame would read payload as a header and
    /// desynchronise for good.
    #[tokio::test]
    async fn the_response_header_is_consumed_exactly_once() {
        let target = Target::Ip("198.51.100.7:53".parse().unwrap());
        // A header with a two-byte addon block, so a second parse would eat
        // four bytes of the frame behind it and produce nonsense.
        let mut wire = vec![0u8, 2u8, 0xaa, 0xbb];
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"hello");
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"world");

        let (mut writer, reader) = tokio::io::duplex(64);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(8);
        tokio::spawn(read_datagrams(
            reader,
            target.clone(),
            inbound_tx,
            CancellationToken::new(),
        ));
        tokio::spawn(async move {
            writer.write_all(&wire).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        assert_eq!(inbound_rx.recv().await.unwrap().0, b"hello");
        assert_eq!(inbound_rx.recv().await.unwrap().0, b"world");
    }

    /// Cancelling the association ends every reader it started, so a dropped
    /// association leaves no task holding a socket.
    #[tokio::test]
    async fn cancelling_ends_a_reader_that_is_still_waiting() {
        let (_writer, reader) = tokio::io::duplex(64);
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let reading = tokio::spawn(read_datagrams(
            reader,
            Target::Ip("198.51.100.7:53".parse().unwrap()),
            inbound_tx,
            shutdown.clone(),
        ));

        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), reading)
            .await
            .expect("the reader observes cancellation rather than blocking on a read")
            .unwrap();
    }

    /// **The defect the port removed, pinned so it cannot come back.** A
    /// response header and 300 bytes of payload arrive in one segment; the
    /// caller reads 16 at a time. The hand-written adapter this replaced handed
    /// out one bufferful and dropped the other 284 with no error anywhere —
    /// a `debug_assert` in release is not a check.
    #[tokio::test]
    async fn a_small_reader_takes_every_byte_that_arrived_with_the_header() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // Version byte, no addons, then payload.
            let mut wire = vec![0u8, 0u8];
            wire.extend(std::iter::repeat_n(b'x', 300));
            peer.write_all(&wire).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut stream = Framed::new(ours, ResponseHeader::default());
        let mut total = 0usize;
        let mut small = [0u8; 16];
        while total < 300 {
            let read = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read(&mut small),
            )
            .await
            .expect("the payload is still coming")
            .unwrap();
            if read == 0 {
                break;
            }
            assert!(small[..read].iter().all(|byte| *byte == b'x'));
            total += read;
        }
        assert_eq!(
            total, 300,
            "every byte the header arrived with reached the caller"
        );
    }

    /// The header may arrive in pieces, and a server that sends it one byte at
    /// a time is a server behind a middlebox that split the segment.
    #[tokio::test]
    async fn the_header_is_stripped_across_arbitrary_read_boundaries() {
        for chunk in [1usize, 2, 3, 64] {
            let (mut peer, ours) = tokio::io::duplex(4096);
            // Two addon bytes, so a second parse would eat payload.
            let mut wire = vec![0u8, 2u8, 0xaa, 0xbb];
            wire.extend_from_slice(b"payload");
            tokio::spawn(async move {
                for piece in wire.chunks(chunk) {
                    peer.write_all(piece).await.unwrap();
                    peer.flush().await.unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            });

            let mut stream = Framed::new(ours, ResponseHeader::default());
            let mut seen = Vec::new();
            while seen.len() < 7 {
                let mut buf = [0u8; 32];
                let read = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                .unwrap_or_else(|_| panic!("chunked by {chunk}: stalled"))
                .unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            assert_eq!(seen, b"payload", "chunked by {chunk}");
        }
    }

    /// The header is consumed once. Re-parsing it after the first payload would
    /// read payload as a header and desynchronise a stream that has no
    /// resynchronisation point.
    #[test]
    fn the_header_is_consumed_exactly_once() {
        let mut codec = ResponseHeader::default();
        let mut out = Vec::new();

        // The whole header, with nothing behind it.
        assert_eq!(
            codec.decode(&[0u8, 2, 0xaa, 0xbb], &mut out).unwrap(),
            Decode::Transparent { rest: &[] }
        );
        // Everything after is payload, and the codec claims none of it.
        let payload = b"\x00\x02more";
        assert_eq!(
            codec.decode(payload, &mut out).unwrap(),
            Decode::Transparent { rest: payload },
            "bytes that merely look like a header are payload now"
        );
        assert!(out.is_empty(), "a strip produces nothing of its own");
    }

    /// A version this crate does not speak is refused rather than skipped over.
    #[test]
    fn a_response_from_a_protocol_this_is_not_is_refused() {
        let mut codec = ResponseHeader::default();
        assert!(codec.decode(&[9u8, 0], &mut Vec::new()).is_err());
    }
}
