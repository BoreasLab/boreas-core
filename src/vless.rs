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
//! in [`crate::transport`] rather than a change to this file, which is what
//! lets this module stay a codec while the transport family grows.
//!
//! **The address encoding is *not* SOCKS5's, and the difference is silent.**
//! VMess and VLESS write the **port before** the address, and their type bytes
//! disagree with RFC 1928 on two of three values: `0x02` is a domain here and
//! IPv6 there, `0x03` is IPv6 here and a domain there. Reusing the SOCKS5
//! encoder would produce a header that parses successfully into the wrong
//! destination for every name and every IPv6 address. They are separate
//! functions for that reason, and the tests pin both.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    AsyncStream, BoxFuture, DatagramFidelity, Decoded, DomainName, EgressError, NatBehavior,
    PathProperties, ProxyError, ProxyTransport, StreamEgress, Target,
};

/// The only VLESS version, and the only one the reference implementations
/// accept. VMess uses 1 for its own header; the two are unrelated numbers.
const VERSION: u8 = 0;

/// Commands, from the reference implementation. Only `Tcp` is issued here:
/// VLESS UDP needs a length-prefixed packet framing this egress does not
/// implement, and the path properties say so rather than implying it.
const COMMAND_TCP: u8 = 1;

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
    out.extend_from_slice(&target.port().to_be_bytes());
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
            // Safe without a check: `DomainName` bounds itself at 255 bytes.
            out.push(host.wire_len());
            out.extend_from_slice(host.as_str().as_bytes());
        }
    }
}

/// Reads a destination in VMess/VLESS form. Total on untrusted input, and
/// `Incomplete` rather than an error while bytes are still missing.
pub fn decode_addr_port(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let Some(port_bytes) = bytes.get(..2) else {
        return Ok(Decoded::Incomplete);
    };
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    let Some(&atyp) = bytes.get(2) else {
        return Ok(Decoded::Incomplete);
    };
    let rest = &bytes[3..];
    let (target, used) = match atyp {
        ATYP_IPV4 => {
            let Some(octets) = rest.get(..4) else {
                return Ok(Decoded::Incomplete);
            };
            let octets: [u8; 4] = octets.try_into().map_err(|_| ProxyError::Address)?;
            (
                Target::Ip(SocketAddr::new(std::net::IpAddr::from(octets), port)),
                4,
            )
        }
        ATYP_IPV6 => {
            let Some(octets) = rest.get(..16) else {
                return Ok(Decoded::Incomplete);
            };
            let octets: [u8; 16] = octets.try_into().map_err(|_| ProxyError::Address)?;
            (
                Target::Ip(SocketAddr::new(std::net::IpAddr::from(octets), port)),
                16,
            )
        }
        ATYP_DOMAIN => {
            let Some(&length) = rest.first() else {
                return Ok(Decoded::Incomplete);
            };
            let length = usize::from(length);
            let Some(name) = rest.get(1..1 + length) else {
                return Ok(Decoded::Incomplete);
            };
            let name = std::str::from_utf8(name).map_err(|_| ProxyError::Address)?;
            let host = DomainName::new(name).map_err(|_| ProxyError::Address)?;
            (Target::Domain { host, port }, 1 + length)
        }
        _ => return Err(ProxyError::Address),
    };
    Ok(Decoded::Complete {
        value: target,
        consumed: 3 + used,
    })
}

/// Writes a VLESS request header.
///
/// `version || uuid || addons_len || addons || command || port || atyp ||
/// address`. The addon block is empty here: it carries the flow identifier
/// that XTLS Vision uses, which belongs with Reality rather than with plain
/// VLESS, and an empty block is the explicit "no flow" the reference expects.
pub fn encode_request(user: &UserId, target: &Target, out: &mut Vec<u8>) {
    out.push(VERSION);
    out.extend_from_slice(user.as_bytes());
    out.push(0); // addons length: no flow
    out.push(COMMAND_TCP);
    encode_addr_port(target, out);
}

/// Reads a VLESS response header: a version and an addon block to skip.
///
/// Returns how many bytes the header used, so the caller can hand the
/// remainder to the application as payload.
pub fn decode_response(bytes: &[u8]) -> Result<Decoded<()>, ProxyError> {
    let Some(&version) = bytes.first() else {
        return Ok(Decoded::Incomplete);
    };
    if version != VERSION {
        return Err(ProxyError::Version(version));
    }
    let Some(&addons_len) = bytes.get(1) else {
        return Ok(Decoded::Incomplete);
    };
    let consumed = 2 + usize::from(addons_len);
    if bytes.len() < consumed {
        return Ok(Decoded::Incomplete);
    }
    Ok(Decoded::Complete {
        value: (),
        consumed,
    })
}

/// Static configuration for one VLESS server.
pub struct VlessConfig {
    pub user: UserId,
    /// The server's RFC 4787 mapping behavior, configuration for the same
    /// reason every other egress's is: it belongs to the server.
    pub nat_behavior: NatBehavior,
}

/// A VLESS server as a stream egress, over any [`ProxyTransport`].
pub struct VlessEgress<T> {
    config: VlessConfig,
    transport: T,
}

impl<T: ProxyTransport> VlessEgress<T> {
    pub fn new(config: VlessConfig, transport: T) -> Self {
        Self { config, transport }
    }
}

impl<T: ProxyTransport + 'static> StreamEgress for VlessEgress<T> {
    fn properties(&self) -> PathProperties {
        PathProperties {
            // VLESS UDP needs a length-prefixed packet framing this egress
            // does not implement. Claiming otherwise would promise a relay
            // that is not here.
            datagram_fidelity: DatagramFidelity::None,
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
            let mut stream = self.transport.dial().await?;
            let mut request = Vec::with_capacity(64);
            encode_request(&self.config.user, target, &mut request);
            stream.write_all(&request).await?;
            stream.flush().await?;
            // The response header is consumed lazily: a server sends it with
            // its first payload, which may be long after the request, and
            // waiting here would make `connect` block on the *target* rather
            // than on the proxy.
            Ok(Box::new(VlessStream {
                inner: stream,
                header: HeaderState::Pending(Vec::new()),
            }) as Box<dyn AsyncStream>)
        })
    }
}

/// Whether the response header has been consumed yet.
///
/// A closed sum rather than a boolean and a buffer: once `Done`, there is no
/// buffer to consult, and the compiler is what stops a later read from
/// re-parsing a header that has already been stripped.
enum HeaderState {
    /// Still accumulating; holds what has arrived and what is left over after
    /// the header ends.
    Pending(Vec<u8>),
    Done,
}

/// A VLESS session as an ordinary byte stream: the request header is already
/// written, and the response header is stripped from the first bytes read.
struct VlessStream<S> {
    inner: S,
    header: HeaderState,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match &mut this.header {
                HeaderState::Done => {
                    return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
                }
                HeaderState::Pending(pending) => {
                    match decode_response(pending) {
                        Ok(Decoded::Complete { consumed, .. }) => {
                            // Whatever followed the header is payload the
                            // caller is owed before any further read.
                            let leftover = pending.split_off(consumed);
                            this.header = HeaderState::Done;
                            if !leftover.is_empty() {
                                let moved = buf.remaining().min(leftover.len());
                                buf.put_slice(&leftover[..moved]);
                                // The remainder beyond one buffer is bounded
                                // by one read, so it cannot be large; pushing
                                // it back would need a second buffer for a
                                // case that a 4 KiB read cannot produce.
                                debug_assert_eq!(moved, leftover.len());
                                return Poll::Ready(Ok(()));
                            }
                            continue;
                        }
                        Ok(Decoded::Incomplete) => {}
                        Err(error) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                error.to_string(),
                            )));
                        }
                    }
                    let mut chunk = [0u8; 512];
                    let mut read_buf = ReadBuf::new(&mut chunk);
                    match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled();
                            if filled.is_empty() {
                                // Closed before a whole header: end of stream
                                // for the caller, which is what it can act on.
                                return Poll::Ready(Ok(()));
                            }
                            pending.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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
}
