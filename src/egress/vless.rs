//! VLESS stream egress over a pluggable transport.
//!
//! VLESS supplies a version, user ID, optional addons, command, and target;
//! encryption comes from the underlying transport. The transport trait keeps
//! TCP, TLS, WebSocket, gRPC, and QUIC composition outside this codec.
//!
//! VLESS addresses use port-first ordering and family values distinct from
//! SOCKS5, so their encoder and decoder remain separate.

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

/// VLESS protocol version.
const VERSION: u8 = 0;

/// VLESS TCP command.
const COMMAND_TCP: u8 = 1;
/// VLESS UDP command.
const COMMAND_UDP: u8 = 2;

/// VMess/VLESS address family bytes.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// A 16-byte VLESS user ID.
///
/// Text parsing validates the wire-sized representation at configuration time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserId([u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserIdError {
    /// The parsed text has the wrong number of hexadecimal digits.
    Length(usize),
    /// The text contains a non-hexadecimal, non-hyphen character.
    Digit,
}

impl UserId {
    /// Parses hyphenated or unhyphenated hexadecimal text.
    pub fn parse(text: &str) -> Result<Self, UserIdError> {
        let mut bytes = [0u8; 16];
        let mut digits = 0usize;
        for character in text.chars().filter(|character| *character != '-') {
            let value = character.to_digit(16).ok_or(UserIdError::Digit)? as u8;
            if digits >= 32 {
                return Err(UserIdError::Length(digits + 1));
            }
            // Pack two hexadecimal digits into each byte.
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
    /// Formats the ID in canonical 8-4-4-4-12 form.
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

/// Writes a VMess/VLESS destination: port, family, then address.
pub fn encode_addr_port(target: &Target, out: &mut Vec<u8>) {
    let mut writer = Writer::new(out);
    writer.u16(target.port());
    match target {
        Target::Ip(SocketAddr::V4(address)) => writer.u8(ATYP_IPV4).bytes(&address.ip().octets()),
        Target::Ip(SocketAddr::V6(address)) => writer.u8(ATYP_IPV6).bytes(&address.ip().octets()),
        // DomainName guarantees that the length fits one octet.
        Target::Domain { host, .. } => writer.u8(ATYP_DOMAIN).vector_u8(host.as_str().as_bytes()),
    };
}

/// Reads a VMess/VLESS destination; short input is incomplete.
pub fn decode_addr_port(bytes: &[u8]) -> Result<Decoded<Target>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let (Some(port), Some(atyp)) = (reader.u16(), reader.u8()) else {
        return Ok(Decoded::Incomplete);
    };
    // VLESS puts the port before the family byte, unlike SOCKS5.
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

/// Writes a VLESS TCP request header with no addons.
pub fn encode_request(user: &UserId, target: &Target, out: &mut Vec<u8>) {
    request(user, target, COMMAND_TCP, out);
}

/// Writes a VLESS UDP request header with no addons.
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

/// Reads a VLESS response header and returns its consumed length.
pub fn decode_response(bytes: &[u8]) -> Result<Decoded<()>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(version) = reader.u8() else {
        return Ok(Decoded::Incomplete);
    };
    if version != VERSION {
        return Err(ProxyError::Version(version));
    }
    // Addons are opaque to this client.
    if reader.vector_u8().is_none() {
        return Ok(Decoded::Incomplete);
    }
    Ok(Decoded::Complete {
        value: (),
        consumed: reader.position(),
    })
}

/// Configuration for one VLESS server.
pub struct VlessConfig {
    pub user: UserId,
    /// RFC 4787 mapping behavior provided by the server.
    pub nat_behavior: NatBehavior,
}

// ---------------------------------------------------------- UDP

/// UDP stream frame: big-endian payload length followed by payload.
const LENGTH_PREFIX: usize = 2;

/// Largest frame emitted by the reference writer.
const MAX_FRAME: usize = 8192 - LENGTH_PREFIX;

/// Bounded inbound datagram queue.
const INBOUND_DEPTH: usize = 64;

/// Shared writer for one destination stream.
type SharedSink = Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>;

/// VLESS UDP association with one stream per destination and one inbound queue.
///
/// The destination is in the request header, so frames on a stream inherit its
/// peer. The resulting mapping behavior is reported through `nat_behavior`.
struct VlessDatagrams<T> {
    transport: Arc<T>,
    user: UserId,
    /// Lazily opened writers, keyed by destination.
    streams: Mutex<HashMap<Target, SharedSink>>,
    inbound: mpsc::Sender<(Vec<u8>, Target)>,
    /// Cancels reader tasks when the association is dropped.
    shutdown: CancellationToken,
}

impl<T> Drop for VlessDatagrams<T> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<T: ProxyTransport + 'static> VlessDatagrams<T> {
    /// Returns the stream for `target`, opening one if needed.
    ///
    /// The lock covers dialing so concurrent first sends share one stream.
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

/// Reads frames from one destination stream until it ends.
///
/// The response header is consumed lazily with the first available bytes.
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

        // Keep partial frames until the next read.
        while let Some(length) = Reader::new(&held).u16().map(usize::from) {
            if held.len() < LENGTH_PREFIX + length {
                break;
            }
            let payload = held[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec();
            held.drain(..LENGTH_PREFIX + length);
            // Ignore zero-length frames.
            if length > 0 && inbound.try_send((payload, target.clone())).is_err() {
                // The mapping is gone or its queue is full.
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
            // Keep the length and payload in one write to preserve framing.
            let mut writer = stream.lock().await;
            writer.write_all(&frame).await?;
            writer.flush().await?;
            Ok(())
        })
    }
}

/// Receiving half of a VLESS UDP association.
struct VlessReplies {
    inbound: mpsc::Receiver<(Vec<u8>, Target)>,
    /// Keeps the streams and reader tasks alive while the source is used.
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

/// VLESS stream egress over any [`ProxyTransport`].
pub struct VlessEgress<T> {
    config: VlessConfig,
    /// Shared transport used by all destination streams.
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
            // Framing preserves boundaries, but the reliable stream emulates
            // datagrams and introduces head-of-line blocking.
            datagram_fidelity: DatagramFidelity::Emulated,
            overhead_bytes: 0,
            max_datagram_size: Some(MAX_FRAME as u16),
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    /// Creates a lazily dialed datagram association.
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
            // The response header is consumed lazily by the codec.
            Ok(Box::new(Framed::new(stream, ResponseHeader::default())) as Box<dyn AsyncStream>)
        })
    }
}

/// Strips the response header and passes the remaining stream transparently.
///
/// The header arrives with the first server payload, so it must be decoded as
/// stream data rather than during connection setup.
#[derive(Default)]
struct ResponseHeader {
    stripped: bool,
}

impl Codec for ResponseHeader {
    /// Decodes the version and length-prefixed addon block.
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
                // Decode reported a consumed prefix of this input.
                let rest = input.get(consumed..).ok_or(ProxyError::Header)?;
                Ok(Decode::Transparent { rest })
            }
            Decoded::Incomplete => Ok(Decode::Framed { rest: input }),
        }
    }

    /// VLESS payload writes pass through unchanged after the request.
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

        // Hyphens are optional.
        assert_eq!(UserId::parse("b831381d63244d53ad4f8cda48b30811"), Ok(user));

        // Short hexadecimal text reports its length.
        assert_eq!(UserId::parse("abcdef"), Err(UserIdError::Length(6)));
        // Non-hexadecimal text reports a digit error.
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

    /// VLESS address encoding differs from SOCKS5.
    #[test]
    fn the_address_encoding_is_vmess_shaped_and_not_socks5_shaped() {
        let target = domain("example.com", 443);
        let mut vless = Vec::new();
        encode_addr_port(&target, &mut vless);

        // VLESS places the port first.
        assert_eq!(&vless[..2], &443u16.to_be_bytes());
        // VLESS uses 0x02 for domains.
        assert_eq!(vless[2], 0x02);
        assert_eq!(vless[3], 11, "the name's length octet");
        assert_eq!(&vless[4..], b"example.com");

        // The SOCKS5 encoding must remain different.
        let mut socks = Vec::new();
        crate::encode_address(&target, &mut socks);
        assert_ne!(vless, socks, "the two wire formats must not converge");

        // VLESS uses 0x03 for IPv6.
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
        // Unknown families are rejected.
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
        // The destination follows, with port first.
        assert_eq!(&request[19..21], &443u16.to_be_bytes());
        assert_eq!(request[21], ATYP_DOMAIN);
    }

    #[test]
    fn a_response_header_is_skipped_including_its_addons() {
        // No addons consume two bytes.
        assert_eq!(
            decode_response(&[VERSION, 0]),
            Ok(Decoded::Complete {
                value: (),
                consumed: 2
            })
        );
        // Addons are skipped as one block.
        assert_eq!(
            decode_response(&[VERSION, 3, 0xaa, 0xbb, 0xcc]),
            Ok(Decoded::Complete {
                value: (),
                consumed: 5
            })
        );
        // Truncated headers are incomplete.
        assert_eq!(decode_response(&[]), Ok(Decoded::Incomplete));
        assert_eq!(decode_response(&[VERSION]), Ok(Decoded::Incomplete));
        assert_eq!(
            decode_response(&[VERSION, 3, 0xaa]),
            Ok(Decoded::Incomplete)
        );
        // Unsupported versions are rejected.
        assert_eq!(decode_response(&[9, 0]), Err(ProxyError::Version(9)));
    }

    /// UDP and TCP requests differ only in the command byte.
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

    /// Frames survive arbitrary read boundaries without short delivery.
    #[tokio::test]
    async fn frames_reassemble_across_arbitrary_read_boundaries() {
        let target = Target::Ip("198.51.100.7:53".parse().unwrap());
        let payloads: [&[u8]; 3] = [b"first", b"second one", b"3"];

        // Response header followed by three framed datagrams.
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
                // Keep the reader alive while the channel drains.
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

    /// The response header is consumed once before all frames.
    #[tokio::test]
    async fn the_response_header_is_consumed_exactly_once() {
        let target = Target::Ip("198.51.100.7:53".parse().unwrap());
        // Include addons to distinguish header consumption from frame parsing.
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

    /// Cancellation ends a reader that is waiting for input.
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

    /// Payload arriving with the header is fully exposed to a small reader.
    #[tokio::test]
    async fn a_small_reader_takes_every_byte_that_arrived_with_the_header() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // Version byte, no addons, then payload bytes.
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

    /// The response header can arrive across arbitrary reads.
    #[tokio::test]
    async fn the_header_is_stripped_across_arbitrary_read_boundaries() {
        for chunk in [1usize, 2, 3, 64] {
            let (mut peer, ours) = tokio::io::duplex(4096);
            // Addons distinguish the response header from payload.
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

    /// Payload remains transparent after one response-header decode.
    #[test]
    fn the_header_is_consumed_exactly_once() {
        let mut codec = ResponseHeader::default();
        let mut out = Vec::new();

        // Decode the complete response header.
        assert_eq!(
            codec.decode(&[0u8, 2, 0xaa, 0xbb], &mut out).unwrap(),
            Decode::Transparent { rest: &[] }
        );
        // Subsequent bytes are payload.
        let payload = b"\x00\x02more";
        assert_eq!(
            codec.decode(payload, &mut out).unwrap(),
            Decode::Transparent { rest: payload },
            "bytes that merely look like a header are payload now"
        );
        assert!(out.is_empty(), "a strip produces nothing of its own");
    }

    /// Unsupported response versions are rejected.
    #[test]
    fn a_response_from_a_protocol_this_is_not_is_refused() {
        let mut codec = ResponseHeader::default();
        assert!(codec.decode(&[9u8, 0], &mut Vec::new()).is_err());
    }
}
