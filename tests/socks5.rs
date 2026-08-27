//! P17 SOCKS5 egress against a real proxy.
//!
//! Unit tests cover codec laws. This file exercises the socket driver: RFC 1928
//! greeting, RFC 1929 authentication, reply framing, and UDP relay lifetime.
//!
//! The proxy rejects unsupported methods and invalid credentials, so protocol
//! errors fail the tests instead of passing by accident.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use boreas_core::{
    Credentials, DirectSockets, DomainName, EgressError, NatBehavior, Socks5Config, Socks5Egress,
    StreamEgress, Target, decode_datagram, encode_datagram,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

#[derive(Clone)]
struct ProxyPolicy {
    credentials: Option<(String, String)>,
    /// Bytes sent with the CONNECT reply to test surplus preservation. A
    /// server-first protocol may send its banner in the same write.
    banner: &'static [u8],
}

impl ProxyPolicy {
    fn open() -> Self {
        Self {
            credentials: None,
            banner: b"",
        }
    }
}

/// Negotiates the greeting and optional RFC 1929 authentication.
async fn negotiate(stream: &mut TcpStream, policy: &ProxyPolicy) -> std::io::Result<bool> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    assert_eq!(head[0], 5, "the client must speak SOCKS5");
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;

    let required = if policy.credentials.is_some() {
        0x02
    } else {
        0x00
    };
    if !methods.contains(&required) {
        stream.write_all(&[5, 0xff]).await?;
        return Ok(false);
    }
    stream.write_all(&[5, required]).await?;

    let Some((username, password)) = policy.credentials.as_ref() else {
        return Ok(true);
    };

    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;
    assert_eq!(version[0], 1, "sub-negotiation carries its own version");
    let mut user = vec![0u8; usize::from(version[1])];
    stream.read_exact(&mut user).await?;
    let mut password_len = [0u8; 1];
    stream.read_exact(&mut password_len).await?;
    let mut pass = vec![0u8; usize::from(password_len[0])];
    stream.read_exact(&mut pass).await?;

    let ok = user == username.as_bytes() && pass == password.as_bytes();
    stream.write_all(&[1, u8::from(!ok)]).await?;
    Ok(ok)
}

/// Parses a request into its command and target.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<(u8, Target)> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    assert_eq!(head[0], 5);
    let target = match head[3] {
        1 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Target::Ip(SocketAddr::from((ip, port)))
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Target::Domain {
                host: DomainName::new(String::from_utf8(name).unwrap()).unwrap(),
                port: u16::from_be_bytes(port),
            }
        }
        other => panic!("the client sent an address type the test does not use: {other}"),
    };
    Ok((head[1], target))
}

/// Encodes a reply with a bound address and trailing bytes.
async fn write_reply(
    stream: &mut TcpStream,
    code: u8,
    bound: SocketAddr,
    trailer: &[u8],
) -> std::io::Result<()> {
    let mut out = vec![5, code, 0];
    match bound {
        SocketAddr::V4(address) => {
            out.push(1);
            out.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            out.push(4);
            out.extend_from_slice(&address.ip().octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    out.extend_from_slice(trailer);
    stream.write_all(&out).await
}

/// Runs one connection of a minimal SOCKS5 proxy.
///
/// CONNECT dials an IP target and splices. UDP ASSOCIATE binds a relay that
/// echoes each datagram with its protocol header.
async fn serve(mut stream: TcpStream, policy: ProxyPolicy) {
    if !negotiate(&mut stream, &policy).await.unwrap() {
        return;
    }
    let (command, target) = read_request(&mut stream).await.unwrap();
    match command {
        1 => {
            let Target::Ip(address) = target else {
                // The test dials by address so the proxy does not resolve names.
                write_reply(&mut stream, 4, ([0, 0, 0, 0], 0).into(), b"")
                    .await
                    .unwrap();
                return;
            };
            let mut upstream = TcpStream::connect(address).await.unwrap();
            write_reply(&mut stream, 0, address, policy.banner)
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
        3 => {
            let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let relay_address = relay.local_addr().unwrap();
            write_reply(&mut stream, 0, relay_address, b"")
                .await
                .unwrap();

            // RFC 1928 §7 ties the relay lifetime to the control connection.
            let relaying = async {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (read, from) = relay.recv_from(&mut buf).await.unwrap();
                    let (destination, payload) = decode_datagram(&buf[..read]).unwrap();
                    // Preserve the destination so the client's decoder sees it.
                    let mut framed = Vec::new();
                    encode_datagram(&destination, payload, &mut framed);
                    relay.send_to(&framed, from).await.unwrap();
                }
            };
            let closed = async {
                let mut sink = [0u8; 1];
                let _ = stream.read(&mut sink).await;
            };
            tokio::select! {
                () = relaying => {}
                () = closed => {}
            }
        }
        other => panic!("unexpected command {other}"),
    }
}

async fn start_proxy(policy: ProxyPolicy) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(stream, policy.clone()));
        }
    });
    address
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok(read) = stream.read(&mut buf).await {
                    if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

fn egress(proxy: SocketAddr, credentials: Option<Credentials>) -> Socks5Egress<DirectSockets> {
    Socks5Egress::new(
        Socks5Config {
            proxy,
            credentials,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        DirectSockets,
    )
}

#[tokio::test]
async fn connect_reaches_the_target_and_carries_bytes_both_ways() {
    let echo = start_echo().await;
    let proxy = start_proxy(ProxyPolicy::open()).await;
    let egress = egress(proxy, None);

    let target = Target::Ip(echo);
    let mut stream = egress.connect(&target).await.expect("the proxy connects");
    stream.write_all(b"through the proxy").await.unwrap();
    let mut buf = [0u8; 17];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through the proxy");
}

#[tokio::test]
async fn authentication_is_performed_when_the_proxy_requires_it() {
    let echo = start_echo().await;
    let proxy = start_proxy(ProxyPolicy {
        banner: b"",
        credentials: Some(("boreas".to_owned(), "secret".to_owned())),
    })
    .await;

    let authenticated = egress(proxy, Some(Credentials::new("boreas", "secret").unwrap()));
    let mut stream = authenticated
        .connect(&Target::Ip(echo))
        .await
        .expect("authenticated connect succeeds");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    // Invalid credentials fail during authentication rather than timing out.
    let wrong = egress(proxy, Some(Credentials::new("boreas", "wrong").unwrap()));
    let Err(error) = wrong.connect(&Target::Ip(echo)).await else {
        panic!("bad credentials must be refused");
    };
    assert!(
        format!("{error}").contains("authentication"),
        "the refusal names itself: {error}"
    );

    // Omitting credentials returns the proxy's "no acceptable method" reply.
    let anonymous = egress(proxy, None);
    let Err(error) = anonymous.connect(&Target::Ip(echo)).await else {
        panic!("an unauthenticated client must be refused");
    };
    assert!(
        format!("{error}").contains("no acceptable authentication method"),
        "the refusal names itself: {error}"
    );
}

#[tokio::test]
async fn udp_associate_relays_datagrams_with_their_targets() {
    let proxy = start_proxy(ProxyPolicy::open()).await;
    let egress = Arc::new(egress(proxy, None));

    let mut association = egress.associate().await.expect("the relay is established");
    let target = Target::Domain {
        host: DomainName::new("example.com").unwrap(),
        port: 53,
    };

    // RFC 1928 §7 framing preserves the destination in both directions.
    association
        .sink
        .send_to(b"\x12\x34query", &target)
        .await
        .expect("the datagram is relayed");

    let mut buf = [0u8; 64];
    let (read, from) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        association.source.recv_from(&mut buf),
    )
    .await
    .expect("the relay answers")
    .expect("the reply decodes");
    assert_eq!(&buf[..read], b"\x12\x34query");
    assert_eq!(from, target, "the reply names the peer it came from");

    // Native datagram fidelity preserves boundaries or rejects the datagram;
    // truncating a QUIC packet would corrupt the connection.
    association
        .sink
        .send_to(&[0xab; 200], &target)
        .await
        .expect("the datagram is relayed");
    let mut small = [0u8; 64];
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        association.source.recv_from(&mut small),
    )
    .await
    .expect("the relay answers");
    assert!(
        matches!(
            refused,
            Err(EgressError::DatagramTooLarge { required: 200 })
        ),
        "an oversized datagram must be refused, not truncated: {refused:?}"
    );
}

/// Regression test for a reply reader that over-reads.
///
/// A SOCKS5 reply has an internal length and may be followed in the same write
/// by a server-first banner. Discarding bytes beyond the reply loses that
/// banner without an error.
///
/// The proxy coalesces the reply and banner in one `write_all`.
#[tokio::test]
async fn a_banner_coalesced_with_the_reply_is_not_swallowed() {
    const BANNER: &[u8] = b"SSH-2.0-Boreas\r\n";

    let echo = start_echo().await;
    let proxy = start_proxy(ProxyPolicy {
        credentials: None,
        banner: BANNER,
    })
    .await;

    let mut stream = egress(proxy, None)
        .connect(&Target::Ip(echo))
        .await
        .expect("connect succeeds");

    // Bound this read because swallowing the banner would otherwise hang.
    let mut greeting = vec![0u8; BANNER.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut greeting),
    )
    .await
    .expect("the banner arrives rather than being waited for forever")
    .expect("the banner survives the reply reader");
    assert_eq!(
        greeting, BANNER,
        "the bytes that followed the reply must be delivered, not discarded"
    );

    // Replayed surplus must not displace later socket bytes.
    stream.write_all(b"after").await.unwrap();
    let mut echoed = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut echoed),
    )
    .await
    .expect("the stream still carries bytes after the replayed prefix")
    .unwrap();
    assert_eq!(&echoed, b"after");
}
