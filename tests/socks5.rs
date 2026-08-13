//! P17: the SOCKS5 egress driven against a real proxy.
//!
//! The codec's laws are unit-tested in `src/socks5.rs`; what needs a socket is
//! the *driver* — the greeting, the authentication sub-negotiation, the reply
//! framing, and the UDP relay's lifetime. So this file implements a minimal but
//! genuine RFC 1928 proxy and makes the egress talk to it.
//!
//! The proxy validates rather than rubber-stamps: it refuses a greeting that
//! does not offer a method it accepts, and it checks the credentials it was
//! configured with. A client that spoke the protocol incorrectly would fail
//! these tests rather than pass them by accident.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use boreas_core::{
    Credentials, DirectSockets, DomainName, NatBehavior, Socks5Config, Socks5Egress, StreamEgress,
    Target, decode_datagram, encode_datagram,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

/// What the test proxy demands of its clients.
#[derive(Clone)]
struct ProxyPolicy {
    credentials: Option<(String, String)>,
}

/// Reads the client's greeting and answers with a method, performing RFC 1929
/// authentication when this proxy requires it. Returns whether the client may
/// proceed.
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

/// Reads a request and returns its command byte and target.
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

/// Writes a reply with the given code and bound address.
async fn write_reply(stream: &mut TcpStream, code: u8, bound: SocketAddr) -> std::io::Result<()> {
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
    stream.write_all(&out).await
}

/// Runs one connection of a minimal SOCKS5 proxy.
///
/// CONNECT dials the target and splices; UDP ASSOCIATE binds a relay that
/// echoes each datagram back to its sender, framed as the protocol requires,
/// which is what proves the client's header handling in both directions.
async fn serve(mut stream: TcpStream, policy: ProxyPolicy) {
    if !negotiate(&mut stream, &policy).await.unwrap() {
        return;
    }
    let (command, target) = read_request(&mut stream).await.unwrap();
    match command {
        1 => {
            let Target::Ip(address) = target else {
                // A CONNECT to a name would need resolution; the test dials by
                // address so the proxy stays a proxy.
                write_reply(&mut stream, 4, ([0, 0, 0, 0], 0).into())
                    .await
                    .unwrap();
                return;
            };
            let mut upstream = TcpStream::connect(address).await.unwrap();
            write_reply(&mut stream, 0, address).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
        3 => {
            let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let relay_address = relay.local_addr().unwrap();
            write_reply(&mut stream, 0, relay_address).await.unwrap();

            // The relay outlives the request but not the control connection,
            // which is the lifetime RFC 1928 §7 specifies.
            let relaying = async {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (read, from) = relay.recv_from(&mut buf).await.unwrap();
                    let (destination, payload) = decode_datagram(&buf[..read]).unwrap();
                    // Echo the payload back, attributed to the destination the
                    // client addressed, so the client's decode is exercised.
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

/// Starts the proxy and returns the address it listens on.
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

/// An echo server for CONNECT to reach.
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
    let proxy = start_proxy(ProxyPolicy { credentials: None }).await;
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
        credentials: Some(("boreas".to_owned(), "secret".to_owned())),
    })
    .await;

    // The right credentials get through.
    let authenticated = egress(proxy, Some(Credentials::new("boreas", "secret").unwrap()));
    let mut stream = authenticated
        .connect(&Target::Ip(echo))
        .await
        .expect("authenticated connect succeeds");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    // The wrong ones do not, and the failure is named rather than a timeout.
    let wrong = egress(proxy, Some(Credentials::new("boreas", "wrong").unwrap()));
    let Err(error) = wrong.connect(&Target::Ip(echo)).await else {
        panic!("bad credentials must be refused");
    };
    assert!(
        format!("{error}").contains("authentication"),
        "the refusal names itself: {error}"
    );

    // Offering no credentials at all to a proxy that demands them ends in the
    // proxy's own "no acceptable method", not in a hang.
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
    let proxy = start_proxy(ProxyPolicy { credentials: None }).await;
    let egress = Arc::new(egress(proxy, None));

    let association = egress.associate().await.expect("the relay is established");
    let target = Target::Domain {
        host: DomainName::new("example.com").unwrap(),
        port: 53,
    };

    // A datagram crosses with its destination in the header, and comes back
    // attributed to that same destination: the framing works in both
    // directions, which is the whole of RFC 1928 §7 that a client performs.
    association
        .send_to(b"\x12\x34query", &target)
        .await
        .expect("the datagram is relayed");

    let mut buf = [0u8; 64];
    let (read, from) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        association.recv_from(&mut buf),
    )
    .await
    .expect("the relay answers")
    .expect("the reply decodes");
    assert_eq!(&buf[..read], b"\x12\x34query");
    assert_eq!(from, target, "the reply names the peer it came from");
}
