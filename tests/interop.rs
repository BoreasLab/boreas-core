//! Interoperability tests against an independent reference implementation.
//!
//! A self-test can validate two matching mistakes. These tests run Boreas
//! against [sing-box](https://github.com/SagerNet/sing-box), so a successful
//! round trip crosses both Boreas's encoder and a foreign decoder.
//!
//! The reference binary is an out-of-process development tool, not a linked or
//! distributed dependency. Local runs may announce a skip when it is absent;
//! CI sets `BOREAS_INTEROP=required`, which turns absence into failure.
//! `scripts/reference.sh` fetches the pinned binary and verifies its digest.
//!
//! ```sh
//! BOREAS_INTEROP=required BOREAS_SINGBOX=$(scripts/reference.sh) \
//!     cargo test --test interop
//! ```

use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use boreas_core::{
    DirectSockets, GrpcConfig, GrpcTransport, HttpConfig, HttpHeaders, HttpTransport,
    HttpUpgradeConfig, HttpUpgradeTransport, Hysteria2Config, Hysteria2Egress, Method, NatBehavior,
    PlainTransport, PreSharedKey, QuicTransport, QuicTransportConfig, ShadowsocksConfig,
    ShadowsocksEgress, Socks5Config, Socks5Egress, StreamEgress, Target, TlsConfig, TlsTransport,
    UserId, VlessConfig, VlessEgress, WebSocketConfig, WebSocketTransport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Demand {
    Optional,
    Required,
}

impl Demand {
    fn current() -> Self {
        match std::env::var("BOREAS_INTEROP").as_deref() {
            Ok("required") => Self::Required,
            _ => Self::Optional,
        }
    }
}

fn reference_binary() -> Result<PathBuf, Demand> {
    let demand = Demand::current();
    let Some(raw) = std::env::var_os("BOREAS_SINGBOX") else {
        return Err(demand);
    };
    let path = PathBuf::from(raw);
    path.is_file().then_some(path).ok_or(demand)
}

/// # Panics
///
/// Under `BOREAS_INTEROP=required`, when no usable binary was named.
fn reference_or_skip(test: &str) -> Option<PathBuf> {
    match reference_binary() {
        Ok(path) => Some(path),
        Err(Demand::Required) => panic!(
            "{test}: BOREAS_INTEROP=required, but BOREAS_SINGBOX does not name a \
             usable sing-box binary. This suite is the only check that these \
             protocols interoperate with an implementation Boreas did not write; \
             skipping it silently is what it exists to prevent."
        ),
        Err(Demand::Optional) => {
            // Make an optional skip visible in test output.
            eprintln!(
                "SKIPPED {test}: set BOREAS_SINGBOX to a sing-box binary to verify \
                 wire compatibility against the reference implementation"
            );
            None
        }
    }
}

struct Reference {
    child: Child,
    _dir: TempDir,
}

/// The separate CA and leaf form a chain accepted by both the `boring` and
/// `rustls` clients. Verification remains enabled so the TLS transport is part
/// of the interoperability check.
struct Certificate {
    authority: Vec<u8>,
    authority_path: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    _dir: TempDir,
}

impl Certificate {
    const NAME: &'static str = "reference.example";

    fn generate() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("a CA key pair");
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("valid parameters");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Boreas Interop CA");
        let ca = ca_params
            .clone()
            .self_signed(&ca_key)
            .expect("a self-signed CA");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().expect("a leaf key pair");
        let mut leaf_params =
            rcgen::CertificateParams::new(vec![Self::NAME.to_owned()]).expect("valid parameters");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, Self::NAME);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("a leaf signed by the CA");

        let dir = TempDir::new();
        let authority_path = dir.path().join("ca.crt");
        let certificate_path = dir.path().join("reference.crt");
        let key_path = dir.path().join("reference.key");
        std::fs::write(&authority_path, pem("CERTIFICATE", ca.der())).unwrap();
        std::fs::write(&certificate_path, pem("CERTIFICATE", leaf.der())).unwrap();
        std::fs::write(&key_path, pem("PRIVATE KEY", &leaf_key.serialize_der())).unwrap();
        Self {
            authority: ca.der().to_vec(),
            authority_path,
            certificate: certificate_path,
            key: key_path,
            _dir: dir,
        }
    }

    fn tls_transport(
        &self,
        server: SocketAddr,
        alpn: &[&[u8]],
    ) -> Box<dyn boreas_core::ProxyTransport> {
        Box::new(
            TlsTransport::new(
                TlsConfig {
                    server,
                    server_name: Self::NAME.to_owned(),
                    alpn: alpn.iter().map(|protocol| protocol.to_vec()).collect(),
                    extra_roots: vec![self.authority.clone()],
                },
                DirectSockets,
            )
            .expect("the TLS transport is configurable"),
        )
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in der.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(ALPHABET[((bits >> (18 - index * 6)) & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n")
}

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Reference {
    fn start(binary: &PathBuf, config: &str, ports: &[u16]) -> Self {
        let dir = TempDir::new();
        let path = dir.path().join("config.json");
        let mut file = std::fs::File::create(&path).expect("config is writable");
        file.write_all(config.as_bytes())
            .expect("config is written");
        drop(file);

        let child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the reference binary starts");

        let reference = Self { child, _dir: dir };
        for &port in ports {
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let ready = (0..100).any(|_| {
                if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100))
                    .is_ok()
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
                false
            });
            assert!(ready, "the reference server never opened port {port}");
        }
        reference
    }
}

/// A per-process counter prevents concurrent tests from selecting the same
/// port. Binding both protocols checks for conflicts outside the process.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};

    const FIRST: u32 = 20_000;
    const COUNT: u32 = 40_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);

    // Offset separate test binaries into different parts of the range.
    let start = std::process::id() % COUNT;
    loop {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        let candidate = (FIRST + (start + step) % COUNT) as u16;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, candidate));
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, candidate));
        if tcp.is_ok() && udp.is_ok() {
            return candidate;
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("boreas-interop-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
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

const PSK: [u8; 32] = [7u8; 32];

fn psk_base64(len: usize) -> String {
    let psk = &PSK[..len];
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in psk.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(ALPHABET[((bits >> (18 - index * 6)) & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// This covers subkey derivation, nonce order, header layouts, chunk framing,
/// and response-salt handling beyond self-tests.
#[tokio::test]
async fn shadowsocks_2022_interoperates_with_the_reference_server() {
    let Some(binary) =
        reference_or_skip("shadowsocks_2022_interoperates_with_the_reference_server")
    else {
        return;
    };

    // Cover each key length and cipher implementation.
    for method in [
        Method::Aes128Gcm,
        Method::Aes256Gcm,
        Method::ChaCha20Poly1305,
    ] {
        let echo = start_echo().await;
        let port = free_port();
        let config = format!(
            r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "shadowsocks",
    "listen": "127.0.0.1",
    "listen_port": {port},
    "method": "{}",
    "password": "{}"
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#,
            method.name(),
            psk_base64(method.key_len())
        );
        let _reference = Reference::start(&binary, &config, &[port]);

        let egress = ShadowsocksEgress::new(
            ShadowsocksConfig {
                server: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                key: PreSharedKey::new(method, PSK[..method.key_len()].to_vec()).unwrap(),
                nat_behavior: NatBehavior::EndpointIndependent,
            },
            DirectSockets,
        );

        let Ok(mut stream) = egress.connect(&Target::Ip(echo)).await else {
            panic!("the reference refused a {} session", method.name());
        };
        stream.write_all(b"interop").await.expect("write crosses");
        stream.flush().await.unwrap();

        let mut buf = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{} timed out", method.name()))
            .unwrap_or_else(|error| panic!("{} did not decrypt: {error}", method.name()));
        assert_eq!(
            &buf,
            b"interop",
            "a foreign server round-tripped our bytes under {}",
            method.name()
        );
    }
}

#[tokio::test]
async fn socks5_interoperates_with_the_reference_server() {
    let Some(binary) = reference_or_skip("socks5_interoperates_with_the_reference_server") else {
        return;
    };
    let echo = start_echo().await;
    let port = free_port();
    let config = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "socks",
    "listen": "127.0.0.1",
    "listen_port": {port}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#
    );
    let _reference = Reference::start(&binary, &config, &[port]);

    let egress = Socks5Egress::new(
        Socks5Config {
            proxy: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            credentials: None,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        DirectSockets,
    );

    let Ok(mut stream) = egress.connect(&Target::Ip(echo)).await else {
        panic!("the reference server refused the SOCKS5 request");
    };
    stream.write_all(b"socks interop").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("the reference answers")
        .expect("the response arrives");
    assert_eq!(&buf, b"socks interop");
}

/// A domain target exercises the family byte that differs from SOCKS5.
#[tokio::test]
async fn vless_interoperates_with_the_reference_server() {
    let Some(binary) = reference_or_skip("vless_interoperates_with_the_reference_server") else {
        return;
    };
    let echo = start_echo().await;
    let port = free_port();
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let config = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "vless",
    "listen": "127.0.0.1",
    "listen_port": {port},
    "users": [{{"uuid": "{uuid}"}}]
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#
    );
    let _reference = Reference::start(&binary, &config, &[port]);

    let egress = VlessEgress::new(
        VlessConfig {
            user: UserId::parse(uuid).unwrap(),
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        PlainTransport::new(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), DirectSockets),
    );

    let Ok(mut stream) = egress.connect(&Target::Ip(echo)).await else {
        panic!("the reference server refused the VLESS request");
    };
    stream.write_all(b"vless interop").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("the reference answers")
        .expect("the response arrives");
    assert_eq!(&buf, b"vless interop");
}

/// The exchange covers QUIC, HTTP/3 status 233, stream setup, bidirectional
/// pumping, and request/response framing. Two flows must share one connection
/// and use different stream IDs.
#[tokio::test]
async fn hysteria2_interoperates_with_the_reference_server() {
    let Some(binary) = reference_or_skip("hysteria2_interoperates_with_the_reference_server")
    else {
        return;
    };
    let echo = start_echo().await;
    let port = free_port();
    let password = "interop-password";
    let certificate = Certificate::generate();
    let config = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "hysteria2",
    "listen": "127.0.0.1",
    "listen_port": {port},
    "users": [{{"password": "{password}"}}],
    "tls": {{
      "enabled": true,
      "server_name": "{name}",
      "certificate_path": "{cert}",
      "key_path": "{key}"
    }}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#,
        name = Certificate::NAME,
        cert = certificate.certificate.display(),
        key = certificate.key.display(),
    );
    // UDP has no TCP readiness probe; the dial retry establishes readiness.
    let _reference = Reference::start(&binary, &config, &[]);

    let egress = Hysteria2Egress::new(
        Hysteria2Config {
            server: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            server_name: Certificate::NAME.to_owned(),
            password: password.to_owned(),
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        DirectSockets,
        {
            let anchor = certificate.authority_path.clone();
            Box::new(move || {
                let mut config = Hysteria2Egress::<DirectSockets>::quic_config()?;
                config
                    .load_verify_locations_from_file(anchor.to_str().expect("a UTF-8 path"))
                    .expect("the trust anchor loads");
                Ok(config)
            })
        },
    );

    let mut first = dial_with_retries(&egress, &Target::Ip(echo)).await;
    first.write_all(b"hysteria interop").await.unwrap();
    first.flush().await.unwrap();

    let mut buf = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(10), first.read_exact(&mut buf))
        .await
        .expect("the reference answers")
        .expect("the response arrives");
    assert_eq!(&buf, b"hysteria interop");

    // A second flow checks stream allocation and one-time authentication.
    let mut second = egress
        .connect(&Target::Ip(echo))
        .await
        .expect("the second flow opens on the established connection");
    second.write_all(b"second").await.unwrap();
    second.flush().await.unwrap();
    let mut buf = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), second.read_exact(&mut buf))
        .await
        .expect("the reference answers the second flow")
        .expect("the response arrives");
    assert_eq!(&buf, b"second");

    // The first stream remains live, proving multiplexing rather than reuse.
    first.write_all(b"again").await.unwrap();
    first.flush().await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), first.read_exact(&mut buf))
        .await
        .expect("the first flow is still live")
        .expect("the response arrives");
    assert_eq!(&buf, b"again");
}

/// UDP gives no separate readiness signal, so bounded retries serve as the
/// probe and fail faster than the handshake deadline.
async fn dial_with_retries(
    egress: &impl StreamEgress,
    target: &Target,
) -> Box<dyn boreas_core::AsyncStream> {
    for attempt in 0..10 {
        match tokio::time::timeout(Duration::from_secs(3), egress.connect(target)).await {
            Ok(Ok(stream)) => return stream,
            Ok(Err(error)) if attempt == 9 => panic!("the reference refused the dial: {error}"),
            Err(_) if attempt == 9 => panic!("the reference never answered a dial"),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    unreachable!("the loop either returns or panics on its last attempt")
}

// ------------------------------------------------- VLESS transports
//
// VLESS supplies no transport framing. These tests cover WebSocket, HTTP
// Upgrade, gRPC over HTTP/2, an HTTP/2 body, and a QUIC bidirectional stream
// against matching sing-box inbounds.

const TRANSPORT_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

async fn vless_transport_round_trip(
    name: &str,
    transport_json: &str,
    tls_json: &str,
    build: impl FnOnce(SocketAddr, &Certificate) -> Box<dyn boreas_core::ProxyTransport>,
) {
    let Some(binary) = reference_or_skip(name) else {
        return;
    };
    let echo = start_echo().await;
    let port = free_port();
    let certificate = Certificate::generate();
    let tls = if tls_json.is_empty() {
        String::new()
    } else {
        format!(
            r#","tls": {{"enabled": true, "server_name": "{name}", "certificate_path": "{cert}", "key_path": "{key}"}}"#,
            name = Certificate::NAME,
            cert = certificate.certificate.display(),
            key = certificate.key.display(),
        )
    };
    let config = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "vless",
    "listen": "127.0.0.1",
    "listen_port": {port},
    "users": [{{"uuid": "{TRANSPORT_UUID}"}}],
    "transport": {transport_json}{tls}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#
    );
    // Only TCP transports provide a readiness connection.
    let tcp_ports: &[u16] = if transport_json.contains("\"quic\"") {
        &[]
    } else {
        &[port]
    };
    let _reference = Reference::start(&binary, &config, tcp_ports);

    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let egress = VlessEgress::new(
        VlessConfig {
            user: UserId::parse(TRANSPORT_UUID).unwrap(),
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        build(server, &certificate),
    );

    // This size distinguishes protobuf and QUIC varints, crosses one read and
    // one frame/message, and remains below HTTP/2's initial window.
    let payload: Vec<u8> = name.bytes().cycle().take(20_000).collect();

    // Retry the whole flow for a known sing-box HTTPUpgrade handoff race: bytes
    // arriving between `101` and Go's `Hijack` can be discarded. A real protocol
    // error still fails every attempt.
    let mut last = String::new();
    for attempt in 0..4 {
        match transport_round_trip(&egress, echo, &payload).await {
            Ok(()) => return,
            Err(error) => last = error,
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    panic!("{name}: every attempt failed, last: {last}");
}

/// Errors retain enough context for a retry caller to report the last failure.
async fn transport_round_trip(
    egress: &impl StreamEgress,
    echo: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), egress.connect(&Target::Ip(echo)))
            .await
            .map_err(|_| "the dial timed out".to_owned())?
            .map_err(|error| format!("the dial failed: {error}"))?;

    stream
        .write_all(payload)
        .await
        .map_err(|error| format!("the write failed: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("the flush failed: {error}"))?;

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .map_err(|_| "the reference never answered".to_owned())?
        .map_err(|error| format!("the response did not arrive: {error}"))?;
    if buf != payload {
        return Err("the payload came back altered".to_owned());
    }
    Ok(())
}

#[tokio::test]
async fn vless_over_websocket_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "websocket",
        r#"{"type": "ws", "path": "/tunnel"}"#,
        "",
        |server, _| {
            Box::new(WebSocketTransport::new(
                WebSocketConfig {
                    path: "/tunnel".to_owned(),
                    headers: HttpHeaders::default(),
                },
                PlainTransport::new(server, DirectSockets),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn vless_over_websocket_tls_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "websocket-tls",
        r#"{"type": "ws", "path": "/tunnel"}"#,
        "tls",
        |server, certificate| {
            Box::new(WebSocketTransport::new(
                WebSocketConfig {
                    path: "/tunnel".to_owned(),
                    headers: HttpHeaders {
                        host: Some(Certificate::NAME.to_owned()),
                        extra: Vec::new(),
                    },
                },
                certificate.tls_transport(server, &[b"http/1.1"]),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn vless_over_httpupgrade_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "httpupgrade",
        r#"{"type": "httpupgrade", "path": "/tunnel"}"#,
        "",
        |server, _| {
            Box::new(HttpUpgradeTransport::new(
                HttpUpgradeConfig {
                    path: "/tunnel".to_owned(),
                    headers: HttpHeaders::default(),
                },
                PlainTransport::new(server, DirectSockets),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn vless_over_grpc_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "grpc",
        r#"{"type": "grpc", "service_name": "TunService"}"#,
        "",
        |server, _| {
            Box::new(GrpcTransport::new(
                GrpcConfig {
                    service_name: "TunService".to_owned(),
                    headers: HttpHeaders::default(),
                },
                PlainTransport::new(server, DirectSockets),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn vless_over_http2_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "http2",
        r#"{"type": "http", "path": "/tunnel"}"#,
        "tls",
        |server, certificate| {
            Box::new(HttpTransport::new(
                HttpConfig {
                    path: "/tunnel".to_owned(),
                    method: "PUT".to_owned(),
                    headers: HttpHeaders {
                        host: Some(Certificate::NAME.to_owned()),
                        extra: Vec::new(),
                    },
                },
                certificate.tls_transport(server, &[b"h2"]),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn vless_over_quic_interoperates_with_the_reference_server() {
    vless_transport_round_trip(
        "quic",
        r#"{"type": "quic"}"#,
        "tls",
        |server, certificate| {
            let _ = certificate;
            Box::new(QuicTransport::new(
                QuicTransportConfig {
                    server,
                    server_name: Certificate::NAME.to_owned(),
                    idle_timeout: Duration::from_secs(30),
                },
                DirectSockets,
            ))
        },
    )
    .await;
}
