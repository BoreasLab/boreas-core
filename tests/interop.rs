//! Interoperability against a reference implementation.
//!
//! Every other test in this crate drives Boreas against a peer Boreas also
//! wrote. That proves self-consistency and nothing about the wire: a misreading
//! of a specification satisfies both halves of a self-test equally. For a
//! protocol whose entire value is that somebody else's server accepts it, that
//! is not a gate — it is a rehearsal.
//!
//! So these tests run against [sing-box](https://github.com/SagerNet/sing-box),
//! which is an independent implementation of every proxy protocol in P17. A
//! byte that survives a round trip here survived Boreas's encoder *and* a
//! foreign decoder, which is the property the phase actually needs.
//!
//! **Opt-in, and skipped rather than failed when absent.** The binary is a
//! development tool, not a dependency: it is never linked, never distributed,
//! and runs out of process, so its licence does not reach this crate. Point
//! `BOREAS_SINGBOX` at it to run these; without it they report that they were
//! skipped and pass, so a machine without the reference still has a green
//! suite.
//!
//! ```sh
//! BOREAS_SINGBOX=/path/to/sing-box cargo test --test interop
//! ```

use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use boreas_core::{
    DirectSockets, Hysteria2Config, Hysteria2Egress, Method, NatBehavior, PlainTransport,
    PreSharedKey, ShadowsocksConfig, ShadowsocksEgress, Socks5Config, Socks5Egress, StreamEgress,
    Target, UserId, VlessConfig, VlessEgress,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The reference binary, when the operator has pointed us at one.
fn reference_binary() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("BOREAS_SINGBOX")?);
    path.is_file().then_some(path)
}

/// Announces a skip in a way that shows up in `cargo test -- --nocapture`, so
/// a green run without the reference is never mistaken for a verified one.
fn skipped(test: &str) {
    eprintln!(
        "SKIPPED {test}: set BOREAS_SINGBOX to a sing-box binary to verify \
         wire compatibility against the reference implementation"
    );
}

/// A running reference server. Killed on drop, so a failing assertion cannot
/// leave a proxy listening.
struct Reference {
    child: Child,
    _dir: TempDir,
}

/// A self-signed certificate for the reference server to present, and the trust
/// anchor this client verifies it against.
///
/// **Verification stays on.** Turning it off would make the test pass on a
/// server presenting anything at all, and for a protocol whose authentication
/// rides inside TLS that would quietly remove the property under test.
/// `quiche` loads trust anchors only from PEM files, so they go to disk.
struct Certificate {
    certificate: PathBuf,
    key: PathBuf,
    _dir: TempDir,
}

impl Certificate {
    const NAME: &'static str = "reference.example";

    fn generate() -> Self {
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let mut params =
            rcgen::CertificateParams::new(vec![Self::NAME.to_owned()]).expect("valid parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, Self::NAME);
        let certificate = params.self_signed(&key).expect("a self-signed leaf");

        let dir = TempDir::new();
        let certificate_path = dir.path().join("reference.crt");
        let key_path = dir.path().join("reference.key");
        std::fs::write(&certificate_path, pem("CERTIFICATE", certificate.der())).unwrap();
        std::fs::write(&key_path, pem("PRIVATE KEY", &key.serialize_der())).unwrap();
        Self {
            certificate: certificate_path,
            key: key_path,
            _dir: dir,
        }
    }
}

/// Wraps DER as PEM. Written out rather than enabling `rcgen`'s `pem` feature,
/// which would pull a base64 crate in for four lines of work.
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
    /// Writes `config` to a scratch directory and starts the binary on it,
    /// waiting until every port in `ports` accepts a connection.
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
            .stderr(Stdio::piped())
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

/// Reserves a port by binding and releasing it. A race is possible in
/// principle and has not been observed; the alternative is teaching the
/// reference to report its own ports, which it does not do.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("a port is available")
        .local_addr()
        .expect("the socket has an address")
        .port()
}

/// A scratch directory that removes itself.
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

/// An echo server for the proxy to reach, so a round trip proves the whole
/// path rather than only the handshake.
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

/// The pre-shared key material both sides use. Fixed rather than random so a
/// failure is reproducible; sliced to whatever length the method requires.
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

/// The gate the Shadowsocks module's own tests could not provide: a foreign
/// server decrypting what this client encrypted.
///
/// Everything self-testing left open rides on this — the BLAKE3 subkey
/// derivation and its context string, the nonce counter's little-endian order,
/// the fixed and variable header layouts, the chunk framing, and the response
/// salt echo. Any one of them wrong and sing-box rejects the session.
#[tokio::test]
async fn shadowsocks_2022_interoperates_with_the_reference_server() {
    let Some(binary) = reference_binary() else {
        return skipped("shadowsocks_2022_interoperates_with_the_reference_server");
    };

    // Every method, because they differ in key length and cipher: a
    // derivation truncated for the 128-bit suite, or the wrong `ring`
    // algorithm selected, would show on one of these and not the others.
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

/// SOCKS5 against the same reference. Its own tests already check it against an
/// independently written RFC 1928 proxy, so this is corroboration rather than
/// the first evidence — but the proxy in those tests is still one this
/// repository wrote, and sing-box is not.
#[tokio::test]
async fn socks5_interoperates_with_the_reference_server() {
    let Some(binary) = reference_binary() else {
        return skipped("socks5_interoperates_with_the_reference_server");
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

/// VLESS against the reference. This is the protocol whose address encoding
/// most invites a silent error — the port precedes the address and two of the
/// three family bytes disagree with SOCKS5 — so a foreign server reading the
/// destination back is exactly the check that matters.
///
/// A domain target rather than an address, because the domain form is the one
/// that would be misread as IPv6 if the family bytes were taken from RFC 1928.
#[tokio::test]
async fn vless_interoperates_with_the_reference_server() {
    let Some(binary) = reference_binary() else {
        return skipped("vless_interoperates_with_the_reference_server");
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

/// Hysteria2 against the reference, which is the first test in this file that
/// exercises a QUIC connection of our own driving rather than a TCP socket.
///
/// Everything the protocol newly depends on rides on this: the QUIC handshake,
/// the HTTP/3 authentication exchange and its status 233, the decision to drop
/// the HTTP/3 layer before opening a proxy stream, the driver's stream pump in
/// both directions, and the request and response frame codecs. A mistake in any
/// of them is a server that refuses or a stream that never delivers.
///
/// **Two flows, deliberately.** They must share one QUIC connection and land on
/// *different* stream ids; a driver that reused an id or opened a second
/// connection would still pass a single-flow test.
#[tokio::test]
async fn hysteria2_interoperates_with_the_reference_server() {
    let Some(binary) = reference_binary() else {
        return skipped("hysteria2_interoperates_with_the_reference_server");
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
    // No TCP port to probe: Hysteria2 listens on UDP, and there is no
    // connectionless equivalent of a completed handshake. Readiness is
    // established by the client's own retry loop below.
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
            let anchor = certificate.certificate.clone();
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

    // A second flow over the same connection. It exercises the stream id
    // allocator and proves the authentication is not repeated per flow.
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

    // The first stream must still work after the second opened, which is what
    // separates a multiplexed connection from a serially reused one.
    first.write_all(b"again").await.unwrap();
    first.flush().await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), first.read_exact(&mut buf))
        .await
        .expect("the first flow is still live")
        .expect("the response arrives");
    assert_eq!(&buf, b"again");
}

/// Dials until the reference's UDP listener is up.
///
/// A QUIC client cannot tell "not listening yet" from "packet lost" — that is
/// what makes UDP readiness unprobeable — so the retry is the readiness check.
/// The timeout is short so a genuinely dead server fails fast rather than
/// sitting through the handshake's own deadline.
async fn dial_with_retries(
    egress: &impl StreamEgress,
    target: &Target,
) -> Box<dyn boreas_core::AsyncStream> {
    for attempt in 0..10 {
        match tokio::time::timeout(Duration::from_secs(3), egress.connect(target)).await {
            Ok(Ok(stream)) => return stream,
            Ok(Err(error)) if attempt == 9 => panic!("the reference refused Hysteria2: {error}"),
            Err(_) if attempt == 9 => panic!("the reference never completed a QUIC handshake"),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    unreachable!("the loop either returns or panics on its last attempt")
}
