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
    DirectSockets, Method, NatBehavior, PreSharedKey, ShadowsocksConfig, ShadowsocksEgress,
    Socks5Config, Socks5Egress, StreamEgress, Target,
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
