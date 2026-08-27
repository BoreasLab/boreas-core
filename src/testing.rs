//! Helpers shared only by this crate's tests.
//!
//! They are test-only because the QUIC fixtures need PEM credentials on disk.
//! The helpers provide one certificate generator, DER-to-PEM encoding, and a
//! scratch directory with cleanup on drop.

use std::path::{Path, PathBuf};

/// Creates a self-signed certificate and key for `name` in a temporary folder.
///
/// The returned directory owns both files and removes them on drop.
pub fn self_signed(name: &str) -> (PathBuf, PathBuf, TempDir) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let certificate = params.self_signed(&key).unwrap();

    let dir = TempDir::new();
    let cert_path = dir.path().join("peer.crt");
    let key_path = dir.path().join("peer.key");
    std::fs::write(&cert_path, pem("CERTIFICATE", certificate.der())).unwrap();
    std::fs::write(&key_path, pem("PRIVATE KEY", &key.serialize_der())).unwrap();
    (cert_path, key_path, dir)
}

/// Encodes DER as PEM for `quiche`, while `rcgen` supplies DER here.
///
/// The encoder stays local instead of enabling `rcgen`'s `pem` feature, which
/// would add a base64 implementation to the artifact for a test-only need.
pub fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in der.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                encoded.push(ALPHABET[((bits >> shift) & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n")
}

/// Temporary directory removed recursively on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("boreas-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
