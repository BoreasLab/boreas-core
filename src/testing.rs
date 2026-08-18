//! Helpers shared by this crate's own tests, and by nothing else.
//!
//! `#[cfg(test)]` throughout, so none of it reaches the artefact. It exists
//! because two modules need a real QUIC server to test against and `quiche`
//! loads its credentials only from PEM files on disk — so both need the same
//! self-signed certificate, the same DER-to-PEM encoder, and the same scratch
//! directory that removes itself.

use std::path::{Path, PathBuf};

/// A self-signed certificate for `name`, written where `quiche` can load it.
///
/// Returns the two paths and the directory that owns them: dropping the
/// directory removes both, so a failing test leaves nothing behind.
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

/// Wraps DER as PEM, because `quiche` loads only PEM while `rcgen` here
/// produces DER.
///
/// Written out rather than enabling `rcgen`'s `pem` feature: that feature is
/// not `dev`-scoped, so it would ship a base64 implementation into the artefact
/// to satisfy a need that exists only in tests.
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

/// A scratch directory that removes itself.
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
