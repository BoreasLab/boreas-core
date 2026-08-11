//! Platform adapters: byte shims over OS handles, no policy. Each implements
//! both the sync `Device` seam (for tests and the simulator) and the async
//! `AsyncDevice` seam (for the reactor). The Android adapter wraps the
//! VpnService file descriptor delivered over JNI; the Windows adapter wraps a
//! Wintun session.

#[cfg(unix)]
mod android {
    use std::io;

    use crate::{AsyncDevice, Device, Mtu};

    /// Android's VpnService fd. Readiness comes from tokio's `AsyncFd`, so
    /// `recv` is cancel-safe: it registers interest and only reads when the
    /// reactor is actually waiting, so a dropped future consumes nothing.
    pub struct AndroidTun {
        fd: tokio::io::unix::AsyncFd<std::fs::File>,
        mtu: Mtu,
    }

    impl AndroidTun {
        /// Takes ownership of the fd the JNI layer handed over, wrapped in the
        /// `File` that owns its close-on-drop. The adapter never opens the
        /// device; VpnService owns lifecycle and permissions.
        pub fn from_owned_fd(fd: std::os::fd::OwnedFd, mtu: Mtu) -> io::Result<Self> {
            Ok(Self {
                fd: tokio::io::unix::AsyncFd::new(std::fs::File::from(fd))?,
                mtu,
            })
        }
    }

    impl Device for AndroidTun {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.fd.get_mut(), buf)
        }

        fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::io::Write::write(&mut self.fd.get_mut(), buf)
        }

        fn mtu(&self) -> Mtu {
            self.mtu
        }
    }

    impl AsyncDevice for AndroidTun {
        #[allow(clippy::manual_async_fn)]
        fn recv<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            async move {
                loop {
                    let mut guard = self.fd.readable_mut().await?;
                    match guard.try_io(|inner| std::io::Read::read(&mut inner.get_mut(), buf)) {
                        Ok(result) => return result,
                        Err(_would_block) => continue,
                    }
                }
            }
        }

        #[allow(clippy::manual_async_fn)]
        fn send<'a>(
            &'a mut self,
            buf: &'a [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            async move {
                loop {
                    let mut guard = self.fd.writable_mut().await?;
                    match guard.try_io(|inner| std::io::Write::write(&mut inner.get_mut(), buf)) {
                        Ok(result) => return result,
                        Err(_would_block) => continue,
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;

    use crate::{AsyncDevice, Device, Mtu};

    /// Windows Wintun session. Packets arrive through the driver's ring
    /// buffer; the adapter moves them across the seam without interpreting.
    /// The session is `Arc`-backed so the blocking-read path can hold its own
    /// reference across a `spawn_blocking` boundary.
    pub struct WintunDevice {
        session: std::sync::Arc<wintun_bindings::Session>,
        mtu: Mtu,
    }

    impl WintunDevice {
        /// Takes the open session from the adapter setup path. `wintun.dll` is
        /// the WireGuard-authorized signed binary; loading lives in the
        /// platform crate, not here.
        pub fn from_session(session: std::sync::Arc<wintun_bindings::Session>, mtu: Mtu) -> Self {
            Self { session, mtu }
        }
    }

    impl Device for WintunDevice {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(packet) = self.session.try_receive().map_err(io::Error::other)?
            else {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet"));
            };
            let bytes = packet.bytes();
            if bytes.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet exceeds the receive buffer",
                ));
            }
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }

        fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut packet =
                self.session
                    .allocate_send_packet(buf.len().try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "packet too large")
                    })?)?;
            packet.bytes_mut().copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(buf.len())
        }

        fn mtu(&self) -> Mtu {
            self.mtu
        }
    }

    impl AsyncDevice for WintunDevice {
        #[allow(clippy::manual_async_fn)]
        fn recv<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            // Wintun's read wait is a Win32 event, not a tokio primitive, so
            // the blocking read moves to the blocking pool. Cancel-safety
            // holds because `receive_blocking` owns its session reference and
            // runs to completion even when the reactor drops the join handle.
            let session = std::sync::Arc::clone(&self.session);
            async move {
                let packet = tokio::task::spawn_blocking(move || {
                    session.receive_blocking().map_err(io::Error::other)
                })
                .await
                .map_err(io::Error::other)??;
                let bytes = packet.bytes();
                if bytes.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet exceeds the receive buffer",
                    ));
                }
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        #[allow(clippy::manual_async_fn)]
        fn send<'a>(
            &'a mut self,
            buf: &'a [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            async move { Device::send(self, buf) }
        }
    }
}

#[cfg(unix)]
pub use android::AndroidTun;
#[cfg(windows)]
pub use windows::WintunDevice;
