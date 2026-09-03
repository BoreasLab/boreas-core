//! Platform adapters are policy-free byte shims over OS handles.
//!
//! Each implements the sync `Device` seam and the async `AsyncDevice` seam.
//! Android wraps the VpnService descriptor; Windows wraps a Wintun session.

#[cfg(unix)]
mod android {
    use std::io;

    use crate::{AsyncDevice, Device, Mtu, host::shell::whole};

    /// Android VpnService descriptor driven by tokio's `AsyncFd`.
    /// Readiness registration makes `recv` cancel-safe: a dropped future has
    /// not consumed a packet.
    pub struct AndroidTun {
        fd: tokio::io::unix::AsyncFd<std::fs::File>,
        mtu: Mtu,
    }

    impl AndroidTun {
        /// Takes ownership of the JNI-provided descriptor through a `File`.
        /// The `File` closes it on drop; VpnService owns device lifecycle and
        /// permissions.
        ///
        /// **Must be called on a Tokio runtime.** `AsyncFd` registers with the
        /// reactor during construction, including for sync-only callers.
        ///
        /// The descriptor is made non-blocking here; a blocking one would
        /// stall the reactor on its first read.
        pub fn from_owned_fd(fd: std::os::fd::OwnedFd, mtu: Mtu) -> io::Result<Self> {
            nonblocking(&fd)?;
            Ok(Self {
                fd: tokio::io::unix::AsyncFd::new(std::fs::File::from(fd))?,
                mtu,
            })
        }
    }

    fn nonblocking(fd: &impl std::os::fd::AsRawFd) -> io::Result<()> {
        let raw = fd.as_raw_fd();
        // SAFETY: `fd` is open and owned by the caller for the call.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0
            && unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A read of nothing is the descriptor closing under us, not a packet.
    fn read(file: &mut std::fs::File, buf: &mut [u8]) -> io::Result<usize> {
        match std::io::Read::read(file, buf)? {
            0 => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            len => Ok(len),
        }
    }

    impl Device for AndroidTun {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            read(self.fd.get_mut(), buf)
        }

        fn send(&mut self, buf: &[u8]) -> io::Result<()> {
            whole(
                std::io::Write::write(&mut self.fd.get_mut(), buf)?,
                buf.len(),
            )
        }

        fn mtu(&self) -> Mtu {
            self.mtu
        }
    }

    impl AsyncDevice for AndroidTun {
        fn mtu(&self) -> Mtu {
            self.mtu
        }

        #[allow(clippy::manual_async_fn)]
        fn recv<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            async move {
                loop {
                    let mut guard = self.fd.readable_mut().await?;
                    match guard.try_io(|inner| read(inner.get_mut(), buf)) {
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
        ) -> impl Future<Output = io::Result<()>> + Send + 'a {
            async move {
                loop {
                    let mut guard = self.fd.writable_mut().await?;
                    match guard.try_io(|inner| std::io::Write::write(&mut inner.get_mut(), buf)) {
                        Ok(result) => return whole(result?, buf.len()),
                        Err(_would_block) => continue,
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixDatagram;

        /// A datagram socket pair standing in for the VpnService descriptor.
        ///
        /// Datagram semantics preserve TUN packet boundaries; a stream pair
        /// could let an invalid adapter pass. Non-blocking mode is required by
        /// `AsyncFd` and prevents a read from stalling the reactor.
        /// Polls `future` once and drops it, matching a `recv` future whose
        /// `select!` arm lost the race. Keeping this local avoids a dependency
        /// for one polling helper.
        fn poll_once<F: Future>(future: F) -> std::task::Poll<F::Output> {
            let mut future = std::pin::pin!(future);
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            future.as_mut().poll(&mut cx)
        }

        fn tun() -> (AndroidTun, UnixDatagram) {
            let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
            ours.set_nonblocking(true).expect("non-blocking");
            let fd = std::os::fd::OwnedFd::from(ours);
            (
                AndroidTun::from_owned_fd(fd, Mtu::new(1500).unwrap())
                    .expect("the adapter wraps it"),
                theirs,
            )
        }

        #[tokio::test]
        async fn a_packet_crosses_the_seam_whole_in_both_directions() {
            let (mut tun, peer) = tun();

            peer.send(b"inbound packet").expect("the peer writes");
            let mut buf = [0u8; 1500];
            let read = AsyncDevice::recv(&mut tun, &mut buf).await.expect("read");
            assert_eq!(&buf[..read], b"inbound packet");

            AsyncDevice::send(&mut tun, b"outbound packet")
                .await
                .expect("write");
            let mut back = [0u8; 1500];
            let read = peer.recv(&mut back).expect("the peer reads");
            assert_eq!(&back[..read], b"outbound packet");
        }

        /// The reactor routinely drops `recv` when another `select!` arm wins.
        /// A read that consumed before completion would lose a packet without
        /// producing an error, leaving the connection stalled.
        #[tokio::test]
        async fn a_dropped_read_consumes_nothing() {
            let (mut tun, peer) = tun();

            // Abandon a read before any packet is available.
            {
                let mut buf = [0u8; 1500];
                assert!(
                    poll_once(AsyncDevice::recv(&mut tun, &mut buf)).is_pending(),
                    "nothing has arrived yet"
                );
            }

            peer.send(b"arrived after the abandoned read").unwrap();
            let mut buf = [0u8; 1500];
            let read = AsyncDevice::recv(&mut tun, &mut buf).await.unwrap();
            assert_eq!(
                &buf[..read],
                b"arrived after the abandoned read",
                "the packet survives a read that was dropped before it landed"
            );
        }

        /// Dropped reads must not consume a packet that is already waiting.
        #[tokio::test]
        async fn repeated_dropped_reads_lose_no_packet() {
            let (mut tun, peer) = tun();
            peer.send(b"one").unwrap();

            for _ in 0..8 {
                let mut buf = [0u8; 1500];
                // The read may complete here, but dropping it must not consume
                // the packet if it does not.
                if let std::task::Poll::Ready(Ok(read)) =
                    poll_once(AsyncDevice::recv(&mut tun, &mut buf))
                {
                    assert_eq!(&buf[..read], b"one");
                    return;
                }
            }

            let mut buf = [0u8; 1500];
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                AsyncDevice::recv(&mut tun, &mut buf),
            )
            .await
            .expect("the packet is still there")
            .unwrap();
            assert_eq!(&buf[..read], b"one");
        }

        /// The platform revoking the descriptor is the end of the device, not
        /// an empty packet the reactor would spin on.
        #[tokio::test]
        async fn a_closed_descriptor_ends_reads_with_an_error() {
            let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut tun = AndroidTun::from_owned_fd(ours.into(), Mtu::new(1500).unwrap())
                .expect("made non-blocking on entry");
            drop(theirs);
            let mut buf = [0u8; 1500];
            assert_eq!(
                AsyncDevice::recv(&mut tun, &mut buf)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }

        /// The sync seam uses the same descriptor as the async seam.
        /// Construction still needs a Tokio runtime because `AsyncFd` registers
        /// with the reactor immediately.
        #[tokio::test]
        async fn the_sync_seam_reads_and_writes_the_same_descriptor() {
            let (mut tun, peer) = tun();
            assert_eq!(Device::mtu(&tun).get(), 1500);

            peer.send(b"sync inbound").unwrap();
            let mut buf = [0u8; 1500];
            let read = Device::recv(&mut tun, &mut buf).expect("read");
            assert_eq!(&buf[..read], b"sync inbound");

            Device::send(&mut tun, b"sync outbound").expect("write");
            let mut back = [0u8; 1500];
            let read = peer.recv(&mut back).unwrap();
            assert_eq!(&back[..read], b"sync outbound");
        }

        /// A closed peer produces an error instead of a false successful send.
        /// The reactor treats that device failure as fatal.
        #[tokio::test]
        async fn a_write_to_a_closed_peer_is_an_error_not_a_silent_drop() {
            let (mut tun, peer) = tun();
            drop(peer);
            assert!(
                AsyncDevice::send(&mut tun, b"nowhere to go").await.is_err(),
                "a packet that did not leave is not a packet that left"
            );
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;

    use crate::{AsyncDevice, Device, Mtu};

    /// Wintun session adapter. It transfers packets from the driver's ring
    /// buffer without interpreting them.
    pub struct WintunDevice {
        session: std::sync::Arc<wintun_bindings::Session>,
        mtu: Mtu,
        /// A blocking read already in flight, retained across calls.
        ///
        /// `spawn_blocking` cannot cancel its task. Retaining the handle lets
        /// the next call await the same read after a dropped future; starting a
        /// new read would let the completed task discard its packet.
        pending: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
    }

    impl WintunDevice {
        /// Takes an open session from adapter setup. Loading the
        /// WireGuard-authorized signed `wintun.dll` belongs to the platform
        /// setup path.
        pub fn from_session(session: std::sync::Arc<wintun_bindings::Session>, mtu: Mtu) -> Self {
            Self {
                session,
                mtu,
                pending: None,
            }
        }
    }

    impl Device for WintunDevice {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(packet) = self.session.try_receive().map_err(io::Error::other)? else {
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

        fn send(&mut self, buf: &[u8]) -> io::Result<()> {
            let mut packet =
                self.session
                    .allocate_send_packet(buf.len().try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "packet too large")
                    })?)?;
            packet.bytes_mut().copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(())
        }

        fn mtu(&self) -> Mtu {
            self.mtu
        }
    }

    impl AsyncDevice for WintunDevice {
        fn mtu(&self) -> Mtu {
            self.mtu
        }

        #[allow(clippy::manual_async_fn)]
        fn recv<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
            // Wintun waits on a Win32 event, so the read runs on the blocking
            // pool. The task owns its bytes and the handle remains in `self`
            // until observed; a dropped future therefore consumes nothing.
            async move {
                if self.pending.is_none() {
                    let session = std::sync::Arc::clone(&self.session);
                    self.pending = Some(tokio::task::spawn_blocking(move || {
                        session
                            .receive_blocking()
                            .map(|packet| packet.bytes().to_vec())
                            .map_err(io::Error::other)
                    }));
                }

                let joined = self
                    .pending
                    .as_mut()
                    .expect("the read was just started")
                    .await;
                // The join resolved, so the packet is in hand and the slot is
                // free for the next read.
                self.pending = None;

                let bytes = joined.map_err(io::Error::other)??;
                if bytes.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet exceeds the receive buffer",
                    ));
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
        }

        #[allow(clippy::manual_async_fn)]
        fn send<'a>(
            &'a mut self,
            buf: &'a [u8],
        ) -> impl Future<Output = io::Result<()>> + Send + 'a {
            // A driver call of unknown latency, like the read: not on the
            // runtime thread.
            async move {
                let session = std::sync::Arc::clone(&self.session);
                let bytes = buf.to_vec();
                tokio::task::spawn_blocking(move || {
                    let mut packet =
                        session.allocate_send_packet(bytes.len().try_into().map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "packet too large")
                        })?)?;
                    packet.bytes_mut().copy_from_slice(&bytes);
                    session.send_packet(packet);
                    Ok(())
                })
                .await
                .map_err(io::Error::other)?
            }
        }
    }
}

#[cfg(unix)]
pub use android::AndroidTun;
#[cfg(windows)]
pub use windows::WintunDevice;
