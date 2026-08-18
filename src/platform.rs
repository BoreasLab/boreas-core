//! Platform adapters: byte shims over OS handles, no policy. Each implements
//! both the sync `Device` seam (for tests and the simulator) and the async
//! `AsyncDevice` seam (for the reactor). The Android adapter wraps the
//! VpnService file descriptor delivered over JNI; the Windows adapter wraps a
//! Wintun session.

#[cfg(unix)]
mod android {
    use std::io;

    use crate::{AsyncDevice, Device, Mtu, shell::whole};

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
        ///
        /// **Must be called on a Tokio runtime**, even by a caller that only
        /// ever uses the sync [`Device`] seam: registration with the reactor
        /// happens here rather than at first read, so a construction off the
        /// runtime panics rather than failing later at a less obvious place.
        ///
        /// The descriptor must already be non-blocking. `VpnService.establish`
        /// returns one that is not, so set `O_NONBLOCK` before handing it
        /// over — a blocking descriptor would stall the whole reactor on its
        /// first read.
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
        /// Datagram rather than stream, deliberately: a TUN preserves packet
        /// boundaries, and a stream pair would let a test pass that a real
        /// device would fail. Non-blocking because `AsyncFd` requires it — a
        /// blocking descriptor here would stall the whole reactor on its first
        /// read, which is the failure this shim exists to avoid.
        /// Polls `future` once and drops it, which is exactly what a lost
        /// `select!` arm does to a `recv`. Two lines here rather than a
        /// dependency on `futures-util` for one macro.
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

        /// **The obligation the seam states, and the one whose breach is
        /// silent.** The reactor selects over `recv` and drops the future every
        /// time another arm wins, which is routine. An implementation that had
        /// already consumed bytes would lose a packet per lost race — and the
        /// symptom is not an error, it is a connection that stalls for reasons
        /// nothing records.
        #[tokio::test]
        async fn a_dropped_read_consumes_nothing() {
            let (mut tun, peer) = tun();

            // A read with nothing to read, abandoned.
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

        /// Several reads dropped in a row, each after a packet is already
        /// waiting. This is the shape that catches an implementation which
        /// consumes on poll rather than on completion.
        #[tokio::test]
        async fn repeated_dropped_reads_lose_no_packet() {
            let (mut tun, peer) = tun();
            peer.send(b"one").unwrap();

            for _ in 0..8 {
                let mut buf = [0u8; 1500];
                // This one *can* complete, since a packet is waiting; whether
                // it does is not the point. The point is that dropping it
                // must not be what consumes the packet.
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

        /// The sync seam over the same descriptor, which the simulator drives.
        ///
        /// A `tokio::test` despite using none of the async seam: construction
        /// registers with the reactor, so there has to be one.
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

        /// A descriptor whose peer is gone reports the failure rather than
        /// pretending the packet left. The reactor treats a device error as
        /// fatal, which is right — there is nothing left to serve.
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

    /// Windows Wintun session. Packets arrive through the driver's ring
    /// buffer; the adapter moves them across the seam without interpreting.
    /// The session is `Arc`-backed so the blocking-read path can hold its own
    /// reference across a `spawn_blocking` boundary.
    pub struct WintunDevice {
        session: std::sync::Arc<wintun_bindings::Session>,
        mtu: Mtu,
        /// A blocking read already in flight, retained across calls.
        ///
        /// This is what makes `recv` cancel-safe, and its absence was a real
        /// defect: `spawn_blocking` cannot be cancelled, so dropping the join
        /// handle lets the task run to completion and *discards the packet it
        /// received*. The reactor drops this future every time another
        /// `select!` arm wins, which is routine, so a fresh read per call
        /// loses a packet per lost race. Holding the handle means the next
        /// call awaits the same read instead of starting another.
        pending: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
    }

    impl WintunDevice {
        /// Takes the open session from the adapter setup path. `wintun.dll` is
        /// the WireGuard-authorized signed binary; loading lives in the
        /// platform crate, not here.
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
            // Wintun's read wait is a Win32 event, not a tokio primitive, so
            // the blocking read moves to the blocking pool. The task owns the
            // bytes it read — it must, because nothing can hand them back
            // through a cancelled future — and the handle stays in `self`
            // until it has actually been observed. A dropped future therefore
            // consumes nothing, which is the seam's stated obligation.
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
                // Reached only after the join future resolved, so the packet
                // is in hand and the slot is genuinely free.
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
            async move { Device::send(self, buf) }
        }
    }
}

#[cfg(unix)]
pub use android::AndroidTun;
#[cfg(windows)]
pub use windows::WintunDevice;
