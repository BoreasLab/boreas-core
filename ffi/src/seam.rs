//! Host-provided device and bypass operations, represented as C vtables.
//!
//! Kotlin and C# implement the Rust platform traits through an opaque context
//! and callbacks with `#[repr(C)]` layouts.

use std::{ffi::c_void, future::Future, io, net::SocketAddr, sync::Arc};

use boreas_core::{AsyncDevice, Mtu, TunnelBypass};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::mpsc,
};

/// A host socket handle excluded from the tunnel.
///
/// This holds Unix file descriptors and Windows `SOCKET` values.
pub type BoreasSocket = i64;

/// Host implementation of the client's TUN.
///
/// Callbacks may run on any Tokio worker thread. The host must make them
/// thread-safe; Rust cannot verify that property for the opaque context.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasDevice {
    /// Host-owned state passed to every callback unchanged.
    pub context: *mut c_void,
    /// Reads one IP packet into `buf`: a byte count, zero for "ask again", or a
    /// negative error code. Blocking callbacks run on a blocking thread;
    /// [`Device`] retains their result across polls.
    pub recv: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize>,
    /// Writes one complete IP packet. Returns 0 or a negative error code.
    /// Short writes are errors.
    pub send: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> isize>,
    /// Causes an in-flight [`Self::recv`] to return promptly.
    ///
    /// Called before [`Self::release`] and possibly while `recv` is blocked.
    /// A device with bounded reads may omit it, but shutdown then waits for the
    /// outstanding callback.
    pub close: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Releases `context` once all callbacks have returned.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Configured interface MTU.
    pub mtu: u16,
}

/// Host operations for sockets that must bypass the tunnel.
///
/// Boreas creates each socket and the host excludes it. Android uses
/// `VpnService.protect(fd)`; Windows uses the physical interface or index.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasBypass {
    pub context: *mut c_void,
    /// Excludes one socket from the tunnel. Returns 0 on success.
    pub protect: Option<unsafe extern "C" fn(*mut c_void, BoreasSocket) -> i32>,
    /// Releases `context` once when the tunnel is freed.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

unsafe impl Send for BoreasDevice {}
unsafe impl Sync for BoreasDevice {}
unsafe impl Send for BoreasBypass {}
unsafe impl Sync for BoreasBypass {}

impl BoreasDevice {
    /// Reads one packet through the host callback.
    ///
    /// # Safety
    ///
    /// The host promised these callbacks are safe to call from any thread.
    unsafe fn read_into(self, buf: &mut [u8]) -> io::Result<usize> {
        let recv = self.recv.ok_or_else(missing)?;
        // SAFETY: `buf` is a live allocation for the length given, and it
        // outlives this call.
        let read = unsafe { recv(self.context, buf.as_mut_ptr(), buf.len()) };
        if read < 0 {
            return Err(failed(read));
        }
        let read = usize::try_from(read).unwrap_or(0);
        if read > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the device reported more bytes than it was given room for",
            ));
        }
        Ok(read)
    }

    /// Writes one complete packet.
    ///
    /// # Safety
    ///
    /// As [`Self::read_into`].
    unsafe fn write_all(self, buf: &[u8]) -> io::Result<()> {
        let send = self.send.ok_or_else(missing)?;
        // SAFETY: `buf` outlives the call.
        let written = unsafe { send(self.context, buf.as_ptr(), buf.len()) };
        if written < 0 {
            return Err(failed(written));
        }
        Ok(())
    }

    /// Asks the host to end an in-flight read.
    ///
    /// # Safety
    ///
    /// The host promised this is safe to call while a `recv` is blocked.
    unsafe fn close_reads(self) {
        if let Some(close) = self.close {
            // SAFETY: the caller established the concurrency contract.
            unsafe { close(self.context) };
        }
    }

    /// Releases the host context exactly once.
    ///
    /// # Safety
    ///
    /// No other call may be in flight, and none may follow.
    unsafe fn release_context(self) {
        if let Some(release) = self.release {
            // SAFETY: the caller established this is the one call.
            unsafe { release(self.context) };
        }
    }
}

impl BoreasBypass {
    /// Asks the host to exclude one socket before use.
    ///
    /// # Safety
    ///
    /// `socket` must be live for the duration of the call, and the host
    /// promised these callbacks are safe to call from any thread.
    unsafe fn exclude(self, socket: BoreasSocket) -> io::Result<()> {
        let protect = self.protect.ok_or_else(missing)?;
        // SAFETY: the caller established both preconditions.
        match unsafe { protect(self.context, socket) } {
            0 => Ok(()),
            _ => Err(io::Error::other("the host refused to protect a socket")),
        }
    }

    /// # Safety
    ///
    /// No other call may be in flight, and none may follow.
    unsafe fn release_context(self) {
        if let Some(release) = self.release {
            // SAFETY: the caller established this is the one call.
            unsafe { release(self.context) };
        }
    }
}

fn missing() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "the host supplied no callback")
}

fn failed(code: isize) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(-code).unwrap_or(libc_eio()))
}

const fn libc_eio() -> i32 {
    5
}

/// Adapts [`BoreasDevice`] to [`AsyncDevice`].
///
/// Two blocking tasks own the host's callbacks, one per direction, joined to
/// the reactor by bounded channels of recycled buffers. The reactor never waits
/// on the host, reads overlap writes, and a packet in flight allocates nothing.
/// The tasks start on first use so a device that never ran releases its
/// context synchronously, and runtime shutdown joins them within its grace.
struct Context(BoreasDevice);

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this runs when the last `Arc` drops, so no call is in flight
        // and none can follow.
        unsafe { self.0.release_context() };
    }
}

/// Buffers per direction; a burst can hold this many packets in flight.
const DEPTH: usize = 64;

pub struct Device {
    ops: BoreasDevice,
    mtu: Mtu,
    /// Packets from the reader. An `Err` ends the device.
    inbound: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// Emptied buffers back to the reader.
    refill: mpsc::Sender<Vec<u8>>,
    /// Packets to the writer.
    outbound: mpsc::Sender<Vec<u8>>,
    /// Emptied buffers back from the writer.
    spare: mpsc::Receiver<Vec<u8>>,
    /// The tasks' halves, until first use starts them.
    unstarted: Option<Unstarted>,
    context: Arc<Context>,
}

struct Unstarted {
    refill: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Receiver<Vec<u8>>,
    spare: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Sender<io::Result<Vec<u8>>>,
}

impl Device {
    /// Returns `None` when required callbacks are absent or the MTU is below
    /// the IPv6 minimum.
    pub fn new(ops: BoreasDevice) -> Option<Self> {
        ops.recv?;
        ops.send?;
        // Before the MTU check: a refused device still releases its context.
        let context = Arc::new(Context(ops));
        let mtu = Mtu::new(ops.mtu).ok()?;

        let (inbound_tx, inbound) = mpsc::channel(DEPTH);
        let (refill, refill_rx) = mpsc::channel(DEPTH);
        let (outbound, outbound_rx) = mpsc::channel(DEPTH);
        let (spare_tx, spare) = mpsc::channel(DEPTH);
        for _ in 0..DEPTH {
            let _ = refill.try_send(Vec::with_capacity(usize::from(mtu.get())));
            let _ = spare_tx.try_send(Vec::with_capacity(usize::from(mtu.get())));
        }

        Some(Self {
            ops,
            mtu,
            inbound,
            refill,
            outbound,
            spare,
            unstarted: Some(Unstarted {
                refill: refill_rx,
                outbound: outbound_rx,
                spare: spare_tx,
                inbound: inbound_tx,
            }),
            context,
        })
    }

    /// Starts both tasks once, on the runtime that polls this device.
    fn start(&mut self) {
        let Some(halves) = self.unstarted.take() else {
            return;
        };
        let Unstarted {
            refill,
            outbound,
            spare,
            inbound,
        } = halves;
        let mtu = self.mtu;
        let reader = Arc::clone(&self.context);
        let writer = Arc::clone(&self.context);
        let inbound_from_writer = inbound.clone();
        tokio::task::spawn_blocking(move || read_loop(&reader, mtu, refill, &inbound));
        tokio::task::spawn_blocking(move || {
            write_loop(&writer, outbound, &spare, &inbound_from_writer);
        });
    }
}

/// Reads until the host fails or the reactor is gone.
fn read_loop(
    context: &Context,
    mtu: Mtu,
    mut refill: mpsc::Receiver<Vec<u8>>,
    inbound: &mpsc::Sender<io::Result<Vec<u8>>>,
) {
    while let Some(mut buf) = refill.blocking_recv() {
        buf.resize(usize::from(mtu.get()), 0);
        // Zero is "no packet yet": ask again with the same buffer, so an idle
        // device costs no channel traffic.
        let read = loop {
            // SAFETY: the host's callbacks are safe from any thread, and
            // `context` keeps them live for as long as this thread runs.
            match unsafe { context.0.read_into(&mut buf) } {
                Ok(0) => continue,
                Ok(read) => break read,
                Err(error) => {
                    let _ = inbound.blocking_send(Err(error));
                    return;
                }
            }
        };
        buf.truncate(read);
        if inbound.blocking_send(Ok(buf)).is_err() {
            return;
        }
    }
}

/// Writes until the host fails or the reactor is gone. A failure is reported
/// on the inbound channel, which the reactor is always polling.
fn write_loop(
    context: &Context,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    spare: &mpsc::Sender<Vec<u8>>,
    inbound: &mpsc::Sender<io::Result<Vec<u8>>>,
) {
    while let Some(mut buf) = outbound.blocking_recv() {
        // SAFETY: as in `read_loop`.
        if let Err(error) = unsafe { context.0.write_all(&buf) } {
            let _ = inbound.blocking_send(Err(error));
            return;
        }
        buf.clear();
        // A full spare queue means the reactor is allocating faster than this
        // thread returns buffers; dropping one here bounds the total.
        let _ = spare.try_send(buf);
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the device threads have exited")
}

impl Drop for Device {
    fn drop(&mut self) {
        // The channels close with `self`, which ends both threads once the host
        // returns. `close` is what makes a blocked `recv` return.
        // SAFETY: the host's contract is that this is safe while a read is
        // blocked, which is precisely the case it exists for.
        unsafe { self.ops.close_reads() };
    }
}

impl AsyncDevice for Device {
    fn mtu(&self) -> Mtu {
        self.mtu
    }

    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        // Cancel-safe: `recv` hands over a packet only when it completes, and
        // the copy and refill happen in the same poll.
        async move {
            self.start();
            let bytes = self.inbound.recv().await.ok_or_else(closed)??;
            if bytes.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet exceeds the receive buffer",
                ));
            }
            buf[..bytes.len()].copy_from_slice(&bytes);
            let len = bytes.len();
            let _ = self.refill.try_send(bytes);
            Ok(len)
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move {
            self.start();
            let mut owned = self.spare.try_recv().unwrap_or_default();
            owned.clear();
            owned.extend_from_slice(buf);
            self.outbound.send(owned).await.map_err(|_| closed())
        }
    }
}

#[derive(Clone, Copy)]
pub struct Bypass {
    ops: BoreasBypass,
}

impl Bypass {
    /// Returns `None` when `protect` is absent. A no-op would let egress traffic
    /// re-enter the tunnel once it starts.
    pub fn new(ops: BoreasBypass) -> Option<Self> {
        ops.protect?;
        Some(Self { ops })
    }

    /// Hands the host a live socket before it is connected or bound.
    fn protect(&self, socket: BoreasSocket) -> io::Result<()> {
        // SAFETY: the socket is a live handle owned by the caller for the
        // duration of this call, and the host promised any thread is fine.
        unsafe { self.ops.exclude(socket) }
    }
}

/// Releases the host context once, independently of [`Bypass`] clone count.
pub struct BypassGuard(BoreasBypass);

impl BypassGuard {
    pub fn new(ops: BoreasBypass) -> Self {
        Self(ops)
    }
}

impl Drop for BypassGuard {
    fn drop(&mut self) {
        // SAFETY: one guard exists per tunnel and it outlives every `Bypass`
        // clone, so this is the one release.
        unsafe { self.0.release_context() };
    }
}

#[cfg(unix)]
fn raw(socket: &impl std::os::fd::AsRawFd) -> BoreasSocket {
    BoreasSocket::from(socket.as_raw_fd())
}

#[cfg(windows)]
fn raw(socket: &impl std::os::windows::io::AsRawSocket) -> BoreasSocket {
    // Preserve every bit of the unsigned pointer-width Windows handle.
    socket.as_raw_socket() as BoreasSocket
}

impl TunnelBypass for Bypass {
    #[allow(clippy::manual_async_fn)]
    fn tcp(&self, peer: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        let bypass = *self;
        async move {
            // Exclude the unconnected socket before its first packet leaves.
            let socket = match peer {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            bypass.protect(raw(&socket))?;
            socket.connect(peer).await
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn udp(&self, peer: SocketAddr) -> impl Future<Output = io::Result<UdpSocket>> + Send {
        let bypass = *self;
        async move {
            let socket = bypass.bind(unspecified(peer))?;
            socket.connect(peer).await?;
            Ok(socket)
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn unbound(&self) -> impl Future<Output = io::Result<UdpSocket>> + Send {
        let bypass = *self;
        async move { bypass.bind(SocketAddr::from(([0, 0, 0, 0], 0))) }
    }
}

impl Bypass {
    /// Binds and protects a socket before handing it to Tokio.
    fn bind(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        self.protect(raw(&socket))?;
        UdpSocket::from_std(socket)
    }
}

fn unspecified(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}
