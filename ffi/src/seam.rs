//! Host-provided device and bypass operations, represented as C vtables.
//!
//! Kotlin and C# implement the Rust platform traits through an opaque context
//! and callbacks with `#[repr(C)]` layouts.

use std::{ffi::c_void, future::Future, io, net::SocketAddr, sync::Arc};

use boreas_core::{AsyncDevice, Mtu, TunnelBypass};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

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
/// The blocking read and its join handle remain in `self` across polls. A
/// dropped future therefore consumes no packet, and a blocking callback cannot
/// outlive the context guard held by its task.
struct Context(BoreasDevice);

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this runs when the last `Arc` drops, so no call is in flight
        // and none can follow.
        unsafe { self.0.release_context() };
    }
}

pub struct Device {
    ops: BoreasDevice,
    context: Arc<Context>,
    mtu: Mtu,
    pending: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
}

impl Device {
    /// Returns `None` when required callbacks are absent or the MTU is below
    /// the IPv6 minimum.
    pub fn new(ops: BoreasDevice) -> Option<Self> {
        ops.recv?;
        ops.send?;
        Some(Self {
            ops,
            context: Arc::new(Context(ops)),
            mtu: Mtu::new(ops.mtu).ok()?,
            pending: None,
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Aborting the handle stops only the join. The host callback still runs
        // until `close` ends it; `Context` keeps `release` behind that callback.
        if let Some(pending) = self.pending.take() {
            pending.abort();
        }
        // SAFETY: the host's contract is that this is safe to call while a
        // read is blocked, which is precisely the case it exists for.
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
        // Keep the blocking task and its bytes in `self` until the join resolves;
        // a cancelled future must not consume a packet invisibly.
        async move {
            loop {
                if self.pending.is_none() {
                    let ops = self.ops;
                    // Keep the host context alive for the callback.
                    let context = Arc::clone(&self.context);
                    let capacity = buf.len();
                    self.pending = Some(tokio::task::spawn_blocking(move || {
                        let _context = context;
                        let mut owned = vec![0u8; capacity];
                        // SAFETY: the host's contract is that its callbacks
                        // are safe from any thread, which is what a blocking
                        // pool gives them, and `_context` keeps them live.
                        let read = unsafe { ops.read_into(&mut owned) }?;
                        owned.truncate(read);
                        Ok(owned)
                    }));
                }

                let joined = self
                    .pending
                    .as_mut()
                    .expect("the read was just started")
                    .await;
                // The join resolved, so the callback and its context are done.
                self.pending = None;

                let bytes = joined.map_err(io::Error::other)??;
                // Zero means that the host has no packet yet. There is no
                // zero-length IP packet, so retry without charging a rejection.
                if bytes.is_empty() {
                    continue;
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                return Ok(bytes.len());
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a {
        let ops = self.ops;
        let context = Arc::clone(&self.context);
        let packet = buf.to_vec();
        async move {
            tokio::task::spawn_blocking(move || {
                let _context = context;
                // SAFETY: as in `recv` above.
                unsafe { ops.write_all(&packet) }
            })
            .await
            .map_err(io::Error::other)?
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
