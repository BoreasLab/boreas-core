//! The two obligations a host cannot delegate, as vtables of function pointers.
//!
//! `api/platform.md` states them as Rust traits. Neither Kotlin nor C# can
//! implement one, so each becomes a `#[repr(C)]` product of an opaque context
//! and the functions that act on it — the closure, spelled out.

use std::{ffi::c_void, future::Future, io, net::SocketAddr, sync::Arc};

use boreas_core::{AsyncDevice, Mtu, TunnelBypass};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// A socket the host is being asked to exclude from the tunnel.
///
/// A file descriptor on Unix and a `SOCKET` on Windows, which is why this is
/// signed 64-bit rather than `int`: the two platforms disagree about the width
/// and one of them uses the top bit.
pub type BoreasSocket = i64;

/// The client's TUN, as the host implements it.
///
/// **Every function here is called from a Tokio worker thread**, and not
/// always the same one. The host's implementation must therefore be safe to
/// call from any thread; that requirement is what the `unsafe impl Send` below
/// rests on, and it is not something this crate can check.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasDevice {
    /// Passed back to every call, untouched. The host's own state.
    pub context: *mut c_void,
    /// Reads one IP packet into `buf`. Returns the number of bytes written,
    /// **zero for "nothing yet, ask again"**, or a negative value on error.
    ///
    /// **Blocking is expected but not required.** A callback cannot be a
    /// future, so this runs on a blocking thread and its result is held across
    /// polls; see [`Device`]. A host that must not block indefinitely may wait
    /// for a bounded interval and return zero — there is no zero-length IP
    /// packet, so the value is free to mean "ask again", and it costs nothing
    /// but another call.
    pub recv: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize>,
    /// Writes one IP packet, whole. Returns 0, or a negative value on error.
    /// A short write is an error rather than a success with a count.
    pub send: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> isize>,
    /// Makes any in-flight [`Self::recv`] return, promptly.
    ///
    /// **Called *before* [`Self::release`], and possibly while a `recv` is
    /// blocked**, so it must be safe to call concurrently with one. That
    /// ordering is not a nicety: a blocking read cannot be cancelled, so
    /// `release` cannot fire until the read returns, and the read does not
    /// return until the host makes it. If `release` were the only signal the
    /// two would wait for each other. On Android this is `close(fd)`; on
    /// Windows, cancelling the read wait.
    ///
    /// Optional, for a device whose reads are bounded anyway — but a tunnel
    /// with none pays a grace period on every stop and detaches a
    /// read that may never end.
    pub close: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Releases `context`. Called once, after every callback has returned.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
    /// The MTU the interface is configured with.
    pub mtu: u16,
}

/// Sockets that do not re-enter the tunnel.
///
/// One function, because the platforms agree on the shape even where they
/// disagree on the mechanism: Boreas creates the socket and the host excludes
/// it. On Android that is `VpnService.protect(fd)`; on Windows it is binding
/// the physical interface or setting its index. Creating the socket here rather
/// than in the host is what keeps its type and its lifetime on this side.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasBypass {
    pub context: *mut c_void,
    /// Excludes one socket from the tunnel. Returns 0 on success.
    pub protect: Option<unsafe extern "C" fn(*mut c_void, BoreasSocket) -> i32>,
    /// Releases `context`. Called once, when the tunnel is freed.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

// **The claim, stated once.** A raw pointer is `!Send` because the compiler
// cannot know what it points at. Here the host has been told, in the
// documentation above and in the header, that its callbacks are called from
// arbitrary worker threads — so this asserts a contract the host agreed to
// rather than a fact about the pointer.
unsafe impl Send for BoreasDevice {}
unsafe impl Sync for BoreasDevice {}
unsafe impl Send for BoreasBypass {}
unsafe impl Sync for BoreasBypass {}

impl BoreasDevice {
    /// Reads one packet through the host's callback.
    ///
    /// **A method rather than a call spelled out at each site**, so the whole
    /// vtable is one value: a closure that touched `context` and `recv`
    /// separately would capture those *fields*, and a `*mut c_void` field is
    /// not `Send` however the struct around it is declared.
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

    /// Writes one packet, whole.
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

    /// Asks the host to end any in-flight read.
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

    /// Releases the host's context. Called exactly once.
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
    /// Asks the host to exclude one socket.
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

/// `EIO`, spelled without a libc dependency for one constant.
const fn libc_eio() -> i32 {
    5
}

/// A [`BoreasDevice`] as an [`AsyncDevice`].
///
/// **The in-flight read is held across calls, and that is the whole design.**
/// The reactor selects over `recv` and drops the future routinely, so a dropped
/// future must consume nothing. A blocking callback can only run on
/// `spawn_blocking`, which cannot be cancelled — dropping its join handle would
/// discard a packet the host has already taken off the interface. So the handle
/// is parked here and the next call resumes it. `platform.rs`'s Wintun adapter
/// solves the same problem the same way, for the same reason.
/// The host's device context, released when the last holder drops it.
///
/// **Refcounted, and that is not incidental.** `spawn_blocking` cannot be
/// cancelled: a `recv` already inside the host's callback keeps running after
/// its join handle is aborted and after the tunnel is gone. If `release` fired
/// when [`Device`] dropped, that in-flight call would be holding a context the
/// host had already freed. Sharing the guard with the blocking task makes the
/// release happen after *both*, which is the only ordering that is sound
/// without a cancellation the platform does not provide.
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
    /// `None` when the host left out a callback or named an MTU below the IPv6
    /// minimum, both of which are configuration rather than runtime failures.
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
        // Aborting the handle stops the *join*, not the blocking call: a
        // `spawn_blocking` task already inside the host's `recv` runs to
        // completion whatever happens here. Asking the host to end the read is
        // the only thing that actually ends it, and the refcounted `Context`
        // is what keeps `release` behind it.
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
        // The same shape, and for the same reason, as `WintunDevice`: the
        // blocking task owns the bytes it read — it must, because nothing can
        // hand them back through a cancelled future — and its handle stays in
        // `self` until the join has actually resolved. A dropped future
        // therefore consumes nothing, which is the seam's stated obligation
        // and the one thing a callback-shaped device makes hard.
        async move {
            loop {
                if self.pending.is_none() {
                    let ops = self.ops;
                    // Held for the life of the call, so the host's `release`
                    // cannot run while this callback is inside it.
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
                // Reached only once the join resolved, so the packet is in
                // hand and the slot is genuinely free.
                self.pending = None;

                let bytes = joined.map_err(io::Error::other)??;
                // **Zero is "nothing yet", not "a packet of no bytes".**
                //
                // There is no such thing as a zero-length IP packet, so the
                // value is free to mean something else, and what a host needs
                // it to mean is "ask me again". A device that must not block
                // indefinitely — a .NET callback runs in the CLR's cooperative
                // mode, where a long block stalls every managed thread's
                // garbage collection — can then wait for a bounded interval
                // and return here. Handing the empty slice on would make the
                // datapath reject it and charge `packets_rejected` for a
                // packet nobody sent.
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

/// A [`BoreasBypass`] as a [`TunnelBypass`].
///
/// Cheap to clone, because a tunnel needs one per thing that dials and the
/// clone is two pointers.
#[derive(Clone, Copy)]
pub struct Bypass {
    ops: BoreasBypass,
}

impl Bypass {
    /// `None` when the host left out `protect`. **Not defaulted to a no-op**,
    /// for the reason `api/platform.md` gives: an unprotected socket works
    /// perfectly until the tunnel comes up, and then every packet it sends
    /// re-enters the tunnel it was serving.
    pub fn new(ops: BoreasBypass) -> Option<Self> {
        ops.protect?;
        Some(Self { ops })
    }

    /// Hands one socket to the host, before it is connected or bound.
    fn protect(&self, socket: BoreasSocket) -> io::Result<()> {
        // SAFETY: the socket is a live handle owned by the caller for the
        // duration of this call, and the host promised any thread is fine.
        unsafe { self.ops.exclude(socket) }
    }
}

/// Releases the host's context exactly once, however many [`Bypass`] clones
/// were made. A tunnel clones its bypass per dialling thing, so the release
/// cannot live on `Bypass` itself.
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
    // A `SOCKET` is an unsigned pointer-width handle; the cast preserves every
    // bit and the host casts it back.
    socket.as_raw_socket() as BoreasSocket
}

impl TunnelBypass for Bypass {
    #[allow(clippy::manual_async_fn)]
    fn tcp(&self, peer: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        let bypass = *self;
        async move {
            // Created unconnected on purpose: the socket must be excluded
            // *before* its first packet leaves, and a connected socket has
            // already sent one.
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
    /// Binds, protects, then hands the socket to Tokio. Not `async`, because
    /// none of the three steps awaits: the ordering is the point, not the
    /// concurrency.
    fn bind(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        self.protect(raw(&socket))?;
        UdpSocket::from_std(socket)
    }
}

/// The wildcard address of `peer`'s family, which is what a socket about to
/// connect to it must be bound to.
fn unspecified(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}
