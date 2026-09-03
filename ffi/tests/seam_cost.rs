//! What one packet costs to cross the device seam, as a law CI can ratchet.
//!
//! The allocator count is the assertion; the time is printed. A count is stable
//! across machines and a duration is not, and the count is what the seam's
//! design controls. The budget here is lowered as the seam improves; it is
//! never raised.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use boreas::{BoreasDevice, Device};
use boreas_core::AsyncDevice;

/// Allocations by any thread, which is what a packet costs the process.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to `System` unchanged; the counter has no effect on layout.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const PACKET: usize = 1400;
const MTU: u16 = 1500;
/// Packets before counting, so runtime threads and channels exist already.
const WARM_UP: usize = 256;
const PACKETS: u64 = 20_000;
/// Allocations per packet, receive plus send, rounded to whole allocations so
/// runtime housekeeping cannot fail the law. The seam that spawned a blocking
/// task per call measured 4; the one that recycles its buffers owes none.
const BUDGET: u64 = 0;

struct Host {
    closed: AtomicBool,
    sent: AtomicU64,
}

/// # Safety
///
/// `context` is the `Arc<Host>` leaked by [`vtable`].
unsafe extern "C" fn recv(context: *mut c_void, buf: *mut u8, cap: usize) -> isize {
    let host = unsafe { &*context.cast::<Host>() };
    if host.closed.load(Ordering::Relaxed) || cap < PACKET {
        return -5;
    }
    // A minimal IPv4 header so the bytes are a packet, not a pattern.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, PACKET) };
    out.fill(0);
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(PACKET as u16).to_be_bytes());
    PACKET as isize
}

/// # Safety
///
/// As [`recv`].
unsafe extern "C" fn send(context: *mut c_void, _buf: *const u8, len: usize) -> isize {
    let host = unsafe { &*context.cast::<Host>() };
    host.sent.fetch_add(len as u64, Ordering::Relaxed);
    0
}

/// # Safety
///
/// As [`recv`].
unsafe extern "C" fn close(context: *mut c_void) {
    let host = unsafe { &*context.cast::<Host>() };
    host.closed.store(true, Ordering::Relaxed);
}

/// # Safety
///
/// As [`recv`]; consumes the leaked reference.
unsafe extern "C" fn release(context: *mut c_void) {
    drop(unsafe { Arc::from_raw(context.cast::<Host>()) });
}

fn vtable(host: &Arc<Host>) -> BoreasDevice {
    BoreasDevice {
        context: Arc::into_raw(Arc::clone(host)).cast::<c_void>().cast_mut(),
        recv: Some(recv),
        send: Some(send),
        close: Some(close),
        release: Some(release),
        mtu: MTU,
    }
}

#[test]
fn a_packet_crosses_the_seam_within_its_allocation_budget() {
    let host = Arc::new(Host {
        closed: AtomicBool::new(false),
        sent: AtomicU64::new(0),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    let (allocations, elapsed) = runtime.block_on(async {
        let mut device = Device::new(vtable(&host)).expect("a complete vtable");
        let mut buf = vec![0u8; usize::from(MTU)];

        for _ in 0..WARM_UP {
            let len = device.recv(&mut buf).await.expect("a packet");
            device.send(&buf[..len]).await.expect("a write");
        }

        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let start = Instant::now();
        for _ in 0..PACKETS {
            let len = device.recv(&mut buf).await.expect("a packet");
            device.send(&buf[..len]).await.expect("a write");
        }
        (
            ALLOCATIONS.load(Ordering::Relaxed) - before,
            start.elapsed(),
        )
    });

    let per_packet = allocations as f64 / PACKETS as f64;
    let nanos = elapsed.as_nanos() as f64 / PACKETS as f64;
    println!("seam: {nanos:.0} ns/packet, {per_packet:.2} allocations/packet");

    // `send` completes when the packet is queued; the writer task delivers
    // it. Wait for the tail rather than assume the writer kept pace.
    let expected = (WARM_UP as u64 + PACKETS) * PACKET as u64;
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while host.sent.load(Ordering::Relaxed) < expected && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(
        host.sent.load(Ordering::Relaxed),
        expected,
        "every packet received was sent back whole"
    );
    // Integer totals: half a packet's worth of slack is the rounding.
    assert!(
        allocations <= BUDGET * PACKETS + PACKETS / 2,
        "{per_packet:.2} allocations per packet exceeds the budget of {BUDGET}"
    );
}

/// The descriptor device, as Android hands it over: no callbacks, the reactor
/// reads the descriptor itself. Same budget, and the time is what one syscall
/// per direction costs.
#[cfg(unix)]
#[test]
fn a_packet_crosses_the_descriptor_device_within_its_allocation_budget() {
    use std::os::unix::net::UnixDatagram;

    let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
    theirs.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let packet = vec![0x45u8; PACKET];

    let (allocations, elapsed) = runtime.block_on(async {
        let mut device = boreas_core::AndroidTun::from_owned_fd(
            theirs.into(),
            boreas_core::Mtu::new(MTU).unwrap(),
        )
        .expect("registers with the reactor");
        let mut buf = vec![0u8; usize::from(MTU)];
        // The far end echoes: every packet sent comes back to be received.
        for _ in 0..WARM_UP {
            ours.send(&packet).unwrap();
            let len = device.recv(&mut buf).await.expect("a packet");
            device.send(&buf[..len]).await.expect("a write");
            ours.recv(&mut buf).unwrap();
        }

        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let start = Instant::now();
        for _ in 0..PACKETS {
            ours.send(&packet).unwrap();
            let len = device.recv(&mut buf).await.expect("a packet");
            device.send(&buf[..len]).await.expect("a write");
            ours.recv(&mut buf).unwrap();
        }
        (
            ALLOCATIONS.load(Ordering::Relaxed) - before,
            start.elapsed(),
        )
    });

    let per_packet = allocations as f64 / PACKETS as f64;
    let nanos = elapsed.as_nanos() as f64 / PACKETS as f64;
    println!("descriptor: {nanos:.0} ns/packet, {per_packet:.2} allocations/packet");
    assert!(
        allocations <= BUDGET * PACKETS + PACKETS / 2,
        "{per_packet:.2} allocations per packet exceeds the budget of {BUDGET}"
    );
}
