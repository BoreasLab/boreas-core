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
/// task per call measured 4; one that recycles its buffers owes none.
const BUDGET: u64 = 4;

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

    assert_eq!(
        host.sent.load(Ordering::Relaxed),
        (WARM_UP as u64 + PACKETS) * PACKET as u64,
        "every packet received was sent back whole"
    );
    assert!(
        per_packet.round() as u64 <= BUDGET,
        "{per_packet:.2} allocations per packet exceeds the budget of {BUDGET}"
    );
}
