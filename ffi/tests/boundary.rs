//! The C entry points, driven exactly as a host drives them.
//!
//! The `rlib` target lets these entry points run in-process, where null
//! pointers, caught panics, short buffers, and callback lifetimes are testable.

use std::{
    ffi::{CString, c_char, c_void},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use boreas::{
    BoreasBypass, BoreasConfig, BoreasDevice, BoreasEgress, BoreasEvent, BoreasEventKind,
    BoreasTunnel, Status, boreas_tunnel_authority, boreas_tunnel_free, boreas_tunnel_next_event,
    boreas_tunnel_reload, boreas_tunnel_shutdown, boreas_tunnel_start,
};

/// What the host's callbacks do, and a record of what was asked of them.
///
/// Stands in for a `VpnService` or a Wintun session: the device blocks until it
/// is told to stop, which is what a real TUN read does, and the bypass counts
/// the sockets it was asked to protect.
struct Host {
    /// Set when the device should stop blocking. A real host closes its file
    /// descriptor instead; the effect a caller sees is the same.
    closed: Arc<std::sync::atomic::AtomicBool>,
    protected: AtomicUsize,
    released: AtomicUsize,
    sent: AtomicUsize,
    polled: AtomicUsize,
}

impl Host {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            closed: Arc::default(),
            protected: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            sent: AtomicUsize::new(0),
            polled: AtomicUsize::new(0),
        })
    }
}

/// # Safety
///
/// `context` must be an `Arc<Host>` leaked by [`vtables`].
unsafe extern "C" fn recv(context: *mut c_void, _buf: *mut u8, _cap: usize) -> isize {
    let host = unsafe { &*context.cast::<Host>() };
    if host.closed.load(Ordering::Relaxed) {
        return -5; // EIO: the interface went away
    }
    // Return zero after a bounded wait so Boreas retries without blocking a
    // cooperative host indefinitely.
    std::thread::sleep(std::time::Duration::from_millis(5));
    host.polled.fetch_add(1, Ordering::Relaxed);
    0
}

/// # Safety
///
/// As [`recv`].
unsafe extern "C" fn send(context: *mut c_void, _buf: *const u8, _len: usize) -> isize {
    let host = unsafe { &*context.cast::<Host>() };
    host.sent.fetch_add(1, Ordering::Relaxed);
    0
}

/// # Safety
///
/// As [`recv`].
unsafe extern "C" fn protect(context: *mut c_void, _socket: i64) -> i32 {
    let host = unsafe { &*context.cast::<Host>() };
    host.protected.fetch_add(1, Ordering::Relaxed);
    0
}

/// Ends a blocked read, matching `close(fd)` for a real TUN.
///
/// # Safety
///
/// As [`recv`].
unsafe extern "C" fn close(context: *mut c_void) {
    let host = unsafe { &*context.cast::<Host>() };
    host.closed.store(true, Ordering::Relaxed);
}

/// # Safety
///
/// As [`recv`], and this consumes the leaked reference.
unsafe extern "C" fn release(context: *mut c_void) {
    let host = unsafe { Arc::from_raw(context.cast::<Host>()) };
    host.released.fetch_add(1, Ordering::Relaxed);
}

/// Builds two vtables, each owning one leaked reference to the host.
fn vtables(host: &Arc<Host>) -> (BoreasDevice, BoreasBypass) {
    let device = BoreasDevice {
        context: Arc::into_raw(Arc::clone(host)).cast::<c_void>().cast_mut(),
        recv: Some(recv),
        send: Some(send),
        close: Some(close),
        release: Some(release),
        mtu: 1400,
    };
    let bypass = BoreasBypass {
        context: Arc::into_raw(Arc::clone(host)).cast::<c_void>().cast_mut(),
        protect: Some(protect),
        release: Some(release),
    };
    (device, bypass)
}

/// A configuration that starts successfully with a resolver and one filter list.
fn config(lists: &[*const c_char], resolver: *const c_char) -> BoreasConfig {
    BoreasConfig {
        egress: BoreasEgress::Direct,
        wireguard: unsafe { std::mem::zeroed() },
        nat_behavior: boreas::BoreasNat::EndpointIndependent,
        resolver,
        lists: lists.as_ptr(),
        list_count: lists.len(),
        intercept_hosts: ptr::null(),
        intercept_host_count: 0,
        root_certificate: ptr::null(),
        root_certificate_len: 0,
        authority_keys: ptr::null(),
        authority_keys_len: 0,
        rewrite_documents: false,
        mtu: 1400,
        ceilings: boreas::BoreasCeilings::default(),
    }
}

/// Waits for a spawned task's observable effect instead of assuming scheduling
/// order.
fn eventually(ready: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    false
}

fn empty_event() -> BoreasEvent {
    BoreasEvent {
        kind: BoreasEventKind::Counted,
        blocked: false,
        name_len: 0,
        rule_len: 0,
        allowed: 0,
        blocked_rules: 0,
        inspected: 0,
        counters: boreas::BoreasCounters::default(),
    }
}

/// Verifies start, reload, shutdown, and exactly-once context release.
#[test]
fn a_tunnel_starts_reloads_and_stops_through_the_c_abi() {
    let host = Host::new();
    let (device, bypass) = vtables(&host);
    let resolver = CString::new("127.0.0.1:53").unwrap();
    let list = CString::new("||ads.example^").unwrap();
    let lists = [list.as_ptr()];

    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    let status = unsafe {
        boreas_tunnel_start(
            &config(&lists, resolver.as_ptr()),
            &device,
            &bypass,
            &mut handle,
        )
    };
    assert_eq!(status, Status::Ok, "the tunnel must start");
    assert!(!handle.is_null());

    // Reload reports the active rules without restarting the tunnel.
    let replacement = CString::new("||tracker.example^\n||other.example^").unwrap();
    let replacements = [replacement.as_ptr()];
    let mut event = empty_event();
    let status = unsafe {
        boreas_tunnel_reload(
            handle,
            replacements.as_ptr(),
            replacements.len(),
            &mut event,
        )
    };
    assert_eq!(status, Status::Ok);
    assert_eq!(event.kind, BoreasEventKind::Reloaded);
    assert_eq!(event.blocked_rules, 2, "both rules are in force");

    // Ensure the read loop ran before shutdown, which ends it through `close`.
    assert!(
        eventually(|| host.polled.load(Ordering::Relaxed) > 0),
        "a zero-length read must be asked again rather than forwarded as a packet"
    );

    // `free` calls `close`; a real host must stop the tunnel before tearing down
    // its interface or the blocked read and release callback can wait on each other.
    assert_eq!(unsafe { boreas_tunnel_shutdown(handle) }, Status::Ok);
    // Shutdown is idempotent.
    assert_eq!(unsafe { boreas_tunnel_shutdown(handle) }, Status::Ok);
    assert_eq!(unsafe { boreas_tunnel_free(handle) }, Status::Ok);

    assert_eq!(
        host.released.load(Ordering::Relaxed),
        2,
        "each context released exactly once: one device, one bypass"
    );
    assert_eq!(
        Arc::strong_count(&host),
        1,
        "and every leaked reference reclaimed, so nothing outlived the tunnel"
    );
}

/// A parked `next_event` reader must not block reload or shutdown.
#[test]
fn a_blocked_reader_delays_nothing_else() {
    let host = Host::new();
    let (device, bypass) = vtables(&host);
    let resolver = CString::new("127.0.0.1:53").unwrap();
    let list = CString::new("||ads.example^").unwrap();
    let lists = [list.as_ptr()];

    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    assert_eq!(
        unsafe {
            boreas_tunnel_start(
                &config(&lists, resolver.as_ptr()),
                &device,
                &bypass,
                &mut handle,
            )
        },
        Status::Ok
    );

    let parked = Sendable(handle);
    let reader = std::thread::spawn(move || {
        let handle = parked;
        let mut event = empty_event();
        // Reload publishes an event on this stream as well as returning one.
        loop {
            let status = unsafe {
                boreas_tunnel_next_event(
                    handle.0,
                    &mut event,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                )
            };
            if status != Status::Ok {
                return status;
            }
        }
    });
    // Let the reader enter the blocking call.
    std::thread::sleep(std::time::Duration::from_millis(150));

    let replacement = CString::new("||tracker.example^\n||other.example^").unwrap();
    let replacements = [replacement.as_ptr()];
    let mut event = empty_event();
    assert_eq!(
        unsafe {
            boreas_tunnel_reload(
                handle,
                replacements.as_ptr(),
                replacements.len(),
                &mut event,
            )
        },
        Status::Ok,
        "a reload must not wait for a reader that may never return"
    );
    assert_eq!(event.blocked_rules, 2);

    let (mut certificate_len, mut keys_len) = (0usize, 0usize);
    assert_eq!(
        unsafe {
            boreas_tunnel_authority(
                handle,
                ptr::null_mut(),
                0,
                &mut certificate_len,
                ptr::null_mut(),
                0,
                &mut keys_len,
            )
        },
        Status::Ok
    );
    assert_eq!(certificate_len, 0, "this tunnel does not intercept");

    // Shutdown closes the device read and releases the parked reader.
    assert_eq!(unsafe { boreas_tunnel_shutdown(handle) }, Status::Ok);
    assert_eq!(
        reader.join().expect("the reader thread must not panic"),
        Status::Stopped,
        "shutdown must release a parked reader"
    );
    assert_eq!(unsafe { boreas_tunnel_free(handle) }, Status::Ok);
    assert_eq!(host.released.load(Ordering::Relaxed), 2);
}

struct Sendable(*mut BoreasTunnel);
// SAFETY: the ABI's contract is that every entry point but `free` is callable
// from any thread concurrently, which is exactly what this test exercises.
unsafe impl Send for Sendable {}

/// Every entry point rejects required null arguments.
#[test]
fn every_entry_point_refuses_a_null_argument() {
    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    let device = BoreasDevice {
        context: ptr::null_mut(),
        recv: Some(recv),
        send: Some(send),
        close: None,
        release: None,
        mtu: 1400,
    };
    let bypass = BoreasBypass {
        context: ptr::null_mut(),
        protect: Some(protect),
        release: None,
    };

    assert_eq!(
        unsafe { boreas_tunnel_start(ptr::null(), &device, &bypass, &mut handle) },
        Status::NullArgument
    );
    let empty: [*const c_char; 0] = [];
    assert_eq!(
        unsafe {
            boreas_tunnel_start(
                &config(&empty, ptr::null()),
                ptr::null(),
                &bypass,
                &mut handle,
            )
        },
        Status::NullArgument
    );
    assert_eq!(
        unsafe {
            boreas_tunnel_start(
                &config(&empty, ptr::null()),
                &device,
                ptr::null(),
                &mut handle,
            )
        },
        Status::NullArgument
    );

    let mut event = empty_event();
    assert_eq!(
        unsafe {
            boreas_tunnel_next_event(
                ptr::null_mut(),
                &mut event,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
            )
        },
        Status::NullArgument
    );
    assert_eq!(
        unsafe { boreas_tunnel_reload(ptr::null_mut(), ptr::null(), 0, &mut event) },
        Status::NullArgument
    );
    let (mut certificate_len, mut keys_len) = (0usize, 0usize);
    assert_eq!(
        unsafe {
            boreas_tunnel_authority(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut certificate_len,
                ptr::null_mut(),
                0,
                &mut keys_len,
            )
        },
        Status::NullArgument
    );
    // Freeing null is the idempotent exception.
    assert_eq!(unsafe { boreas_tunnel_free(ptr::null_mut()) }, Status::Ok);
}

/// A refused configuration releases callback contexts before returning.
#[test]
fn a_refused_configuration_still_releases_what_it_was_handed() {
    let host = Host::new();
    let (device, bypass) = vtables(&host);
    // Filtering requires a resolver; without one, parsed lists cannot inspect
    // flows selected by DNS answers.
    let list = CString::new("||ads.example^").unwrap();
    let lists = [list.as_ptr()];

    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    let status =
        unsafe { boreas_tunnel_start(&config(&lists, ptr::null()), &device, &bypass, &mut handle) };
    assert_eq!(status, Status::Config);
    assert!(handle.is_null(), "nothing was allocated");
    assert_eq!(
        host.released.load(Ordering::Relaxed),
        2,
        "both contexts released on the failure path too"
    );
    assert_eq!(Arc::strong_count(&host), 1);
}

/// Rejects an MTU below IPv6's minimum before building the runtime.
#[test]
fn a_link_narrower_than_ipv6_permits_is_refused() {
    let host = Host::new();
    let (mut device, bypass) = vtables(&host);
    device.mtu = 576;
    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    let empty: [*const c_char; 0] = [];
    assert_eq!(
        unsafe { boreas_tunnel_start(&config(&empty, ptr::null()), &device, &bypass, &mut handle) },
        Status::Config
    );
    assert_eq!(host.released.load(Ordering::Relaxed), 2);
}
