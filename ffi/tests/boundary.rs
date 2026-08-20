//! The C entry points, driven exactly as a host drives them.
//!
//! **The `rlib` crate type exists for this.** A `cdylib` alone would leave
//! every one of these functions reachable only from a language this repository
//! does not build, and the whole point of the boundary is that its failure
//! modes — a null pointer, a caught panic, a short buffer, a context freed
//! while a callback is inside it — are the ones nobody notices until a device
//! is in the loop.

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
    BoreasTunnel, Status, boreas_tunnel_authority, boreas_tunnel_next_event, boreas_tunnel_reload,
    boreas_tunnel_start, boreas_tunnel_stop,
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
}

impl Host {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            closed: Arc::default(),
            protected: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            sent: AtomicUsize::new(0),
        })
    }
}

/// # Safety
///
/// `context` must be an `Arc<Host>` leaked by [`vtables`].
unsafe extern "C" fn recv(context: *mut c_void, _buf: *mut u8, _cap: usize) -> isize {
    let host = unsafe { &*context.cast::<Host>() };
    // A TUN read blocks until a packet arrives; this one blocks until the host
    // says the interface is gone, which is what `close(fd)` does to a real one.
    while !host.closed.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    -5 // EIO: the interface went away
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

/// Ends any blocked read, exactly as `close(fd)` does to a real TUN. Called
/// while `recv` may be sitting in its loop, which is the whole contract.
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

/// Two vtables over one `Host`, each holding its own leaked reference so each
/// `release` reclaims exactly one.
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

/// A configuration that starts: filtering needs a resolver it can answer from,
/// which is what `ConfigError::NothingToFilter` exists to say.
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

/// **The whole lifecycle, through the ABI a host actually calls.** Start,
/// reload, stop — and the two host contexts released exactly once each, which
/// is the property that separates a shim from a leak.
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

    // A reload answers with what is now in force, without restarting anything.
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

    // **No closing from the test.** A real host stops the tunnel first and
    // tears its interface down afterwards, which is exactly the ordering that
    // deadlocks if `release` is the only signal: the read waits for the host
    // and the host waits for `release`. `stop` calls `close` for it.
    assert_eq!(unsafe { boreas_tunnel_stop(handle) }, Status::Ok);

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

/// A null argument is a caller's bug, and it must be told rather than
/// dereferenced.
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
    // Freeing null is the one exception: a host that unconditionally frees an
    // initialised pointer is doing the right thing, not a wrong one.
    assert_eq!(unsafe { boreas_tunnel_stop(ptr::null_mut()) }, Status::Ok);
}

/// A configuration that cannot be a tunnel is refused before anything is
/// built, and the host's contexts are still released — a failure that leaked
/// them would be a failure the host could not retry from.
#[test]
fn a_refused_configuration_still_releases_what_it_was_handed() {
    let host = Host::new();
    let (device, bypass) = vtables(&host);
    // Filtering with no resolver: on a packet egress a flow is selected for
    // inspection because a DNS answer named its address, so a tunnel that
    // never sees a question can filter nothing.
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

/// An MTU below the IPv6 minimum is configuration, not a runtime failure, and
/// is caught before a runtime is even built.
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
