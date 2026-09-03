//! `boreas_tunnel_start_fd`, driven as an Android host would drive it: a
//! descriptor handed over, no device callbacks, and the bypass accounted for.
#![cfg(unix)]

use std::{
    ffi::{CString, c_void},
    os::{fd::IntoRawFd, unix::net::UnixDatagram},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use boreas::{
    BoreasBypass, BoreasConfig, BoreasEgress, BoreasTunnel, Status, boreas_tunnel_free,
    boreas_tunnel_shutdown, boreas_tunnel_start_fd,
};

struct Host {
    protected: AtomicUsize,
    released: AtomicUsize,
}

/// # Safety
///
/// `context` is the `Arc<Host>` leaked by [`bypass`].
unsafe extern "C" fn protect(context: *mut c_void, _socket: i64) -> i32 {
    let host = unsafe { &*context.cast::<Host>() };
    host.protected.fetch_add(1, Ordering::Relaxed);
    0
}

/// # Safety
///
/// As [`protect`]; consumes the leaked reference.
unsafe extern "C" fn release(context: *mut c_void) {
    let host = unsafe { Arc::from_raw(context.cast::<Host>()) };
    host.released.fetch_add(1, Ordering::Relaxed);
}

fn bypass(host: &Arc<Host>) -> BoreasBypass {
    BoreasBypass {
        context: Arc::into_raw(Arc::clone(host)).cast::<c_void>().cast_mut(),
        protect: Some(protect),
        release: Some(release),
    }
}

fn config(lists: &[*const std::ffi::c_char], resolver: *const std::ffi::c_char) -> BoreasConfig {
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

/// IPv4/UDP from 192.0.2.1:1234 to 198.51.100.2:9999, no payload.
fn udp_frame() -> [u8; 28] {
    [
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
        0xd2, 0x27, 0x0f, 0x00, 0x08, 0, 0,
    ]
}

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

#[test]
fn a_descriptor_tunnel_reads_the_descriptor_and_closes_it_after_free() {
    let host = Arc::new(Host {
        protected: AtomicUsize::new(0),
        released: AtomicUsize::new(0),
    });
    let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
    let resolver = CString::new("127.0.0.1:53").unwrap();
    let list = CString::new("||ads.example^").unwrap();
    let lists = [list.as_ptr()];

    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    let status = unsafe {
        boreas_tunnel_start_fd(
            &config(&lists, resolver.as_ptr()),
            theirs.into_raw_fd(),
            1400,
            &bypass(&host),
            &mut handle,
        )
    };
    assert_eq!(status, Status::Ok);
    assert!(!handle.is_null());

    // A datagram on the descriptor reaches the datapath: a Direct egress opens
    // a socket for it, which is what the bypass is asked to protect.
    ours.send(&udp_frame()).expect("the far end reads");
    assert!(
        eventually(|| host.protected.load(Ordering::Relaxed) >= 1),
        "the packet read from the descriptor was relayed"
    );

    assert_eq!(unsafe { boreas_tunnel_shutdown(handle) }, Status::Ok);
    assert_eq!(unsafe { boreas_tunnel_free(handle) }, Status::Ok);
    assert_eq!(host.released.load(Ordering::Relaxed), 1, "the bypass, once");
    // The descriptor was ours to close, and it is closed.
    assert!(
        eventually(|| ours.send(b"after").is_err()),
        "the far end of the pair is gone"
    );
}

#[test]
fn a_refused_start_still_owns_and_closes_the_descriptor() {
    let host = Arc::new(Host {
        protected: AtomicUsize::new(0),
        released: AtomicUsize::new(0),
    });
    let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
    let empty: [*const std::ffi::c_char; 0] = [];

    let mut handle: *mut BoreasTunnel = ptr::null_mut();
    // An MTU below the IPv6 minimum: refused before a runtime exists.
    let status = unsafe {
        boreas_tunnel_start_fd(
            &config(&empty, ptr::null()),
            theirs.into_raw_fd(),
            1000,
            &bypass(&host),
            &mut handle,
        )
    };
    assert_eq!(status, Status::Config);
    assert!(handle.is_null());
    assert_eq!(host.released.load(Ordering::Relaxed), 1);
    assert!(ours.send(b"after").is_err(), "closed on the way out");
}
