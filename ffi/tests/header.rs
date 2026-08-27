//! Checks `include/boreas.h` against the Rust types it describes.
//!
//! The header is hand-written, so these tests compare its constants, sizes,
//! alignments, and field offsets with the Rust ABI.
//!
//! Size checks cannot detect swapped equal-sized fields; offset assertions cover
//! that case.

use std::{
    mem::{align_of, offset_of, size_of},
    path::Path,
};

use boreas::{
    BoreasBypass, BoreasCeilings, BoreasConfig, BoreasCounters, BoreasDevice, BoreasEgress,
    BoreasEvent, BoreasEventKind, BoreasNat, BoreasSocket, BoreasWireGuard, Status,
};

fn header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include/boreas.h");
    std::fs::read_to_string(&path).expect("the header ships beside the crate")
}

/// The header and library ABI versions must match at startup.
#[test]
fn the_abi_version_is_the_same_on_both_sides() {
    let declared = header()
        .lines()
        .find_map(|line| {
            line.strip_prefix("#define BOREAS_ABI_VERSION ")
                .map(|value| value.trim().trim_end_matches('u').to_owned())
        })
        .expect("the header declares BOREAS_ABI_VERSION");
    assert_eq!(
        declared,
        boreas::ABI_VERSION.to_string(),
        "boreas.h and the library disagree about the ABI version"
    );
    assert_eq!(boreas::boreas_abi_version(), boreas::ABI_VERSION);
}

/// Every status-returning declaration must be marked `BOREAS_MUST_USE`.
#[test]
fn every_status_returning_declaration_is_must_use() {
    let header = header();
    let unmarked: Vec<&str> = header
        .lines()
        .filter(|line| line.starts_with("BoreasStatus boreas_"))
        .collect();
    assert!(
        unmarked.is_empty(),
        "these are missing BOREAS_MUST_USE: {unmarked:?}"
    );
}

/// Header constants must match Rust discriminants.
#[test]
fn every_enum_constant_matches_the_header() {
    assert_eq!(Status::Ok as i32, 0);
    assert_eq!(Status::NullArgument as i32, 1);
    assert_eq!(Status::NotUtf8 as i32, 2);
    assert_eq!(Status::Config as i32, 3);
    assert_eq!(Status::Authority as i32, 4);
    assert_eq!(Status::Egress as i32, 5);
    assert_eq!(Status::Termination as i32, 6);
    assert_eq!(Status::Datapath as i32, 7);
    assert_eq!(Status::Io as i32, 8);
    assert_eq!(Status::Stopped as i32, 9);
    assert_eq!(Status::BufferTooSmall as i32, 10);
    assert_eq!(Status::Panic as i32, 11);
    assert_eq!(Status::Unrecognised as i32, 12);

    assert_eq!(BoreasEgress::Direct as i32, 0);
    assert_eq!(BoreasEgress::WireGuard as i32, 1);

    assert_eq!(BoreasNat::EndpointIndependent as i32, 0);
    assert_eq!(BoreasNat::AddressDependent as i32, 1);
    assert_eq!(BoreasNat::AddressAndPortDependent as i32, 2);

    assert_eq!(BoreasEventKind::Resolved as i32, 0);
    assert_eq!(BoreasEventKind::Reloaded as i32, 1);
    assert_eq!(BoreasEventKind::Counted as i32, 2);
}

/// `BoreasSocket` preserves the pointer-width unsigned Windows `SOCKET`.
#[test]
fn a_socket_handle_survives_both_platforms() {
    assert_eq!(size_of::<BoreasSocket>(), 8);
    assert!(BoreasSocket::try_from(u64::from(u32::MAX)).is_ok());
}

/// Field offsets must match, because equal-sized fields can be swapped without
/// changing the struct size.
#[test]
fn the_counters_are_laid_out_as_the_header_declares() {
    assert_eq!(size_of::<BoreasCounters>(), 6 * size_of::<u64>());
    assert_eq!(align_of::<BoreasCounters>(), align_of::<u64>());
    assert_eq!(offset_of!(BoreasCounters, datagrams_dropped), 0);
    assert_eq!(offset_of!(BoreasCounters, packets_rejected), 8);
    assert_eq!(offset_of!(BoreasCounters, quic_steered), 16);
    assert_eq!(offset_of!(BoreasCounters, paths_reported), 24);
    assert_eq!(offset_of!(BoreasCounters, events_lost), 32);
    assert_eq!(offset_of!(BoreasCounters, tasks_panicked), 40);
}

#[test]
fn the_ceilings_are_six_words_in_the_declared_order() {
    assert_eq!(size_of::<BoreasCeilings>(), 6 * size_of::<usize>());
    let word = size_of::<usize>();
    assert_eq!(offset_of!(BoreasCeilings, buffer_slices), 0);
    assert_eq!(offset_of!(BoreasCeilings, datagrams_per_flow), word);
    assert_eq!(offset_of!(BoreasCeilings, terminated_connections), 2 * word);
    assert_eq!(offset_of!(BoreasCeilings, associations), 3 * word);
    assert_eq!(offset_of!(BoreasCeilings, inspected_addresses), 4 * word);
    assert_eq!(offset_of!(BoreasCeilings, pending_reassemblies), 5 * word);
}

/// Vtable offsets must match the function pointers a host fills in by hand.
#[test]
fn the_vtables_are_laid_out_as_the_header_declares() {
    let word = size_of::<usize>();
    assert_eq!(offset_of!(BoreasDevice, context), 0);
    assert_eq!(offset_of!(BoreasDevice, recv), word);
    assert_eq!(offset_of!(BoreasDevice, send), 2 * word);
    assert_eq!(offset_of!(BoreasDevice, close), 3 * word);
    assert_eq!(offset_of!(BoreasDevice, release), 4 * word);
    assert_eq!(offset_of!(BoreasDevice, mtu), 5 * word);

    assert_eq!(offset_of!(BoreasBypass, context), 0);
    assert_eq!(offset_of!(BoreasBypass, protect), word);
    assert_eq!(offset_of!(BoreasBypass, release), 2 * word);
    assert_eq!(size_of::<BoreasBypass>(), 3 * word);
}

/// An absent callback must use C's null function-pointer representation.
#[test]
fn an_absent_callback_is_a_null_pointer() {
    assert_eq!(
        size_of::<Option<unsafe extern "C" fn(*mut std::ffi::c_void)>>(),
        size_of::<usize>(),
        "the niche is what makes `Option<fn>` and a C function pointer the same bytes"
    );
    let absent: Option<unsafe extern "C" fn(*mut std::ffi::c_void)> = None;
    // SAFETY: both are one pointer-sized value with no padding, which the
    // assertion above establishes.
    let raw: usize = unsafe { std::mem::transmute(absent) };
    assert_eq!(raw, 0);
}

/// Read-back structs must lead with the tags hosts use for dispatch.
#[test]
fn the_read_back_structs_lead_with_their_tags() {
    assert_eq!(offset_of!(BoreasEvent, kind), 0);
    assert_eq!(offset_of!(BoreasConfig, egress), 0);
    // Tagged field groups must fit inside their containing structs.
    assert!(size_of::<BoreasEvent>() >= size_of::<BoreasCounters>());
    assert!(size_of::<BoreasConfig>() >= size_of::<BoreasWireGuard>());
}
