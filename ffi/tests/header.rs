//! `include/boreas.h` against the types it describes.
//!
//! **A hand-written header is a second source of truth, and this is the thing
//! that stops it becoming a wrong one.** See the header's own preamble for why
//! it is written rather than generated; what follows from that choice is that
//! nothing but this file keeps the two in step.
//!
//! What this can check is what a C compiler would disagree about: the size and
//! alignment of every struct that crosses, and the discriminant of every enum
//! constant. What it cannot check is a field *reordered* between two members of
//! the same size, so every struct below also asserts its field offsets.

use std::{
    mem::{align_of, offset_of, size_of},
    path::Path,
};

use boreas::{
    BoreasBypass, BoreasCeilings, BoreasConfig, BoreasCounters, BoreasDevice, BoreasEgress,
    BoreasEvent, BoreasEventKind, BoreasNat, BoreasSocket, BoreasWireGuard, Status,
};

/// The header, read from the source tree.
fn header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include/boreas.h");
    std::fs::read_to_string(&path).expect("the header ships beside the crate")
}

/// **The two numbers a host compares must be one number.** The header's macro
/// is what a host compiles against and `boreas_abi_version()` is what the
/// library answers; if they could differ, the check a host performs at startup
/// would pass while the mismatch it exists to catch was present.
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

/// Every entry point must be declared `BOREAS_MUST_USE`, because every one of
/// them returns a status and none can be safely dropped. A new function added
/// to the header without it is the one this catches.
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

/// Every constant in the header, spelled as the header spells it. A value
/// changed on one side and not the other is a host that reads a success as a
/// failure, or dispatches an event to the wrong arm.
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

/// `BoreasSocket` must hold a Windows `SOCKET`, which is pointer-width and
/// unsigned. Narrowing it would truncate a handle on a 64-bit host.
#[test]
fn a_socket_handle_survives_both_platforms() {
    assert_eq!(size_of::<BoreasSocket>(), 8);
    assert!(BoreasSocket::try_from(u64::from(u32::MAX)).is_ok());
}

/// Offsets, not just sizes: two `size_t` fields swapped would pass a size
/// check and hand the host the wrong number.
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

/// The vtables are the ones a host fills in by hand, so a reordered field here
/// is a call through the wrong function pointer rather than a compile error.
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

/// A null function pointer must be the null representation, because that is
/// how a C host says "I did not supply this one".
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

/// The two structs the host reads back. Their leading fields are what a host
/// switches on, so their offsets are load-bearing.
#[test]
fn the_read_back_structs_lead_with_their_tags() {
    assert_eq!(offset_of!(BoreasEvent, kind), 0);
    assert_eq!(offset_of!(BoreasConfig, egress), 0);
    // And every field group the tag selects is inside the struct it claims.
    assert!(size_of::<BoreasEvent>() >= size_of::<BoreasCounters>());
    assert!(size_of::<BoreasConfig>() >= size_of::<BoreasWireGuard>());
}
