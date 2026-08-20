//! `include/boreas.h` against the types it describes.
//!
//! **A hand-written header is a second source of truth, and this is the thing
//! that stops it becoming a wrong one.** The header is hand-written on purpose
//! — a generator reproduces layouts and none of the contracts, and the
//! contracts are the whole value of that file — so the layouts are checked
//! here instead.
//!
//! What this can check is what a C compiler would disagree about: the size and
//! alignment of every struct that crosses, and the discriminant of every enum
//! constant. What it cannot check is a field *reordered* between two members of
//! the same size, so every struct below also asserts its field offsets.

use std::mem::{align_of, offset_of, size_of};

use boreas::{
    BoreasBypass, BoreasCeilings, BoreasConfig, BoreasCounters, BoreasDevice, BoreasEgress,
    BoreasEvent, BoreasEventKind, BoreasNat, BoreasSocket, BoreasWireGuard, Status,
};

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
