//! The C boundary, and the Android boundary on top of it.
//!
//! The core API uses async Rust traits, while Kotlin and C# consume `repr(C)`
//! values, status codes, and out-parameters. This crate converts between those
//! contracts and rebuilds core invariants at the boundary.
//!
//! # Boundary guarantees
//!
//! C inputs are parsed once into [`boreas_core::api::TunnelConfig`]. Invalid
//! configuration returns [`Status::Config`] before runtime construction.
//!
//! Every entry point returns [`Status`] and writes outputs through
//! out-parameters. `Status::Ok` is zero for C's conventional failure check.
//!
//! Panics must not cross an `extern "C"` frame. [`boundary`] catches them for
//! every entry point.
//!
//! # What the host still owes
//!
//! [`BoreasDevice`] and [`BoreasBypass`] are called from Tokio worker threads.
//! Host callbacks must therefore be safe to call from any thread.
//!
//! # Scope
//!
//! [`BoreasEgress`] exposes direct and WireGuard egress. Proxy egresses are not
//! part of this C surface.

#![deny(unsafe_op_in_unsafe_fn)]

/// The version of the C ABI this library implements.
///
/// Bump this when a symbol, field, or call meaning changes. Keep it synchronized
/// with `BOREAS_ABI_VERSION` in `ffi/include/boreas.h`; `ffi/tests/header.rs`
/// checks the pair.
pub const ABI_VERSION: u32 = 1;

/// The ABI version this library was built as.
///
/// Hosts should compare it with `BOREAS_ABI_VERSION` at startup.
#[unsafe(no_mangle)]
pub extern "C" fn boreas_abi_version() -> u32 {
    ABI_VERSION
}

mod config;
mod seam;
mod status;
mod tunnel;

/// Android bypass using the managed-object method required by that platform.
#[cfg(target_os = "android")]
pub mod android;

pub use config::{BoreasCeilings, BoreasConfig, BoreasEgress, BoreasNat, BoreasWireGuard};
pub use seam::{BoreasBypass, BoreasDevice, BoreasSocket};
pub use status::{Status, boundary};
pub use tunnel::{
    BoreasCounters, BoreasEvent, BoreasEventKind, BoreasTunnel, boreas_tunnel_authority,
    boreas_tunnel_free, boreas_tunnel_next_event, boreas_tunnel_reload, boreas_tunnel_shutdown,
    boreas_tunnel_start,
};
