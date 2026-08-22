//! The C boundary, and the Android boundary on top of it.
//!
//! [`boreas_core::api`] is a Rust-to-Rust contract: a host implements
//! `AsyncDevice` and `TunnelBypass`, hands over a `TunnelConfig`, and awaits a
//! `Tunnel`. Every consumer this project actually has is a Kotlin or a C#
//! application, none of which can implement an async Rust trait or await a
//! Rust future. This crate is the layer that turns that contract into one two
//! managed runtimes can hold.
//!
//! # Three things are lost at this boundary, and each one has an answer here
//!
//! **Types.** Everything crossing is a primitive, a pointer, or a
//! `#[repr(C)]` product. The invariants the core spent so much effort making
//! unrepresentable cannot travel, so they are re-established on this side: one
//! function turns a C configuration into a [`boreas_core::api::TunnelConfig`],
//! and that function is the only way in. A configuration that fails to parse
//! is [`Status::Config`] before anything is built.
//!
//! **Totality.** A C caller has no `Result`, so every entry point returns a
//! [`Status`] and writes its output through an out-parameter. `Status::Ok` is
//! zero, so the C idiom `if (boreas_...(...)) { fail; }` reads correctly.
//!
//! **Unwinding.** A panic that reaches an `extern "C"` frame aborts the
//! process — the host's whole application, on a device where the tunnel is one
//! feature of it. Since Rust 1.81 that abort is defined rather than undefined,
//! which makes it predictable and no less fatal. Nothing here is allowed to
//! unwind: [`boundary`] is the single combinator every entry point is written
//! in, and it catches.
//!
//! # What the host still owes
//!
//! The two obligations in `api/platform.md` do not go away; they change shape
//! into [`BoreasDevice`] and [`BoreasBypass`], two vtables of function
//! pointers. Both are called from Tokio worker threads, so **the host's
//! callbacks must be safe to call from any thread**, and that requirement is
//! the load-bearing half of every `unsafe impl Send` in this crate.
//!
//! # Scope
//!
//! Egress is [`BoreasEgress`]: direct, or a WireGuard peer. Those are what M1
//! gates on — "a working single-interface WireGuard client on Android and
//! Windows" — and the proxy egresses are deliberately not mirrored yet, because
//! six VLESS transports crossing as C structs is a surface to design once the
//! platforms are real rather than twice.

#![deny(unsafe_op_in_unsafe_fn)]

mod config;
mod seam;
mod status;
mod tunnel;

/// The Android bypass. Compiled only there, because it is the only platform
/// whose obligation is a method on a managed object rather than a socket
/// option, and the only one that needs a JVM to satisfy it.
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
