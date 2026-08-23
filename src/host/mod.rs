//! The runtime edge: OS handles, and the tokio shell that drives the pure
//! core against them.
//!
//! `device` is the raw-IP seam, `platform` the byte shims over Android's and
//! Windows's handles, and `shell` the reactor that interprets [`Datapath`]
//! decisions as reads, writes, timers, and spawned work.
//!
//! [`Datapath`]: crate::Datapath

pub(crate) mod device;
pub(crate) mod platform;
pub(crate) mod shell;
