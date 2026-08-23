//! Interception: what happens to a connection this proxy terminates.
//!
//! `session` decides between splicing, blocking, and inspecting; the rest is
//! the inspecting path — the certificate authority, the ClientHello sent
//! upstream, the HTTP exchange, and the body rewriter.

pub(crate) mod ca;
pub(crate) mod exchange;
pub(crate) mod mirror;
pub(crate) mod mitm;
pub(crate) mod rewrite;
pub(crate) mod session;
