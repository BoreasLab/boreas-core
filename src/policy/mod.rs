//! What a flow is allowed to do, and how that verdict is reached.
//!
//! Resolution and its provenance, the filter-list pipeline that turns list
//! text into rules, the engine that answers with them, and the demotion state
//! that records where interception stopped working.

pub(crate) mod demote;
pub(crate) mod dns;
pub(crate) mod filter;
pub(crate) mod rules;
pub(crate) mod upstream;
