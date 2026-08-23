//! L4: transport state turned into a `Stream` or a `DatagramFlow`.
//!
//! Local TCP termination and its reactor bridge live here, as does the
//! datagram relay that carries UDP when an egress accepts flows rather than
//! packets. Above this line nothing branches on the transport underneath.

pub(crate) mod relay;
pub(crate) mod stream;
pub(crate) mod terminate;
