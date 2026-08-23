//! L3: what arrives from and departs to the device as raw IP.
//!
//! This layer owns packet validity, fragment reassembly, MTU and ICMP Packet
//! Too Big, and the UDP flow table. Nothing above it sees a packet.

pub(crate) mod packet;
pub(crate) mod path;
pub(crate) mod reassembly;
pub(crate) mod udp;
