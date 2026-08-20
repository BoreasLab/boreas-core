//! One function turns a C description into a [`TunnelConfig`], and it is the
//! only way in.
//!
//! Everything crossing the boundary is a primitive or a pointer, so every
//! invariant the core established by construction has to be re-established
//! here. That is the "parse, don't validate" boundary for this crate: after
//! [`BoreasConfig::parse`] the value is a `TunnelConfig` and nothing
//! downstream re-checks it, and before it nothing is built at all.

use std::{
    ffi::{CStr, c_char},
    net::SocketAddr,
    num::NonZeroUsize,
};

use boreas_core::{
    CaKeys, CaMaterial, Mtu, NatBehavior, StreamBudget, Trust, WireGuardConfig,
    api::{Ceilings, Documents, Egress, Filtering, Interception, Link, Resolver, TunnelConfig},
};

use crate::Status;

/// Which egress a [`BoreasConfig`] describes.
///
/// A tag plus the fields each arm needs, because C has no sum type worth
/// mirroring an enum onto. The invariant "only the fields this tag names are
/// read" cannot be expressed here, so it is enforced in one place — the match
/// in [`BoreasConfig::parse`] — rather than trusted at every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BoreasEgress {
    /// Out by the host's own routes. The ordinary content-blocker
    /// configuration, and the only one in which nothing is proxied.
    Direct = 0,
    /// A WireGuard peer, carrying whole IP packets.
    WireGuard = 1,
}

/// The cryptographic half of a WireGuard peer.
///
/// Keys are fixed-width arrays rather than pointers, so there is no length to
/// get wrong and no lifetime to outlive the call.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasWireGuard {
    /// `host:port` of the peer. Not part of the keys: a peer that roams keeps
    /// its keys and changes its address.
    pub endpoint: *const c_char,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    /// A pre-shared key, and whether there is one. C has no `Option`, so the
    /// flag is what distinguishes "no PSK" from "a PSK of thirty-two zeroes".
    pub preshared_key: [u8; 32],
    pub has_preshared_key: bool,
}

/// How much one tunnel may hold. Zero means "use the default for this field",
/// which is what lets a host set one ceiling without restating the rest.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BoreasCeilings {
    pub buffer_slices: usize,
    pub datagrams_per_flow: usize,
    pub terminated_connections: usize,
    pub associations: usize,
    pub inspected_addresses: usize,
    pub pending_reassemblies: usize,
}

/// One tunnel, described in C.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasConfig {
    pub egress: BoreasEgress,
    /// Read only when `egress` is [`BoreasEgress::WireGuard`].
    pub wireguard: BoreasWireGuard,
    /// What the host's own NAT does to a mapping. Read only when `egress` is
    /// [`BoreasEgress::Direct`]; a phone behind carrier-grade NAT and a
    /// desktop with a public address are the same code and different answers,
    /// and only the host can tell which.
    pub nat_behavior: BoreasNat,
    /// `host:port` of a DNS upstream to filter through, or null to forward
    /// queries untouched.
    pub resolver: *const c_char,
    /// Filter lists, as NUL-terminated UTF-8, and how many.
    pub lists: *const *const c_char,
    pub list_count: usize,
    /// Hosts to intercept, and how many. Zero means no interception at all,
    /// which is the configuration that needs no certificate authority.
    pub intercept_hosts: *const *const c_char,
    pub intercept_host_count: usize,
    /// Stored certificate authority material, or null to generate a fresh one.
    /// Both halves are required together.
    pub root_certificate: *const u8,
    pub root_certificate_len: usize,
    pub authority_keys: *const u8,
    pub authority_keys_len: usize,
    /// Whether an intercepting tunnel also rewrites HTML bodies.
    pub rewrite_documents: bool,
    /// The MTU configured on the TUN. **Set the TUN to this and tell this the
    /// same number**; see `api/platform.md`.
    pub mtu: u16,
    pub ceilings: BoreasCeilings,
}

/// RFC 4787 mapping behaviour, as the host observes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BoreasNat {
    EndpointIndependent = 0,
    AddressDependent = 1,
    AddressAndPortDependent = 2,
}

impl From<BoreasNat> for NatBehavior {
    fn from(value: BoreasNat) -> Self {
        match value {
            BoreasNat::EndpointIndependent => Self::EndpointIndependent,
            BoreasNat::AddressDependent => Self::AddressDependent,
            BoreasNat::AddressAndPortDependent => Self::AddressAndPortDependent,
        }
    }
}

/// Reads a NUL-terminated UTF-8 string.
///
/// # Safety
///
/// `pointer`, when non-null, must be NUL-terminated and live for the call.
unsafe fn owned(pointer: *const c_char) -> Result<Option<String>, Status> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller established the pointer is a live C string.
    let raw = unsafe { CStr::from_ptr(pointer) };
    raw.to_str()
        .map(|text| Some(text.to_owned()))
        .map_err(|_| Status::NotUtf8)
}

/// Reads an array of NUL-terminated UTF-8 strings.
///
/// # Safety
///
/// `pointer` must point at `count` live C strings, or `count` must be zero.
pub(crate) unsafe fn strings(
    pointer: *const *const c_char,
    count: usize,
) -> Result<Vec<String>, Status> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(Status::NullArgument);
    }
    // SAFETY: the caller established the array's length.
    let entries = unsafe { std::slice::from_raw_parts(pointer, count) };
    entries
        .iter()
        .map(|entry| unsafe { owned(*entry) }?.ok_or(Status::NullArgument))
        .collect()
}

/// Reads a byte slice, or `None` when either half is absent.
///
/// # Safety
///
/// `pointer` must point at `len` initialised bytes, or `len` must be zero.
unsafe fn bytes(pointer: *const u8, len: usize) -> Option<Vec<u8>> {
    if pointer.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller established the length.
    Some(unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec())
}

fn ceiling(value: usize, default: NonZeroUsize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(default)
}

impl BoreasCeilings {
    /// Built from the default and overwritten field by field, because
    /// `Ceilings` is `#[non_exhaustive]`: a ceiling this ABI predates keeps
    /// the core's default rather than failing to compile or reading zero.
    fn parse(self) -> Ceilings {
        let mut ceilings = Ceilings::default();
        ceilings.buffer_slices = ceiling(self.buffer_slices, ceilings.buffer_slices);
        ceilings.datagrams_per_flow = ceiling(self.datagrams_per_flow, ceilings.datagrams_per_flow);
        ceilings.terminated_connections =
            ceiling(self.terminated_connections, ceilings.terminated_connections);
        ceilings.associations = ceiling(self.associations, ceilings.associations);
        ceilings.inspected_addresses =
            ceiling(self.inspected_addresses, ceilings.inspected_addresses);
        ceilings.pending_reassemblies =
            ceiling(self.pending_reassemblies, ceilings.pending_reassemblies);
        ceilings
    }
}

impl BoreasConfig {
    /// The one boundary a C description crosses to become a configuration.
    ///
    /// O(total string length): every string is copied once, because nothing
    /// the host passed may be assumed to outlive the call.
    ///
    /// # Safety
    ///
    /// Every non-null pointer in `self` must be live and correctly sized for
    /// the duration of the call.
    pub unsafe fn parse(self) -> Result<TunnelConfig, Status> {
        let egress = match self.egress {
            BoreasEgress::Direct => Egress::Direct {
                nat_behavior: self.nat_behavior.into(),
            },
            BoreasEgress::WireGuard => {
                let endpoint = unsafe { owned(self.wireguard.endpoint) }?
                    .ok_or(Status::NullArgument)?
                    .parse::<SocketAddr>()
                    .map_err(|_| Status::Config)?;
                Egress::WireGuard {
                    peer: endpoint,
                    config: WireGuardConfig {
                        private_key: self.wireguard.private_key,
                        peer_public_key: self.wireguard.peer_public_key,
                        // The flag, not a zero test: a key of thirty-two zeroes
                        // is a key a host may legitimately have configured.
                        preshared_key: self
                            .wireguard
                            .has_preshared_key
                            .then_some(self.wireguard.preshared_key),
                        // A keepalive is what keeps a NAT mapping alive on a
                        // handset that is idle in a pocket; 25 s is the
                        // interval WireGuard's own clients use.
                        persistent_keepalive: Some(25),
                        // The tunnel is narrower than the link by whatever the
                        // peer encapsulates, and the core answers the
                        // difference with a Packet Too Big.
                        inner_mtu: Mtu::new(self.mtu).map_err(|_| Status::Config)?,
                    },
                }
            }
        };

        let resolver = match unsafe { owned(self.resolver) }? {
            None => Resolver::Passthrough,
            Some(address) => Resolver::Local {
                upstream: boreas_core::api::Upstream::Do53 {
                    resolver: address.parse().map_err(|_| Status::Config)?,
                },
            },
        };

        let hosts = unsafe { strings(self.intercept_hosts, self.intercept_host_count) }?;
        let interception = if hosts.is_empty() {
            None
        } else {
            // Both halves together or neither: a certificate with no keys is
            // not a partially restored authority, it is a host that wrote one
            // secure-storage slot and not the other.
            let stored = match (
                unsafe { bytes(self.root_certificate, self.root_certificate_len) },
                unsafe { bytes(self.authority_keys, self.authority_keys_len) },
            ) {
                (Some(certificate), Some(keys)) => Some(
                    CaMaterial::from_parts(certificate, CaKeys::from_bytes(keys))
                        .map_err(|_| Status::Authority)?,
                ),
                (None, None) => None,
                _ => return Err(Status::Config),
            };
            Some(Interception {
                hosts,
                trust: stored.map_or(Trust::Generate, Trust::Restore),
                documents: self.rewrite_documents.then(|| Documents {
                    budget: StreamBudget::default(),
                }),
            })
        };

        Ok(TunnelConfig {
            egress,
            resolver,
            filtering: Filtering {
                lists: unsafe { strings(self.lists, self.list_count) }?,
                interception,
            },
            link: Link {
                mtu: Mtu::new(self.mtu).map_err(|_| Status::Config)?,
                ..Link::default()
            },
            ceilings: self.ceilings.parse(),
        })
    }
}
