//! Converts a C configuration into a [`TunnelConfig`]. This is the only
//! construction path into the core.
//!
//! C provides primitives and pointers, so this boundary rebuilds the core's
//! invariants once. After [`BoreasConfig::parse`] succeeds, downstream code
//! receives a `TunnelConfig` and performs no second validation.

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

/// Selects the egress described by a [`BoreasConfig`].
///
/// The tag selects which configuration fields are read. C cannot express that
/// relationship, so [`BoreasConfig::parse`] enforces it in one match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BoreasEgress {
    /// Sends traffic through the host's routes.
    Direct = 0,
    /// Sends whole IP packets through a WireGuard peer.
    WireGuard = 1,
}

/// Cryptographic configuration for a WireGuard peer.
///
/// Fixed-width arrays carry their lengths in the type and do not borrow host
/// memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasWireGuard {
    /// Peer address in `host:port` form. Its address may change independently
    /// of the keys.
    pub endpoint: *const c_char,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    /// Optional pre-shared key. The flag distinguishes absence from a key of
    /// thirty-two zero bytes.
    pub preshared_key: [u8; 32],
    pub has_preshared_key: bool,
}

/// Per-tunnel resource ceilings. Zero selects the core default for that field.
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

/// One tunnel described by the C ABI.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BoreasConfig {
    pub egress: BoreasEgress,
    /// Read when `egress` is [`BoreasEgress::WireGuard`].
    pub wireguard: BoreasWireGuard,
    /// NAT mapping behavior observed by the host. Read when `egress` is
    /// [`BoreasEgress::Direct`].
    pub nat_behavior: BoreasNat,
    /// DNS upstream in `host:port` form, or null for passthrough queries.
    pub resolver: *const c_char,
    /// NUL-terminated UTF-8 filter lists and their count.
    pub lists: *const *const c_char,
    pub list_count: usize,
    /// Intercepted hosts and their count. Zero disables interception and needs
    /// no certificate authority.
    pub intercept_hosts: *const *const c_char,
    pub intercept_host_count: usize,
    /// Stored certificate authority material, or null to generate it. Both
    /// halves must be supplied together.
    pub root_certificate: *const u8,
    pub root_certificate_len: usize,
    pub authority_keys: *const u8,
    pub authority_keys_len: usize,
    /// Enables HTML body rewriting for an intercepting tunnel.
    pub rewrite_documents: bool,
    /// MTU configured on the TUN. Set the TUN and this field to the same value;
    /// see `api/obligations.md`.
    pub mtu: u16,
    pub ceilings: BoreasCeilings,
}

/// RFC 4787 mapping behavior observed by the host.
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

/// Copies a NUL-terminated UTF-8 string.
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

/// Copies an array of NUL-terminated UTF-8 strings.
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

/// Copies a byte slice, or returns `None` when either half is absent.
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
    /// Starts with core defaults and overwrites fields known to this ABI.
    /// `Ceilings` is `#[non_exhaustive]`, so newer fields retain their defaults
    /// when an older ABI parses the structure.
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
    /// Converts the borrowed C description into an owned configuration.
    ///
    /// O(total string length): every string is copied once because host memory
    /// is valid only for this call.
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
                        // Presence is explicit because an all-zero key is valid.
                        preshared_key: self
                            .wireguard
                            .has_preshared_key
                            .then_some(self.wireguard.preshared_key),
                        // Keepalive maintains an idle NAT mapping.
                        persistent_keepalive: Some(25),
                        // The inner MTU excludes WireGuard encapsulation.
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
            // Both halves must be restored together; one half indicates an
            // incomplete secure-storage write.
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
