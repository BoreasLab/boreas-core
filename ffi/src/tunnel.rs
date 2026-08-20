//! The handle a host holds, and the five calls it makes on it.
//!
//! Every entry point here has the same shape: `boundary` around a closure that
//! borrows its arguments, does the work, and writes an out-parameter. Nothing
//! returns a pointer the host must free except the handle itself, and nothing
//! hands out a string it owns — strings are copied into buffers the caller
//! supplied, which removes an entire class of question about who frees what.

use std::{ffi::c_char, time::Duration};

use boreas_core::api::{Event, Platform, Tunnel};

use crate::{
    Status,
    config::BoreasConfig,
    seam::{BoreasBypass, BoreasDevice, Bypass, BypassGuard, Device},
    status::{borrow, borrow_mut},
};

/// How long `stop` waits for a device read already inside the host's callback.
///
/// Short on purpose: the tunnel has stopped carrying traffic by then, so a
/// `recv` still blocked is one waiting for a packet that is not coming.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// A running tunnel, and the runtime it runs on.
///
/// **The runtime lives here because a C caller has no executor.** Every entry
/// point that awaits blocks on this one, so the host's calling thread is the
/// one that waits — which is what a Kotlin coroutine dispatcher or a C# task
/// already knows how to arrange.
pub struct BoreasTunnel {
    runtime: tokio::runtime::Runtime,
    /// `None` once stopped. A stopped tunnel is still a valid handle to free,
    /// and every other call on it answers [`Status::Stopped`] rather than
    /// finding a dangling pointer.
    inner: Option<Tunnel>,
    /// Releases the host's bypass context exactly once, after the tunnel that
    /// borrowed it is gone. Ordering is the point: dropping this before the
    /// tunnel would free a context a dialling task may still be inside.
    _bypass: BypassGuard,
}

/// Which of [`BoreasEvent`]'s field groups is meaningful.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BoreasEventKind {
    /// One name was decided. `blocked`, `name`, and `rule` are meaningful.
    Resolved = 0,
    /// Rules were reloaded. `allowed`, `blocked_rules`, and `inspected` are.
    Reloaded = 1,
    /// Aggregated counters since the previous one. `counters` is.
    Counted = 2,
}

/// Occurrences since the previous [`BoreasEventKind::Counted`].
///
/// A flat mirror of the core's counters. **Every field is a thing that went
/// wrong or was refused**, so a host can surface any non-zero one without
/// knowing what it means.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct BoreasCounters {
    pub datagrams_dropped: u64,
    pub packets_rejected: u64,
    pub quic_steered: u64,
    pub paths_reported: u64,
    pub events_lost: u64,
    /// A defect in Boreas rather than a condition of the network. Report it.
    pub tasks_panicked: u64,
}

/// One event, flattened.
///
/// A tag and every arm's fields side by side, rather than a union: a union
/// would save a few dozen bytes per event and cost every binding generator an
/// unsafe read. Only the fields [`Self::kind`] names carry meaning.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BoreasEvent {
    pub kind: BoreasEventKind,
    /// `Resolved`: whether the answer came from policy without leaving the
    /// device.
    pub blocked: bool,
    /// `Resolved`: the full byte length of the name, before truncation. Larger
    /// than what was written means the caller's buffer was too small.
    pub name_len: usize,
    /// `Resolved`: as `name_len`, for the rule. Zero when no rule decided it.
    pub rule_len: usize,
    pub allowed: usize,
    pub blocked_rules: usize,
    pub inspected: usize,
    pub counters: BoreasCounters,
}

impl BoreasEvent {
    fn empty(kind: BoreasEventKind) -> Self {
        Self {
            kind,
            blocked: false,
            name_len: 0,
            rule_len: 0,
            allowed: 0,
            blocked_rules: 0,
            inspected: 0,
            counters: BoreasCounters::default(),
        }
    }
}

/// Copies `text` into `buf` as a NUL-terminated string, returning the full
/// byte length of `text`.
///
/// **Truncates rather than failing**, and reports the length that would have
/// been needed. An event is a diagnostic; losing the tail of a very long name
/// is better than losing the event, and a caller that cares can compare the
/// reported length against its capacity.
///
/// # Safety
///
/// `buf`, when non-null, must be writable for `cap` bytes.
unsafe fn write_c_string(text: &str, buf: *mut c_char, cap: usize) -> usize {
    if buf.is_null() || cap == 0 {
        return text.len();
    }
    // One byte reserved for the terminator, always, so the result is a C
    // string even when the name did not fit.
    let taken = text.len().min(cap - 1);
    // Never split a UTF-8 character: a truncated name is a diagnostic, and a
    // host that decodes it must not be handed half a code point.
    let taken = (0..=taken)
        .rev()
        .find(|at| text.is_char_boundary(*at))
        .unwrap_or(0);
    // SAFETY: `taken < cap`, and the caller established `buf` is writable for
    // `cap` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), buf, taken);
        buf.add(taken).write(0);
    }
    text.len()
}

/// Starts a tunnel.
///
/// Writes the handle through `out` on success. On any failure nothing is
/// allocated and `out` is untouched — except that the host's `release`
/// callbacks are still called, so a context handed in is always accounted for.
///
/// # Safety
///
/// `config`, `device`, `bypass`, and `out` must be valid pointers, and every
/// pointer reachable from `config` must be live for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_start(
    config: *const BoreasConfig,
    device: *const BoreasDevice,
    bypass: *const BoreasBypass,
    out: *mut *mut BoreasTunnel,
) -> Status {
    crate::boundary(|| {
        let config = *borrow!(config);
        let device_ops = *borrow!(device);
        let bypass_ops = *borrow!(bypass);
        let out = borrow_mut!(out);

        // The guard is created first and dropped last, so a failure anywhere
        // below still releases the host's bypass context exactly once.
        let guard = BypassGuard::new(bypass_ops);
        let Some(device) = Device::new(device_ops) else {
            return Status::Config;
        };
        let Some(bypass) = Bypass::new(bypass_ops) else {
            return Status::Config;
        };
        // SAFETY: the caller's contract covers every pointer in `config`.
        let parsed = match unsafe { config.parse() } {
            Ok(parsed) => parsed,
            Err(status) => return status,
        };

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return Status::Io,
        };
        let started = runtime.block_on(Tunnel::start(parsed, Platform { device, bypass }));
        let tunnel = match started {
            Ok(tunnel) => tunnel,
            Err(error) => return Status::from(error),
        };

        *out = Box::into_raw(Box::new(BoreasTunnel {
            runtime,
            inner: Some(tunnel),
            _bypass: guard,
        }));
        Status::Ok
    })
}

/// Blocks until the next event, or until the tunnel stops.
///
/// `name` and `rule` receive `Resolved`'s strings, truncated to their
/// capacities and always NUL-terminated; either may be null to discard it.
/// [`Status::Stopped`] once no further event can arrive.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and not have been stopped;
/// `event` must be writable; `name` and `rule`, when non-null, must be
/// writable for their stated capacities.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_next_event(
    handle: *mut BoreasTunnel,
    event: *mut BoreasEvent,
    name: *mut c_char,
    name_cap: usize,
    rule: *mut c_char,
    rule_cap: usize,
) -> Status {
    crate::boundary(|| {
        let handle = borrow_mut!(handle);
        let out = borrow_mut!(event);
        let Some(tunnel) = handle.inner.as_mut() else {
            return Status::Stopped;
        };
        let Some(next) = handle.runtime.block_on(tunnel.next_event()) else {
            return Status::Stopped;
        };

        *out = match next {
            Event::Resolved {
                name: decided,
                blocked,
                rule: matched,
            } => {
                let mut flat = BoreasEvent::empty(BoreasEventKind::Resolved);
                flat.blocked = blocked;
                // SAFETY: the caller's contract covers both buffers.
                flat.name_len = unsafe { write_c_string(&decided, name, name_cap) };
                flat.rule_len = match matched {
                    Some(matched) => unsafe { write_c_string(&matched, rule, rule_cap) },
                    None => unsafe { write_c_string("", rule, rule_cap) },
                };
                flat
            }
            Event::Reloaded {
                allowed,
                blocked,
                inspected,
            } => {
                let mut flat = BoreasEvent::empty(BoreasEventKind::Reloaded);
                flat.allowed = allowed;
                flat.blocked_rules = blocked;
                flat.inspected = inspected;
                flat
            }
            Event::Counted(counters) => {
                let mut flat = BoreasEvent::empty(BoreasEventKind::Counted);
                flat.counters = BoreasCounters {
                    datagrams_dropped: counters.datagrams_dropped,
                    packets_rejected: counters.packets_rejected,
                    quic_steered: counters.quic_steered,
                    paths_reported: counters.paths_reported,
                    events_lost: counters.events_lost,
                    tasks_panicked: counters.tasks_panicked,
                };
                flat
            }
            // The core's event sum is `#[non_exhaustive]` on purpose. An event
            // this ABI predates is skipped rather than mistranslated; the host
            // simply never hears about a thing it has no field for.
            _ => return Status::Ok,
        };
        Status::Ok
    })
}

/// Replaces the rules in force, without restarting the tunnel.
///
/// Writes a `Reloaded` event through `out`.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`]; `lists` must point at
/// `count` live C strings; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_reload(
    handle: *mut BoreasTunnel,
    lists: *const *const c_char,
    count: usize,
    out: *mut BoreasEvent,
) -> Status {
    crate::boundary(|| {
        let handle = borrow_mut!(handle);
        let event = borrow_mut!(out);
        let Some(tunnel) = handle.inner.as_ref() else {
            return Status::Stopped;
        };
        // SAFETY: the caller's contract covers the array and its strings.
        let lists = match unsafe { crate::config::strings(lists, count) } {
            Ok(lists) => lists,
            Err(status) => return status,
        };
        let mut flat = BoreasEvent::empty(BoreasEventKind::Reloaded);
        if let Event::Reloaded {
            allowed,
            blocked,
            inspected,
        } = tunnel.reload(&lists)
        {
            flat.allowed = allowed;
            flat.blocked_rules = blocked;
            flat.inspected = inspected;
        }
        *event = flat;
        Status::Ok
    })
}

/// Copies out the certificate authority's material, for the host to store.
///
/// Writes the two halves into the caller's buffers and sets the lengths.
/// [`Status::BufferTooSmall`] when either buffer is short, with both lengths
/// set to what would be needed — so the idiomatic use is to call once with
/// zero capacities to size, then again to fill.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`]; every non-null buffer must
/// be writable for its stated capacity; both length out-parameters must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_authority(
    handle: *mut BoreasTunnel,
    certificate: *mut u8,
    certificate_cap: usize,
    certificate_len: *mut usize,
    keys: *mut u8,
    keys_cap: usize,
    keys_len: *mut usize,
) -> Status {
    crate::boundary(|| {
        let handle = borrow_mut!(handle);
        let certificate_out = borrow_mut!(certificate_len);
        let keys_out = borrow_mut!(keys_len);
        let Some(tunnel) = handle.inner.as_ref() else {
            return Status::Stopped;
        };
        // A tunnel that does not intercept has no authority, which is an
        // answer rather than a failure: both lengths are zero.
        let Some(material) = tunnel.authority() else {
            *certificate_out = 0;
            *keys_out = 0;
            return Status::Ok;
        };

        let root = material.root_certificate();
        let secret = material.keys().as_bytes();
        *certificate_out = root.len();
        *keys_out = secret.len();
        if certificate_cap < root.len() || keys_cap < secret.len() {
            return Status::BufferTooSmall;
        }
        if certificate.is_null() || keys.is_null() {
            return Status::NullArgument;
        }
        // SAFETY: both capacities were just checked against both lengths, and
        // the caller's contract covers writability.
        unsafe {
            std::ptr::copy_nonoverlapping(root.as_ptr(), certificate, root.len());
            std::ptr::copy_nonoverlapping(secret.as_ptr(), keys, secret.len());
        }
        Status::Ok
    })
}

/// Stops the tunnel and frees its handle.
///
/// **Always frees**, whatever it returns: a failed shutdown is still a tunnel
/// that must not be used again. Passing null is a no-op, so the C idiom of
/// freeing an unconditionally-initialised pointer is safe.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not be used again.
/// No other call on it may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_stop(handle: *mut BoreasTunnel) -> Status {
    crate::boundary(|| {
        if handle.is_null() {
            return Status::Ok;
        }
        // SAFETY: the caller's contract is that this came from `start` and is
        // not used again, which makes reclaiming the box sound.
        let mut owned = unsafe { Box::from_raw(handle) };
        let Some(tunnel) = owned.inner.take() else {
            return Status::Stopped;
        };
        // An ordered shutdown is what returns every pooled buffer and closes
        // every socket.
        let stopped = owned.runtime.block_on(tunnel.stop());

        // **Bounded, because a device read cannot be cancelled.** Dropping a
        // runtime waits for its blocking pool, and the host's `recv` is
        // blocked in the kernel until a packet arrives — which, on a tunnel
        // that has just stopped carrying traffic, may be never. Waiting
        // forever inside `stop` would hang the host's UI thread; the read is
        // therefore given a moment to notice and then detached, and the
        // refcounted context in `seam` is what keeps that sound.
        let runtime = std::mem::replace(
            &mut owned.runtime,
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime needs no resources"),
        );
        runtime.shutdown_timeout(SHUTDOWN_GRACE);

        match stopped {
            Ok(()) => Status::Ok,
            Err(_) => Status::Io,
        }
    })
}
