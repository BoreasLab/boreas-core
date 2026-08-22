//! The handle a host holds, and the six calls it makes on it.
//!
//! Every entry point here has the same shape: `boundary` around a closure that
//! borrows its arguments, does the work, and writes an out-parameter. Nothing
//! returns a pointer the host must free except the handle itself, and nothing
//! hands out a string it owns — strings are copied into buffers the caller
//! supplied, which removes an entire class of question about who frees what.
//!
//! # Why a driver task sits between the handle and the tunnel
//!
//! [`Tunnel::next_event`] takes `&mut self` and blocks until something
//! happens, and a healthy idle tunnel emits nothing at all: the core reports a
//! counter only when it is non-zero, so "nothing went wrong" is silence rather
//! than a zero every interval. A handle that reached the tunnel directly would
//! therefore have to promise the host one call at a time — and that promise
//! makes the interface unusable, because the one thread that is allowed to
//! call is parked in `next_event` forever and can never reload a list.
//!
//! So the tunnel is moved into a task that owns it, and the handle keeps two
//! *disjoint* halves: a receiver for events, and a sender for commands. A
//! reader blocked on the first cannot delay the second, and neither aliases
//! the other — which is what makes every entry point take `&self` and makes
//! concurrent calls sound rather than merely unlikely to break.

use std::{
    ffi::c_char,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use boreas_core::{
    CaMaterial,
    api::{Event, Platform, Tunnel},
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    Status,
    config::BoreasConfig,
    seam::{BoreasBypass, BoreasDevice, Bypass, BypassGuard, Device},
    status::{borrow, borrow_mut},
};

/// How long `free` waits for a device read already inside the host's callback.
///
/// Short on purpose: the tunnel has stopped carrying traffic by then, so a
/// `recv` still blocked is one waiting for a packet that is not coming.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// Events buffered between the driver and the host's reader.
///
/// Small, and bounded rather than unbounded: a host that stops reading stalls
/// the driver, which stalls the core's own bounded telemetry channel, which
/// counts the loss as `events_lost`. One accounting point for "the host fell
/// behind" is worth more than a deeper buffer that reports it twice.
const EVENT_DEPTH: usize = 64;

/// What the host asks of a tunnel it cannot touch directly.
///
/// Each carries its own reply channel, so a caller blocks exactly until its
/// own answer arrives and never on another's.
enum Command {
    Reload {
        lists: Vec<String>,
        reply: oneshot::Sender<Event>,
    },
    Authority {
        reply: oneshot::Sender<Option<CaMaterial>>,
    },
    /// Stop carrying traffic. The reply arrives once shutdown is ordered and
    /// complete; the driver then returns, which drops the event sender and
    /// releases any reader blocked in `next_event`.
    Shutdown {
        reply: oneshot::Sender<Result<(), ()>>,
    },
}

/// Owns the tunnel; serves events and commands until either side is done.
///
/// The `select!` is sound because [`Tunnel::next_event`] is documented
/// cancel-safe: losing that arm to a command loses nothing, because the event
/// stays in the core's channel until it is taken.
async fn drive(
    mut tunnel: Tunnel,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    loop {
        tokio::select! {
            next = tunnel.next_event() => {
                let Some(event) = next else { break };
                // Awaited, not tried: a full buffer must slow this loop down
                // rather than silently drop what the host asked to see.
                if events.send(event).await.is_err() {
                    break;
                }
            }
            command = commands.recv() => match command {
                Some(Command::Reload { lists, reply }) => {
                    let _ = reply.send(tunnel.reload(&lists));
                }
                Some(Command::Authority { reply }) => {
                    let _ = reply.send(tunnel.authority());
                }
                Some(Command::Shutdown { reply }) => {
                    let _ = reply.send(tunnel.stop().await.map_err(|_| ()));
                    return;
                }
                // Every handle is gone without a shutdown: `free` without a
                // `shutdown`. Stop anyway, so sockets close.
                None => break,
            },
        }
    }
    let _ = tunnel.stop().await;
}

/// A running tunnel, and the runtime it runs on.
///
/// **The runtime lives here because a C caller has no executor.** Every entry
/// point that awaits blocks on this one, so the host's calling thread is the
/// one that waits — which is what a Kotlin coroutine dispatcher or a C# task
/// already knows how to arrange.
pub struct BoreasTunnel {
    runtime: tokio::runtime::Runtime,
    /// One reader at a time. The mutex makes a second caller queue rather than
    /// alias the receiver; it is never held by anything but `next_event`, so a
    /// blocked reader delays no other call.
    events: Mutex<mpsc::Receiver<Event>>,
    commands: mpsc::Sender<Command>,
    /// Releases the host's bypass context exactly once, after the tunnel that
    /// borrowed it is gone. Ordering is the point: dropping this before the
    /// tunnel would free a context a dialling task may still be inside.
    _bypass: BypassGuard,
}

impl BoreasTunnel {
    /// Sends one command and waits for its reply.
    ///
    /// `None` once the driver is gone, which is what every entry point turns
    /// into [`Status::Stopped`].
    fn ask<T>(&self, build: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.commands.blocking_send(build(reply)).ok()?;
        self.runtime.block_on(answer).ok()
    }
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

    /// The flat form of a `Reloaded`, which two entry points both produce.
    fn reloaded(event: &Event) -> Self {
        let mut flat = Self::empty(BoreasEventKind::Reloaded);
        if let Event::Reloaded {
            allowed,
            blocked,
            inspected,
        } = event
        {
            flat.allowed = *allowed;
            flat.blocked_rules = *blocked;
            flat.inspected = *inspected;
        }
        flat
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

        let (commands_tx, commands_rx) = mpsc::channel(EVENT_DEPTH);
        let (events_tx, events_rx) = mpsc::channel(EVENT_DEPTH);
        runtime.spawn(drive(tunnel, commands_rx, events_tx));

        *out = Box::into_raw(Box::new(BoreasTunnel {
            runtime,
            events: Mutex::new(events_rx),
            commands: commands_tx,
            _bypass: guard,
        }));
        Status::Ok
    })
}

/// Blocks until the next event, or until the tunnel stops.
///
/// `name` and `rule` receive `Resolved`'s strings, truncated to their
/// capacities and always NUL-terminated; either may be null to discard it.
/// [`Status::Stopped`] once no further event can arrive — which is how a
/// reader learns that another thread called
/// [`boreas_tunnel_shutdown`].
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not have been
/// freed; `event` must be writable; `name` and `rule`, when non-null, must be
/// writable for their stated capacities.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_next_event(
    handle: *const BoreasTunnel,
    event: *mut BoreasEvent,
    name: *mut c_char,
    name_cap: usize,
    rule: *mut c_char,
    rule_cap: usize,
) -> Status {
    crate::boundary(|| {
        let handle = borrow!(handle);
        let out = borrow_mut!(event);

        let mut events = handle.events.lock().unwrap_or_else(PoisonError::into_inner);
        // **Loops, because an event this ABI predates must not be delivered as
        // a phantom.** The core's event sum is `#[non_exhaustive]`, so a
        // variant this build has no field for can arrive; returning success
        // without writing `*out` would leave the host dispatching on whatever
        // its own struct happened to contain. Skipping to the next real event
        // is what the host would do anyway, done here where the alternative is
        // not visible to it.
        let next = loop {
            let Some(next) = handle.runtime.block_on(events.recv()) else {
                return Status::Stopped;
            };
            if matches!(
                next,
                Event::Resolved { .. } | Event::Reloaded { .. } | Event::Counted(_)
            ) {
                break next;
            }
        };
        drop(events);

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
            reloaded @ Event::Reloaded { .. } => BoreasEvent::reloaded(&reloaded),
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
            // Filtered out by the loop above, which is what keeps this arm
            // from being a phantom event rather than an absent one.
            _ => return Status::Ok,
        };
        Status::Ok
    })
}

/// Replaces the rules in force, without restarting the tunnel.
///
/// Writes a `Reloaded` event through `out`. Safe to call while another thread
/// is blocked in [`boreas_tunnel_next_event`].
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not have been
/// freed; `lists` must point at `count` live C strings; `out` must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_reload(
    handle: *const BoreasTunnel,
    lists: *const *const c_char,
    count: usize,
    out: *mut BoreasEvent,
) -> Status {
    crate::boundary(|| {
        let handle = borrow!(handle);
        let event = borrow_mut!(out);
        // SAFETY: the caller's contract covers the array and its strings.
        let lists = match unsafe { crate::config::strings(lists, count) } {
            Ok(lists) => lists,
            Err(status) => return status,
        };
        let Some(reloaded) = handle.ask(|reply| Command::Reload { lists, reply }) else {
            return Status::Stopped;
        };
        *event = BoreasEvent::reloaded(&reloaded);
        Status::Ok
    })
}

/// Copies out the certificate authority's material, for the host to store.
///
/// Writes the two halves into the caller's buffers and sets the lengths.
/// [`Status::BufferTooSmall`] when either buffer is short, with both lengths
/// set to what would be needed — so the idiomatic use is to call once with
/// zero capacities to size, then again to fill. Both lengths are zero for a
/// tunnel that does not intercept, which is an answer rather than a failure.
///
/// Safe to call while another thread is blocked in
/// [`boreas_tunnel_next_event`].
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not have been
/// freed; every non-null buffer must be writable for its stated capacity; both
/// length out-parameters must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_authority(
    handle: *const BoreasTunnel,
    certificate: *mut u8,
    certificate_cap: usize,
    certificate_len: *mut usize,
    keys: *mut u8,
    keys_cap: usize,
    keys_len: *mut usize,
) -> Status {
    crate::boundary(|| {
        let handle = borrow!(handle);
        let certificate_out = borrow_mut!(certificate_len);
        let keys_out = borrow_mut!(keys_len);
        let Some(material) = handle.ask(|reply| Command::Authority { reply }) else {
            return Status::Stopped;
        };
        let Some(material) = material else {
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

/// Stops carrying traffic, and releases any thread blocked in
/// [`boreas_tunnel_next_event`].
///
/// **Separate from [`boreas_tunnel_free`], because a blocked reader cannot be
/// freed out from under itself.** A host stops, joins its reader thread, then
/// frees — the same three steps it would take to tear down any of its own
/// worker loops. Safe to call concurrently with anything, and from any thread;
/// calling it twice is not an error.
///
/// When this returns, every socket is closed and every pooled buffer is back.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not have been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_shutdown(handle: *const BoreasTunnel) -> Status {
    crate::boundary(|| {
        let handle = borrow!(handle);
        match handle.ask(|reply| Command::Shutdown { reply }) {
            Some(Ok(())) => Status::Ok,
            Some(Err(())) => Status::Io,
            // The driver is already gone, so the tunnel is already stopped.
            // Idempotent on purpose: a teardown path that has to remember
            // whether it already ran is a teardown path with a race in it.
            None => Status::Ok,
        }
    })
}

/// Frees the handle.
///
/// Call [`boreas_tunnel_shutdown`] first and join whatever thread was reading
/// events; this reclaims the memory once nothing is inside the tunnel any
/// more. A tunnel not already stopped is stopped here, so a host that frees
/// without stopping still closes its sockets — but a reader blocked at that
/// moment is a use-after-free, which is why the two are separate calls.
///
/// Passing null is a no-op, so the C idiom of freeing an unconditionally
/// initialised pointer is safe.
///
/// # Safety
///
/// `handle` must come from [`boreas_tunnel_start`] and must not be used again.
/// No other call on it may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_tunnel_free(handle: *mut BoreasTunnel) -> Status {
    crate::boundary(|| {
        if handle.is_null() {
            return Status::Ok;
        }
        // SAFETY: the caller's contract is that this came from `start` and is
        // not used again, which makes reclaiming the box sound.
        let owned = unsafe { Box::from_raw(handle) };
        // Dropping the command sender ends the driver, which stops the tunnel
        // if `shutdown` did not. Done before the runtime is torn down, so the
        // shutdown has a runtime to run on.
        let BoreasTunnel {
            runtime,
            events,
            commands,
            _bypass,
        } = *owned;
        drop(commands);
        drop(events);

        // **Bounded, because a device read cannot be cancelled.** Dropping a
        // runtime waits for its blocking pool, and the host's `recv` is
        // blocked in the kernel until a packet arrives — which, on a tunnel
        // that has just stopped carrying traffic, may be never. Waiting
        // forever inside `free` would hang the host's UI thread; the read is
        // therefore given a moment to notice and then detached, and the
        // refcounted context in `seam` is what keeps that sound.
        runtime.shutdown_timeout(SHUTDOWN_GRACE);
        Status::Ok
    })
}
