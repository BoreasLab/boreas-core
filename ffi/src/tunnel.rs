//! C-facing tunnel handle and operations.
//!
//! Entry points validate borrowed arguments inside `boundary` and write only
//! to caller-owned outputs. Strings are copied into caller-provided buffers.
//!
//! The tunnel runs in a driver task because [`Tunnel::next_event`] blocks while
//! commands must remain available. The handle therefore owns separate event
//! and command channels, allowing concurrent calls without aliasing the tunnel.

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

/// Grace period for a device read already inside a host callback.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// Bounded event buffer between the driver and host.
const EVENT_DEPTH: usize = 64;

/// Command sent from a host call to the driver.
enum Command {
    Reload {
        lists: Vec<String>,
        reply: oneshot::Sender<Event>,
    },
    Authority {
        reply: oneshot::Sender<Option<CaMaterial>>,
    },
    /// Stop traffic and release blocked event readers.
    Shutdown {
        reply: oneshot::Sender<Result<(), ()>>,
    },
}

/// Owns the tunnel and serves events and commands until shutdown.
async fn drive(
    mut tunnel: Tunnel,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    loop {
        tokio::select! {
            next = tunnel.next_event() => {
                let Some(event) = next else { break };
                // Backpressure preserves events instead of dropping them.
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
                // Dropping every handle still stops the tunnel.
                None => break,
            },
        }
    }
    let _ = tunnel.stop().await;
}

/// Running tunnel handle and its runtime.
pub struct BoreasTunnel {
    runtime: tokio::runtime::Runtime,
    /// Serializes event readers without aliasing the receiver.
    events: Mutex<mpsc::Receiver<Event>>,
    commands: mpsc::Sender<Command>,
    /// Releases the bypass context after the tunnel is dropped.
    _bypass: BypassGuard,
}

impl BoreasTunnel {
    /// Sends one command and waits for its reply; `None` means the driver ended.
    fn ask<T>(&self, build: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.commands.blocking_send(build(reply)).ok()?;
        self.runtime.block_on(answer).ok()
    }
}

/// Event field group represented by [`BoreasEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BoreasEventKind {
    /// A name was resolved.
    Resolved = 0,
    /// Rules were reloaded.
    Reloaded = 1,
    /// Counters since the previous event.
    Counted = 2,
}

/// Counters since the previous [`BoreasEventKind::Counted`] event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct BoreasCounters {
    pub datagrams_dropped: u64,
    pub packets_rejected: u64,
    pub quic_steered: u64,
    pub paths_reported: u64,
    pub events_lost: u64,
    /// Number of tasks that panicked.
    pub tasks_panicked: u64,
}

/// Flattened event record; only fields selected by `kind` are meaningful.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BoreasEvent {
    pub kind: BoreasEventKind,
    /// `Resolved`: whether policy blocked the name.
    pub blocked: bool,
    /// `Resolved`: full name length before truncation.
    pub name_len: usize,
    /// `Resolved`: full rule length, or zero when no rule matched.
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

    /// Converts a reload event to its flat representation.
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

/// Copies `text` into a NUL-terminated buffer and returns its full byte length.
///
/// Truncates at a UTF-8 boundary when the buffer is too small.
///
/// # Safety
///
/// `buf`, when non-null, must be writable for `cap` bytes.
unsafe fn write_c_string(text: &str, buf: *mut c_char, cap: usize) -> usize {
    if buf.is_null() || cap == 0 {
        return text.len();
    }
    // Reserve one byte for the terminator.
    let taken = text.len().min(cap - 1);
    // Keep truncation on a UTF-8 boundary.
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

/// Starts a tunnel and writes its handle through `out`.
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

        // Drop the guard after all tunnel resources.
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

/// Blocks until the next event or tunnel shutdown.
///
/// Resolved names and rules are truncated to their capacities and
/// NUL-terminated; null buffers discard the corresponding text.
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
        // Skip core events not represented by this ABI.
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
            // Kept unreachable by the event filter above.
            _ => return Status::Ok,
        };
        Status::Ok
    })
}

/// Replaces the active rules and writes a `Reloaded` event through `out`.
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

/// Copies the tunnel's certificate authority material into caller buffers.
///
/// Length outputs report required sizes when either buffer is too small. A
/// tunnel without interception reports two zero lengths.
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

/// Stops traffic and releases blocked event readers.
///
/// Callers should join event-reader threads before freeing the handle. Repeated
/// shutdown calls are harmless.
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
            // The driver is already gone, so shutdown is complete.
            None => Status::Ok,
        }
    })
}

/// Frees the handle after callers have stopped it and joined event readers.
///
/// A non-stopped tunnel is stopped during cleanup. A null handle is a no-op.
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
        // End the driver before tearing down its runtime.
        let BoreasTunnel {
            runtime,
            events,
            commands,
            _bypass,
        } = *owned;
        drop(commands);
        drop(events);

        // A device callback may not be cancellable, so bound runtime shutdown.
        runtime.shutdown_timeout(SHUTDOWN_GRACE);
        Status::Ok
    })
}
