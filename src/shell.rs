//! The tokio runtime shell. It interprets the pure `Datapath`: one reactor
//! task owns the core by value (no `Arc<Mutex<Datapath>`), one timer re-arms
//! against `poll_timeout`, and channels are bounded. Backpressure is
//! asymmetric by design: control messages use `send().await`, datagrams use
//! `try_send` and count drops.
//!
//! Per-flow datagram payloads are refcounted slices into one shared pool:
//! `Pooled` bytes cost a handle per queued datagram instead of an owned 1500-
//! byte buffer, which is the difference between ~1.3 MB and ~120 MB at the
//! 10,000-flow acceptance target.

use std::{
    io,
    ops::{Deref, Range},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    sync::mpsc,
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{
    Datapath, EgressCapabilities, FlowEvent, InternalEndpoint, SendOutcome, SteeringReason,
};

/// One slab of bytes carved into fixed-size slices. The slab lives behind an
/// `Arc`, so a pooled slice's address is stable for the pool's lifetime and a
/// `Deref` through it never borrows a guard.
pub struct BufferPool {
    slab: Arc<[u8]>,
    free: Mutex<Vec<Range<usize>>>,
    slice_size: usize,
}

/// A refcounted slice of the pool. Derefs to bytes; clones share the slice.
#[derive(Clone)]
pub struct Pooled {
    pool: Arc<BufferPool>,
    range: Range<usize>,
    len: usize,
}

impl PartialEq for Pooled {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}
impl Eq for Pooled {}

impl std::fmt::Debug for Pooled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pooled({} bytes)", self.len)
    }
}

impl Deref for Pooled {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.pool.slab[self.range.start..self.range.start + self.len]
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        if let Ok(mut free) = self.pool.free.lock() {
            free.push(self.range.clone());
        }
    }
}

impl BufferPool {
    /// `slice_size` should be the path MTU; `slices` the total payload budget.
    pub fn new(slice_size: usize, slices: usize) -> Arc<Self> {
        Arc::new(Self {
            slab: vec![0u8; slice_size * slices].into(),
            free: Mutex::new(
                (0..slices)
                    .map(|index| index * slice_size..(index + 1) * slice_size)
                    .collect(),
            ),
            slice_size,
        })
    }

    /// Copies `bytes` into a pooled slice, or returns `None` when the pool is
    /// exhausted or the datagram exceeds the slice size. Exhaustion is a drop,
    /// never a wait.
    pub fn take(self: &Arc<Self>, bytes: &[u8]) -> Option<Pooled> {
        if bytes.len() > self.slice_size {
            return None;
        }
        let range = self.free.lock().ok()?.pop()?;
        // The slab is immutable-capable only through this write; the free list
        // guarantees exclusive access to the range.
        unsafe {
            let slab = self.slab.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), slab.add(range.start), bytes.len());
        }
        Some(Pooled {
            pool: Arc::clone(self),
            range,
            len: bytes.len(),
        })
    }

    pub fn available(&self) -> usize {
        self.free.lock().map(|free| free.len()).unwrap_or(0)
    }
}

/// Control messages into the reactor. Bounded, awaited: a slow control plane
/// is backpressure on the caller, which is correct for streams of policy.
#[derive(Debug)]
pub enum Control {
    CapabilityChange(EgressCapabilities),
    Datagram {
        endpoint: InternalEndpoint,
        bytes: Pooled,
    },
    Shutdown,
}

/// Telemetry out of the reactor. Bounded, best-effort: telemetry loss under
/// saturation is acceptable, flow correctness is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Telemetry {
    Event(FlowEvent),
    DatagramsDropped(u64),
    ReassemblyDiscarded(u64),
    Resteered(SteeringReason),
}

pub struct Shell {
    control: mpsc::Sender<Control>,
    telemetry: mpsc::Receiver<Telemetry>,
    shutdown: CancellationToken,
    reactor: tokio::task::JoinHandle<io::Result<()>>,
}

impl Shell {
    /// Starts the reactor on the current multi-threaded runtime. `device` is a
    /// file-descriptor-like async reader/writer of raw IP packets; the platform
    /// adapters in P9 supply it. The reactor owns the datapath by value.
    pub fn start<D>(datapath: Datapath, device: D, pool: Arc<BufferPool>) -> Self
    where
        D: AsyncDevice + Send + 'static,
    {
        let (control_tx, control_rx) = mpsc::channel(256);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(256);
        let shutdown = CancellationToken::new();

        let reactor = tokio::spawn(reactor_loop(
            datapath,
            device,
            control_rx,
            telemetry_tx,
            shutdown.clone(),
        ));
        let _ = pool;

        Self {
            control: control_tx,
            telemetry: telemetry_rx,
            shutdown,
            reactor,
        }
    }

    pub async fn control(&self) -> mpsc::Sender<Control> {
        self.control.clone()
    }

    pub async fn next_telemetry(&mut self) -> Option<Telemetry> {
        self.telemetry.recv().await
    }

    /// Drains the reactor: no task leaks past shutdown.
    pub async fn shutdown(self) -> io::Result<()> {
        self.shutdown.cancel();
        let _ = self.control.send(Control::Shutdown).await;
        self.reactor.await??;
        Ok(())
    }
}

/// The async side of the device seam: raw IP packets with readiness, supplied
/// by P9's platform adapters. Futures must be `Send` so the reactor can live
/// on a multi-threaded runtime; the trait is written with explicit future
/// types because `async fn` in a public trait cannot promise that.
pub trait AsyncDevice {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    fn send<'a>(&'a mut self, buf: &'a [u8])
    -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

async fn reactor_loop<D: AsyncDevice>(
    mut datapath: Datapath,
    mut device: D,
    mut control: mpsc::Receiver<Control>,
    telemetry: mpsc::Sender<Telemetry>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut buf = vec![0u8; 2048];

    loop {
        let timeout = TokioInstant::now() + Duration::from_millis(50);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            Some(message) = control.recv() => {
                match message {
                    Control::CapabilityChange(next) => {
                        datapath.on_capability_change(next);
                    }
                    Control::Datagram { endpoint, bytes } => {
                        let outcome = datapath
                            .send_datagram(endpoint, bytes.to_vec(), std::time::Instant::now())
                            .map_err(|error| {
                                io::Error::new(io::ErrorKind::InvalidData, error)
                            })?;
                        if outcome == SendOutcome::Dropped {
                            let _ = telemetry.try_send(Telemetry::DatagramsDropped(1));
                        }
                    }
                    Control::Shutdown => break,
                }
            }
            result = device.recv(&mut buf) => {
                let len = result?;
                datapath.on_tun_packet(&buf[..len], std::time::Instant::now())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            }
            _ = sleep_until(timeout) => {
                datapath.on_timeout(std::time::Instant::now());
            }
        }

        while let Some(transmit) = datapath.poll_transmit() {
            device.send(&transmit.bytes).await?;
        }
        while let Some(event) = datapath.poll_event() {
            let telemetry_event = match event {
                FlowEvent::ReassemblyDiscarded => Telemetry::ReassemblyDiscarded(1),
                FlowEvent::Resteered(reason) => Telemetry::Resteered(reason),
                other => Telemetry::Event(other),
            };
            let _ = telemetry.try_send(telemetry_event);
        }
    }

    Ok(())
}
