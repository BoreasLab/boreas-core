//! Device seam for raw IP packets and MTU only.
//!
//! Platform adapters implement it over OS handles; `SimDevice` implements it
//! over a scripted in-memory wire for deterministic tests.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::Duration,
};

use crate::Mtu;

pub trait Device {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes one complete packet. Partial packet writes are not a valid seam
    /// result; see [`crate::AsyncDevice::send`].
    fn send(&mut self, buf: &[u8]) -> io::Result<()>;
    fn mtu(&self) -> Mtu;
}

/// Seeded SplitMix64 state for deterministic loss and reorder scripts.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..rate` for one-in-`rate` events.
    fn below(&mut self, rate: u64) -> u64 {
        self.next() % rate
    }
}

/// An in-memory wire with virtual-time delivery, loss, and reordering.
pub struct SimDevice {
    mtu: Mtu,
    rng: Rng,
    /// Inbound packets grouped by delivery tick.
    inbound: BTreeMap<u64, VecDeque<Vec<u8>>>,
    /// Packets sent by the datapath, in order.
    sent: Vec<Vec<u8>>,
    now: u64,
    /// One-in-N inbound and outbound loss rates; zero disables loss.
    loss_in: u64,
    loss_out: u64,
    /// Maximum random delivery delay added by reordering.
    reorder_window: u64,
}

impl SimDevice {
    pub fn new(mtu: Mtu, seed: u64) -> Self {
        Self {
            mtu,
            rng: Rng(seed),
            inbound: BTreeMap::new(),
            sent: Vec::new(),
            now: 0,
            loss_in: 0,
            loss_out: 0,
            reorder_window: 0,
        }
    }

    pub fn with_loss_in(mut self, rate: u64) -> Self {
        self.loss_in = rate;
        self
    }

    pub fn with_loss_out(mut self, rate: u64) -> Self {
        self.loss_out = rate;
        self
    }

    pub fn with_reorder_window(mut self, ticks: u64) -> Self {
        self.reorder_window = ticks;
        self
    }

    /// Schedules a packet after `delay` ticks, before script jitter.
    pub fn inject(&mut self, packet: &[u8], delay: u64) {
        let jitter = if self.reorder_window > 0 {
            self.rng.below(self.reorder_window + 1)
        } else {
            0
        };
        self.inbound
            .entry(self.now + delay + jitter)
            .or_default()
            .push_back(packet.to_vec());
    }

    /// Advances virtual time by `ticks`.
    pub fn advance(&mut self, ticks: u64) {
        self.now += ticks;
    }

    /// Sets virtual time to an absolute tick.
    pub fn advance_to(&mut self, tick: u64) {
        self.now = tick;
    }

    /// Changes the wire MTU during a script.
    pub fn set_mtu(&mut self, mtu: Mtu) {
        self.mtu = mtu;
    }

    /// Returns packets sent by the datapath so far.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// Returns the earliest tick with a pending packet.
    pub fn next_delivery(&self) -> Option<u64> {
        self.inbound.first_key_value().map(|(tick, _)| *tick)
    }
}

impl Device for SimDevice {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.loss_in > 0 && self.rng.below(self.loss_in) == 0 {
            // Loss consumes one scheduled packet from its bucket.
            if let Some(mut entry) = self.inbound.first_entry() {
                let queue = entry.get_mut();
                if queue.pop_front().is_some() && queue.is_empty() {
                    entry.remove_entry();
                }
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "simulated loss"));
            }
        }

        let tick = match self.inbound.first_key_value() {
            Some((tick, _)) if *tick <= self.now => *tick,
            _ => return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet due")),
        };

        let Some((_, mut queue)) = self.inbound.pop_first() else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet due"));
        };
        let Some(packet) = queue.pop_front() else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet due"));
        };
        if !queue.is_empty() {
            self.inbound.insert(tick, queue);
        }

        if packet.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet exceeds the receive buffer",
            ));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.loss_out > 0 && self.rng.below(self.loss_out) == 0 {
            return Ok(()); // consumed, but absent from the wire
        }
        self.sent.push(buf.to_vec());
        Ok(())
    }

    fn mtu(&self) -> Mtu {
        self.mtu
    }
}

/// Deterministic shell that drains a device through the datapath and fires
/// timeouts against virtual time.
pub struct Harness<D> {
    pub device: D,
    pub datapath: crate::Datapath,
    /// Virtual time base; each tick represents one millisecond.
    base: std::time::Instant,
    /// Packets rejected by the core, counted as the runtime shell counts them.
    rejected: u64,
    /// Egress-bound packets in order. The harness records them because it has
    /// no egress and must not loop them back to the device.
    to_egress: Vec<Vec<u8>>,
}

impl<D: Device> Harness<D> {
    pub fn new(device: D, datapath: crate::Datapath, base: std::time::Instant) -> Self {
        Self {
            device,
            datapath,
            base,
            rejected: 0,
            to_egress: Vec::new(),
        }
    }

    /// Returns the number of packets rejected so far.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Returns packets sent toward the egress, in order.
    pub fn to_egress(&self) -> &[Vec<u8>] {
        &self.to_egress
    }

    /// Delivers due packets, flushes transmits, and expires state at `ticks`.
    pub fn step(&mut self, ticks: u64) -> io::Result<()> {
        let now = self.base + Duration::from_millis(ticks);
        let mut buf = vec![0u8; usize::from(self.device.mtu().get())];

        loop {
            match self.device.recv(&mut buf) {
                // Rejected input is counted so a trace can continue.
                Ok(len) => {
                    if self.datapath.on_tun_packet(&buf[..len], now).is_err() {
                        self.rejected += 1;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        while let Some(transmit) = self.datapath.poll_transmit() {
            match transmit.to {
                crate::Side::Tunnel => {
                    self.device.send(&transmit.bytes)?;
                }
                crate::Side::Egress => self.to_egress.push(transmit.bytes.to_vec()),
            }
        }

        self.datapath.on_timeout(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Accepts, DatagramFidelity, DnsPolicy, FilterPolicy, NatBehavior, PathProperties};
    use std::{num::NonZeroUsize, time::Instant};

    fn udp_frame() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ]
    }

    fn pool() -> std::sync::Arc<crate::BufferPool> {
        crate::BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        )
    }

    fn datapath() -> crate::Datapath {
        crate::Datapath::new(
            FilterPolicy::PassThrough,
            DnsPolicy::Forward,
            Accepts::IpPackets,
            PathProperties {
                datagram_fidelity: DatagramFidelity::Native,
                overhead_bytes: 60,
                max_datagram_size: None,
                preserves_ecn: true,
                nat_behavior: NatBehavior::EndpointIndependent,
            },
            Mtu::new(1500).unwrap(),
            crate::Limits {
                reassembly_timeout: Duration::from_secs(30),
                max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
                flow_idle_timeout: Duration::from_secs(120),
                max_flows: std::num::NonZeroUsize::new(1024).unwrap(),
                datagram_buffer_capacity: NonZeroUsize::new(64).unwrap(),
                // Long enough to cover the DNS steering backstop in the fixture.
                inspection_window: Duration::from_secs(60),
                max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
                inspected_ports: crate::DEFAULT_INSPECTED_PORTS,
                origination_ports: None,
            },
            pool(),
        )
        .unwrap()
    }

    #[test]
    fn harness_reproduces_directly_driven_results() {
        // The harness and direct calls must emit identical transmits.
        let packet = udp_frame();

        let mut direct = datapath();
        let base = Instant::now();
        direct.on_tun_packet(&packet, base).unwrap();
        let direct_transmits: Vec<(crate::Side, Vec<u8>)> =
            std::iter::from_fn(|| direct.poll_transmit().map(|t| (t.to, t.bytes.to_vec())))
                .collect();

        let mut device = SimDevice::new(Mtu::new(1500).unwrap(), 42);
        device.inject(&packet, 0);
        let mut harness = Harness::new(device, datapath(), base);
        harness.step(0).unwrap();

        // This packet is egress-bound, so the device sees nothing and the
        // egress log receives it once, one hop spent.
        let mut spent = packet.clone();
        crate::spend_hop(&mut spent);
        assert_eq!(direct_transmits, vec![(crate::Side::Egress, spent.clone())]);
        assert!(harness.device.sent().is_empty());
        assert_eq!(harness.to_egress(), &[spent]);
    }

    #[test]
    fn loss_and_reorder_are_scripted_and_deterministic() {
        // One-in-one loss consumes every scheduled packet.
        let mut device = SimDevice::new(Mtu::new(1500).unwrap(), 1).with_loss_in(1);
        device.inject(&udp_frame(), 0);
        let mut buf = vec![0u8; 1500];
        assert_eq!(
            device.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        // Reordering changes order but preserves content for a fixed seed.
        let packets: Vec<Vec<u8>> = (0u8..4).map(|n| vec![0x45, n]).collect();
        let run = |seed| {
            let mut device = SimDevice::new(Mtu::new(1500).unwrap(), seed).with_reorder_window(3);
            for packet in &packets {
                device.inject(packet, 0);
            }
            let mut order = Vec::new();
            let mut buf = vec![0u8; 1500];
            for tick in 0..8 {
                device.advance_to(tick);
                while let Ok(len) = device.recv(&mut buf) {
                    order.push(buf[..len].to_vec());
                }
            }
            order
        };
        let first = run(7);
        let second = run(7);
        assert_eq!(first, second, "same seed, same wire");
        assert_eq!(first.len(), 4);
        assert!(
            first != packets,
            "a reorder window must actually reorder some run"
        );
    }
}
