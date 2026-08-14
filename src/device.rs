//! The device seam: raw IP packets in and out, an MTU, nothing else. Platform
//! adapters implement this over OS handles; `SimDevice` implements it over a
//! scripted in-memory wire so every load and conformance gate can run
//! deterministically in-process.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::Duration,
};

use crate::Mtu;

pub trait Device {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes one packet **whole**; see [`crate::AsyncDevice::send`] for why
    /// the byte count is absent from the result rather than returned unchecked.
    fn send(&mut self, buf: &[u8]) -> io::Result<()>;
    fn mtu(&self) -> Mtu;
}

/// SplitMix64: one multiply-xor-shift round per output. Seeded, deterministic,
/// and adequate for loss and reorder scripts; not a CSPRNG, and nothing here
/// needs one.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..rate`, used as `rng.below(rate) == 0` for a 1/rate event.
    fn below(&mut self, rate: u64) -> u64 {
        self.next() % rate
    }
}

/// A scripted in-memory wire. Delivery is scheduled against the virtual clock
/// the harness drives, so reorder and delay are reproducible from the seed.
pub struct SimDevice {
    mtu: Mtu,
    rng: Rng,
    /// Inbound packets by scheduled delivery tick.
    inbound: BTreeMap<u64, VecDeque<Vec<u8>>>,
    /// Everything the datapath sent, in order.
    sent: Vec<Vec<u8>>,
    now: u64,
    /// One-in-N loss rates; zero disables.
    loss_in: u64,
    loss_out: u64,
    /// Maximum extra ticks a packet may be delayed.
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

    /// Queues a packet for delivery `delay` ticks from now, before any script
    /// distortion applies.
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

    /// Advances the virtual clock.
    pub fn advance(&mut self, ticks: u64) {
        self.now += ticks;
    }

    /// Sets the virtual clock to an absolute tick.
    pub fn advance_to(&mut self, tick: u64) {
        self.now = tick;
    }

    /// Changes the wire MTU mid-script.
    pub fn set_mtu(&mut self, mtu: Mtu) {
        self.mtu = mtu;
    }

    /// What the datapath has sent so far, in order.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// The earliest tick with a pending inbound packet.
    pub fn next_delivery(&self) -> Option<u64> {
        self.inbound.first_key_value().map(|(tick, _)| *tick)
    }
}

impl Device for SimDevice {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.loss_in > 0 && self.rng.below(self.loss_in) == 0 {
            // Consume one scheduled packet from its tick bucket and drop it.
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
            return Ok(()); // consumed, lost on the wire
        }
        self.sent.push(buf.to_vec());
        Ok(())
    }

    fn mtu(&self) -> Mtu {
        self.mtu
    }
}

/// The sans-io shell over any `Device`: drains the device into the datapath,
/// drains the datapath back to the device, and fires timeouts on the virtual
/// clock. Deterministic because every input is scripted.
pub struct Harness<D> {
    pub device: D,
    pub datapath: crate::Datapath,
    /// Virtual time base; one tick is one millisecond.
    base: std::time::Instant,
    /// Packets the core refused, counted rather than fatal — the same
    /// classification the runtime shell makes, so a trace replayed here
    /// behaves as it would in production.
    rejected: u64,
    /// Egress-bound transmits, in order. The harness has no egress — that is
    /// the runtime shell's job — so it records what would have crossed rather
    /// than looping it back down the device, which is exactly the mistake
    /// [`crate::Side`] exists to make unrepresentable.
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

    /// Packets the core refused across every `step` so far.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Everything the core sent toward the egress, in order.
    pub fn to_egress(&self) -> &[Vec<u8>] {
        &self.to_egress
    }

    /// Runs one tick at `ticks`: deliver due packets, flush transmits, expire.
    pub fn step(&mut self, ticks: u64) -> io::Result<()> {
        let now = self.base + Duration::from_millis(ticks);
        let mut buf = vec![0u8; usize::from(self.device.mtu().get())];

        loop {
            match self.device.recv(&mut buf) {
                // Untrusted input: a rejected packet is an observation, not a
                // reason to abandon the trace.
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
    use crate::{
        Accepts, DatagramFidelity, DnsPolicy, EgressCapabilities, FilterPolicy, NatBehavior,
    };
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
            EgressCapabilities {
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
                datagram_buffer_capacity: NonZeroUsize::new(64).unwrap(),
                // Long enough to outlast a browser's cached Alt-Svc entry for
                // an origin, which is what the DNS rewrite alone cannot reach.
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
        // The gate: the same trace through the harness and through direct
        // calls must emit byte-identical transmits.
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

        // A packet from the client's TUN is bound for the egress, so the
        // device sees nothing and the egress log holds it exactly once.
        assert_eq!(
            direct_transmits,
            vec![(crate::Side::Egress, packet.clone())]
        );
        assert!(harness.device.sent().is_empty());
        assert_eq!(harness.to_egress(), &[packet]);
    }

    #[test]
    fn loss_and_reorder_are_scripted_and_deterministic() {
        // One-in-one loss consumes everything.
        let mut device = SimDevice::new(Mtu::new(1500).unwrap(), 1).with_loss_in(1);
        device.inject(&udp_frame(), 0);
        let mut buf = vec![0u8; 1500];
        assert_eq!(
            device.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        // Reordering changes delivery order but not content, reproducibly.
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
