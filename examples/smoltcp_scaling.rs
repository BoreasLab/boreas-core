//! P6: the smoltcp scaling measurement. Runs a fixed workload — N concurrent
//! listening TCP sockets, each polled once per round over a synthetic device —
//! and reports per-socket poll time at p50/p99 and the scaling slope against
//! the budget declared in docs/verification.md item 8.
//!
//! Run: cargo run --release --example smoltcp_scaling -- 100 500 1000 2000

use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    time::{Duration, Instant as WallInstant},
};

use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket, SocketBuffer},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};

/// A device that never has traffic. The measurement is per-socket polling
/// cost, not packet processing: an idle device with live sockets is the load.
struct IdleDevice {
    queue: VecDeque<Vec<u8>>,
}

struct IdleRx;
impl RxToken for IdleRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&[])
    }
}

struct IdleTx;
impl TxToken for IdleTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        f(&mut buf)
    }
}

impl Device for IdleDevice {
    type RxToken<'a> = IdleRx;
    type TxToken<'a> = IdleTx;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.queue.pop_front().map(|_| (IdleRx, IdleTx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(IdleTx)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

fn measure(socket_count: usize, rounds: usize) -> (Duration, Duration, Duration) {
    let mut device = IdleDevice {
        queue: VecDeque::new(),
    };
    let config = Config::new(HardwareAddress::Ip);
    let mut interface = Interface::new(config, &mut device, Instant::ZERO);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)), 24))
            .unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    for index in 0..socket_count {
        let rx = SocketBuffer::new(vec![0; 1024]);
        let tx = SocketBuffer::new(vec![0; 1024]);
        let mut socket = Socket::new(rx, tx);
        socket
            .listen((Ipv4Addr::new(10, 0, 0, 2), 80 + index as u16))
            .unwrap();
        sockets.add(socket);
    }

    let mut samples = Vec::with_capacity(rounds);
    let mut now = Instant::ZERO;
    for _ in 0..rounds {
        now += Duration::from_millis(10).into();
        let started = WallInstant::now();
        let _ = interface.poll(now, &mut device, &mut sockets);
        samples.push(started.elapsed());
    }

    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
    (p50, p99, mean)
}

fn main() {
    let counts: Vec<usize> = std::env::args()
        .skip(1)
        .map(|argument| argument.parse().expect("socket count"))
        .collect();
    let counts = if counts.is_empty() {
        vec![100, 500, 1000, 2000]
    } else {
        counts
    };

    println!("sockets,p50_us,p99_us,mean_us,per_socket_ns");
    let mut previous: Option<(usize, Duration)> = None;
    for count in &counts {
        let (p50, p99, mean) = measure(*count, 200);
        let per_socket = mean.as_nanos() / *count as u128;
        println!(
            "{},{},{},{},{}",
            count,
            p50.as_micros(),
            p99.as_micros(),
            mean.as_micros(),
            per_socket
        );
        if let Some((previous_count, previous_mean)) = previous {
            let slope = mean.as_secs_f64() / previous_mean.as_secs_f64();
            let growth = *count as f64 / previous_count as f64;
            println!(
                "# scaling {} -> {} sockets: {:.2}x time for {:.2}x sockets",
                previous_count, count, slope, growth
            );
        }
        previous = Some((*count, mean));
    }
}
