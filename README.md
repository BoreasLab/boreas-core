# Boreas

Boreas is a single-process Rust engine that combines browser-grade content
filtering with user-selected encrypted egress on one system VPN interface.

The v1 product targets non-rooted Android and Windows. It uses one raw-IP
datapath for DNS and network filtering, browser and WebView HTTPS filtering,
and egress through WireGuard, MASQUE, SOCKS5, Shadowsocks, and later
VLESS-family transports.

## Status

The core currently provides:

- capability-aware flow planning and QUIC steering
- allocation-free IPv4 and IPv6 ingress classification
- explicit packet, stream, datagram, ICMP, and reassembly actions
- endpoint-independent UDP mapping state with bounded, non-blocking buffers
- sans-io local TCP termination over a bounded smoltcp socket set
- a user-store CA and a terminating TLS server that forges per-host leaves

The h1/h2 exchange over terminated TLS, its upstream leg, and the reactor
integration that drives termination live are under construction, as are the
platform on-device gates, the remaining filtering tiers, and egress breadth.

## Documentation

- [Project documentation](docs/README.md)
- [Architecture](docs/architecture.md)
- [Delivery plan](docs/delivery.md)
- [Agent guidance](AGENTS.md)

## Development

Requires a current stable Rust toolchain.

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## License

[GNU Affero General Public License v3.0](LICENSE)