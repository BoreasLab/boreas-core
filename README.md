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
- an h1/h2 interception exchange on hyper, with a URL-tier filter seam, that
  never bridges HTTP versions
- a reactor bridge presenting each terminated connection as an async stream,
  with backpressure carried by TCP's own window rather than by dropping bytes
- MASQUE CONNECT-IP egress over a sans-io QUIC stack, alongside WireGuard
- SOCKS5 with UDP ASSOCIATE, and Shadowsocks 2022 over TCP, on one dial seam
  shared with local termination

The upstream dialer (TCP plus TLS with tunnel bypass) and the session assembly
that chooses between interception and splice are under construction, as are the
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

Proxy protocols are additionally checked against an independent implementation,
because a self-test proves self-consistency and nothing about the wire. Point
`BOREAS_SINGBOX` at a [sing-box](https://github.com/SagerNet/sing-box) binary to
run them; without it they skip loudly rather than fail.

```sh
BOREAS_SINGBOX=/path/to/sing-box cargo test --test interop
```

## License

[GNU Affero General Public License v3.0](LICENSE)