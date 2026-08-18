# Platforms

## Shared Core Boundary

Android and Windows expose different device APIs but the same product boundary:
an ordered stream of raw IP packets. Platform code owns device lifecycle,
permissions, route installation, wakeup integration, and buffer transfer. The
Rust core owns packet semantics and every layer above them.

Do not create platform-specific datapaths. Platform adapters should be thin
effect interpreters for the same ingress and egress actions.

## Android v1

Architecture:

```text
Android VpnService -> raw file descriptor -> JNI -> Rust core
```

The Android application owns VPN consent, foreground-service lifecycle, network
changes, bypass protection for egress sockets, user-store CA installation UX,
and presentation. JNI transfers buffers and lifecycle events without embedding
filter or routing policy.

The target is non-rooted operation. Never depend on:

- system certificate-store modification
- Conscrypt APEX bind mounts
- iptables privileges
- another simultaneously active VPN application

MITM scope is Chromium-family browsers and WebViews that trust the user-store
CA. Native apps continue to receive DNS and network filtering. Vendor and OS
variation requires an early WebView test matrix.

## Windows v1

Use Wintun, not a Windows Filtering Platform callout driver. Wintun is a minimal
kernel TUN adapter that exposes userspace packet rings analogous to
`/dev/net/tun`. Integration ships one `wintun.dll` and uses `wintun-bindings` to
load Adapter and Session APIs.

WireGuard distributes precompiled, Microsoft-signed Wintun binaries that may be
redistributed with applications. This removes the EV-certificate and Microsoft
attestation burden of shipping a custom kernel driver.

WFP would provide per-application policy, but it would also require a signed
driver and a second datapath. Defer it unless measured product demand justifies
both costs.

Windows exposes a broader TLS opportunity than Android because an administrator
can install a CA into the OS trust store, which many applications use. The v1
decision between browser-only and system-wide interception remains open. Any
system-store design must account for Chrome Certificate Transparency behavior
and application pinning before implementation.

## iOS v2

iOS is a declarative filtering product sharing the engine and lists, not the v1
packet interception architecture.

```text
filter lists -> adblock compiler -> Apple content-blocking rules -> extension
                                     +
                              DNS-only packet tunnel
```

Safari content blocking is the enforcement point for page-level filtering.
The VPN performs DNS filtering and network policy only. This avoids forcing an
HTTP interception engine into the 50 MB `NEPacketTunnelProvider` budget.

## Platform Acceptance

- Android and Windows feed identical packet fixtures into the Rust core.
- Device adapters contain no filtering or egress policy.
- Egress sockets cannot loop back into the VPN.
- Adapter shutdown cancels child work and releases OS resources deterministically.
- Wintun distribution uses the authorized signed binary.
- Android CA UX installs only to the user store.
- Platform-specific behavior is represented as path properties or events, not hidden
  branches in shared policy.