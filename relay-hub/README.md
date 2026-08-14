# Reach reference relay-hub core

This module proves a bounded, single-cluster userspace WireGuard forwarding
core. It is not installed by Reach and does not make a relay ship.

The hub owns no Reach credential. It forwards only authenticated host-to-device
and device-to-host packets on a distinct relay `/24`; the inner traffic remains
Reach QUIC/mTLS ciphertext.

## Offline build and test

Use isolated caches preseeded with the exact modules in `go.sum`:

```text
GOPROXY=off GOSUMDB=off go test ./...
REACH_RELAY_REAL=1 GOPROXY=off GOSUMDB=off go test -run TestRealThreePeerForwardingAndPeerDiff ./internal/backend
GOPROXY=off GOSUMDB=off go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags=-buildid= ./cmd/reach-relay-hub
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags=-buildid= ./cmd/reach-relay-hub
```

The real test opens bounded wildcard UDP listeners on disposable ports and
tears them down before returning. All commands remain offline: use explicit
scratch `GOMODCACHE` and `GOCACHE` directories, preseed only the checksummed
module objects in `go.sum`, and set `GOPROXY=off GOSUMDB=off` for list, verify,
test, and build operations.

The package directory describes a future scriptless systemd payload. This pass
does not install it or claim Linux runtime, firewall, ownership, upgrade, or
teardown acceptance.

The package manifest intentionally does not create `config.json`: an operator
must install the strict root-owned mode-`0640` configuration before enabling
the service. The standard wireguard-go bind listens on wildcard IPv4/IPv6 UDP,
not loopback-only. Linux firewall confinement and route-inventory discovery
remain obligations of the next privileged-runtime pass.

Configuration generation 1 fixes the hub key, UDP port, MTU, relay prefix, and
host assignment. Later generations may change only the ordered device manifest.
The router closes forwarding and releases its queue while an exact peer diff is
verified and the new active specification is durably promoted.
Only that promoted active specification is startup authority; crash-left
pending bytes are discarded rather than replayed.
An idempotent same-generation readiness retry re-reads the complete backend
manifest and requires the matching router snapshot with its forwarding gate
open before it can publish `ready: true`.
