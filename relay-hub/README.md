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

## Linux package and service

The package directory is an accepted scriptless systemd payload on native
Ubuntu 26.04 arm64. Build it from an already verified offline module graph and
a static Linux binary:

```text
SOURCE_DATE_EPOCH=<fixed-epoch> \
  ./tests/linux/build-package.sh <source-root> <binary> <version> arm64 <output.deb>
```

The package installs only the binary, unit, sysusers/tmpfiles declarations,
licenses/notices, and route-inventory documentation. It has no maintainer
scripts, creates no key or operator configuration, and does not start or enable
the service. Installation is deliberately inert until an administrator:

1. installs the package and applies its sysusers/tmpfiles declarations;
2. installs strict `/etc/reach-relay-hub/config.json` and `routes.json` files,
   both root-owned, group-owned by `reach-relay`, and mode `0640`;
3. installs a local firewall policy that exposes the wildcard WireGuard
   listener only to the intended relay ingress; and
4. reloads systemd and explicitly enables and starts the unit.

The service reads active Linux IPv4 routes from every table and unions them
with the declared route inventory before accepting a relay prefix. `SIGHUP`
securely rereads both operator files and applies an in-place peer transaction;
an invalid update preserves the running generation and reports `update
refused`. `SIGUSR1` revalidates live backend/router authority and refreshes the
privacy-safe mode-`0600` status at
`/run/reach-relay-hub/status.json`.

To retire an installation, stop and disable the unit, purge the package, then
separately remove operator configuration, active/pending state, runtime state,
firewall policy, and—only after confirming nothing owns it—the dedicated
account. Package removal intentionally does not destroy operator-owned state.

The standard wireguard-go bind listens on wildcard IPv4/IPv6 UDP, not
loopback-only. Firewall confinement is therefore mandatory, not inferred from
the socket. The accepted policy ends with an unconditional drop for the hub
port; its counters advanced for a denied source on allowed ingress, a separate
interface, IPv4 and IPv6 loopback, and injected real-interface ingress while
all hub peer counters stayed unchanged. The complete private acceptance matrix
passed under unprivileged systemd with zero capabilities on native Linux arm64,
including encrypted forwarding, refusal, `systemctl reload`, exact private
directory modes, crash/reboot recovery, B→A→B package compatibility, and
complete teardown. A bounded addendum started the exact installed unit with
253 devices plus the host under `MemoryMax=256M`, `TasksMax=128`,
`LimitNOFILE=1024` and `LimitCORE=0`; its service identity was refused link,
route, namespace and firewall mutation. The same PID then restored the small
encrypted topology and forwarded 3/3 before teardown. The amd64 artifact is
reproducible cross-build evidence only; it has not run on an amd64 kernel.

Linux route discovery accepts only a complete, kernel-originated,
sequence-matched netlink dump. Truncation, interruption, overrun, a foreign
sender, malformed padding, or a missing final completion fails closed before
backend mutation. The package integration tests inspect the actual data and
control archives against `package/manifest.txt`; every declared input is
mandatory and the archive root is mode `0755`.

Configuration generation 1 fixes the hub key, UDP port, MTU, relay prefix, and
host assignment. Later generations may change only the ordered device manifest.
The router closes forwarding and releases its queue while an exact peer diff is
verified and the new active specification is durably promoted.
Only that promoted active specification is startup authority; crash-left
pending bytes are discarded rather than replayed.
An idempotent same-generation readiness retry re-reads the complete backend
manifest and requires the matching router snapshot with its forwarding gate
open before it can publish `ready: true`.

No operational relay, public endpoint, Reach road, product integration, or
package repository ships from this acceptance result.
