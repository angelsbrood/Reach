# Relay overlay contract

Reach does not currently ship an operational relay. The repository contains a
reference-hub core and a scriptless Linux package, proved with synthetic
encrypted traffic in a disposable native-arm64 Ubuntu VM and removed after
acceptance. This note fixes the larger contract that core and every future
endpoint integration must satisfy so that an inbound wall becomes an additive
road, not a new trust system disguised as transport.

## Selected topology

The relay is a self-hosted WireGuard hub. The daemon and each device keep their
existing WireGuard interface and key, then add the hub as a separate outbound
peer. The direct mesh remains on `10.86.0.0/24`; the relay uses a distinct,
operator-configurable private `/24`, with `10.87.0.0/24` as the reference
default. A configuration is invalid if those prefixes overlap each other or an
active or configured route.

The host owns relay address `.1/32`. A device mirrors its direct-mesh final
octet at `.2...254/32`. The hub needs no overlay address: it authenticates each
WireGuard peer, verifies that the source address belongs to that peer, and
forwards only host-to-device or device-to-host packets to the peer that owns
the destination `/32`. Device-to-device forwarding, spoofed sources, broadcast,
multicast, other prefixes, and packets without a configured destination are
dropped. The reference MTU is 1280 and endpoints keep their outbound NAT
bindings with a 25-second keepalive.

The direct host/device peer remains unchanged. A relay endpoint therefore has
two non-overlapping ways to reach the same Reach service:

```text
device 10.86.0.N  ===== direct WireGuard peer =====  10.86.0.1 host
device 10.87.0.N  --> hub peer --> relay hub --> hub peer --> 10.87.0.1 host
```

This rules out a superficially simpler design in which the direct peer merely
gets a second endpoint. A WireGuard peer has one current endpoint, so that
shape cannot preserve direct and relayed roads simultaneously. A second relay
interface and key are also rejected: they add privileged lifecycle and collide
with the iPhone's one-active-packet-tunnel boundary without adding trust.

The initial reference hub is a single-cluster, scriptless Linux/systemd
service. Its binary and configuration are root-owned, but its forwarding core
is intended to be a bounded userspace WireGuard router rather than a host
network appliance: no NAT, hub overlay address, shell hook, Reach process, or
Reach credential is part of the role. Multi-cluster tenancy is later scope.

## Configuration and compatibility

The hub key, stable numeric UDP endpoint, relay prefix, and peer manifest are
operator-supplied strict data. The host and device reuse their existing
WireGuard keys. The hub configuration maps each public key to exactly one
relay `/32`; the cluster derives host and device relay addresses from the
selected prefix. Updating hub peers remains an explicit local administrator
operation in the reference design. There is no remote Reach administration
protocol hidden inside the relay.

The portable reference core treats a peer update as a bounded forwarding
transaction, not merely a status change. It closes router admission, crosses
an in-flight barrier and releases the router queue before changing WireGuard
peers. Unchanged peers retain their runtime state. A peer whose relay `/32`
changes is removed and recreated so its staged packets cannot cross into the
new ownership. Router forwarding stays closed through full peer verification
and durable active-specification promotion; the matching router ownership
snapshot is installed before the gate reopens. A packet already handed to an
unchanged peer may complete only under ownership common to both snapshots.
Rollback restores the prior configuration authority but cannot recreate
runtime state deliberately discarded from a removed peer.

Only the last durably promoted active specification is startup authority.
Crash-left pending bytes are discarded rather than replayed. Generation 1
fixes the hub keypair, port, MTU, relay prefix and host assignment; later
generations can change only the ordered device manifest.
Retrying readiness for that same generation does not trust the digest alone:
the core re-reads the complete peer manifest and requires the matching router
ownership snapshot with its forwarding gate open before publishing ready.

Future authenticated calling cards keep direct roads and relay roads separate.
The planned minimal wire shape is a `HelloAck.relayRoads` array under negotiated
dialect v1. Existing `HelloAck.roads` remains direct-only. Under selected v1,
the optional field has three authoritative states: omission preserves the
stored relay roads, an empty array explicitly removes them, and a nonempty
array replaces them. A daemon therefore omits the field while relay intent
still exists but helper state is temporarily unavailable or cannot be
attested; it emits `[]` only when relay intent was explicitly removed or is
intentionally absent. A v0 peer never sends or interprets relay vocabulary.
Framing is unchanged, so the envelope ALPN generation remains 0 and no new
frame is required.

Relay-capable apps will keep relay candidates in a separate keychain record.
A previously authenticated relay road may be used as a lower-priority cold-dial
candidate before a new `Hello` can negotiate; the cluster CA and mTLS identity,
not the endpoint, still decide trust. A later v0 session neither refreshes nor
clears that relay record. An authenticated v1 omission also preserves it, so a
transient host-side outage cannot become permanent client-side removal and
does not require a server-pushed `HelloAck` after recovery. A later
authenticated v1 empty declaration explicitly clears it.

Direct candidates start first. Relay candidates use a bounded measured hedge,
inside the existing cold-open budget, rather than waiting for dead direct roads
to exhaust a full timeout. The same tiering applies to reattachment. A healthy
relay session is not disrupted merely because a direct road later becomes
available.

Future ceremony fields add an optional relay provision to the existing grant:
the hub public key and endpoint, the device relay `/32`, the host relay `/32`,
and the keepalive. They are sent only under the relay-capable dialect. The QR
schema remains 2, and enrollment remains valid when no relay is configured.

## Movement and removal

Access-network movement is WireGuard roaming: the host and device establish
outbound traffic to the stable hub and refresh that relationship with
keepalives. That is different from discovering a changed hub endpoint. The
baseline therefore accepts only a stable numeric `host:port`; DNS refresh,
endpoint migration, hub-key rotation, dual-hub continuity, and recovery by an
already-away device after such a change require a later measured design.

The cluster's ordinary mapped endpoint continues to move through today's
authenticated direct-road refresh. Relay removal deletes only the relay alias,
hub peer, relay routes, relay declaration, and relay-road record. It never
rewrites or removes the direct peer, direct mesh, mapped roads, or user-tailnet
roads.

## Security and observation boundary

The hub terminates both WireGuard hops. It can observe relay overlay addresses,
which configured peers communicate, timing, and traffic volume. It sees the IP
packets that carry Reach's QUIC/mTLS ciphertext. As a router it can drop,
replay, delay, or inject network packets, and it can deny service.

The hub holds no Reach certificate authority, device certificate, app grant,
session token, model credential, prompt, or generated content. The application
connection remains mutually authenticated and encrypted end to end between
ReachKit and reachd, so the hub cannot read or authenticate a Reach session.
This is narrower than “the relay sees nothing”: it sees network metadata and
mTLS ciphertext, but it is not a Reach trust participant.

The portable reference core exposes only local operator diagnostics. Each
configured peer is named by role and ordinal (`host/1` or `device/N`) and has
its own handshake age plus receive/transmit counters, so later acceptance can
attribute traffic to one peer rather than an aggregate. Keys, overlay
addresses, endpoints, Reach identities, and packet content remain absent from
status and logs. No diagnostic surface is remotely administered.

## Deployment boundary

A separate Go module now implements the strict configuration, bounded router,
exact peer-diff transaction, durable last-known-good state and privacy-safe
status surface. A disposable native-arm64 Ubuntu 26.04 VM then proved the
scriptless package under real systemd: the service ran as its dedicated user
with zero capabilities; kernel WireGuard peers exchanged attributable
encrypted traffic through the userspace hub; nftables confined the wildcard
listener with an unconditional port drop independently exercised from allowed
ingress, another interface, loopback IPv4 and IPv6, and injected real-interface
ingress; live reload, refused updates, three crash restarts, two guest reboots,
B→A→B package compatibility, removal and VM deletion all passed.
The exact hardened unit also became ready with the maximum 253-device manifest
plus the host while remaining below its fixed memory, task and FD limits. Its
unprivileged identity could not create links, routes, namespaces or firewall
state; the same PID then restored the small encrypted topology and forwarded
3/3 before teardown.
The package is inert until an operator supplies strict configuration and
firewall policy and explicitly enables it. Route authority fails closed unless
Linux returns one complete, kernel-originated, sequence-matched netlink dump;
truncation, interruption, overrun or malformed completion refuses the update.

That is Linux **arm64** runtime/package acceptance. The static amd64 binary
reproduced twice but has not executed on an amd64 kernel. The accepted VM,
mutable disk, package, account, state, firewall and namespaces were removed;
only Lima and the exact pinned image cache remain as declared developer
tooling. No public endpoint or Reach participant entered the matrix.

A user's VPS, a community host, or a vendor service can fill the same role. No
operator name appears in the protocol. The reference service is single-cluster
and explicitly configured; multi-tenant allocation, remote management, DNS
mobility, provisioning UI, public package distribution, abuse policy, and a
real public deployment remain follow-on work. Linux acceptance proves the
private deployment substrate; it does not choose, provision, expose, or
operate an endpoint.

No operational relay, wire dialect v1, host relay state, or device relay
provisioning ships today.
