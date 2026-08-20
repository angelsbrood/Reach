# Relay overlay contract

Reach does not currently operate a public relay endpoint. The repository does
ship the reference-hub core and scriptless Linux package, host-side relay
authority, and negotiated relay calling cards/direct-first client fallback.
Those pieces were proved with synthetic encrypted traffic and a disposable
local endpoint; no device is provisioned for the overlay and no external
service was created. This note fixes the contract every deployment and future
device integration must satisfy so that an inbound wall becomes an additive
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

Authenticated calling cards keep direct roads and relay roads separate. The
shipped wire shape is a `HelloAck.relayRoads` array under negotiated
dialect v1. Existing `HelloAck.roads` remains direct-only. Under selected v1,
the optional field has three authoritative states: omission preserves the
stored relay roads, an empty array explicitly removes them, and a nonempty
array replaces them. A daemon therefore omits the field while relay intent
still exists but helper state is temporarily unavailable or cannot be
attested; it emits `[]` only when relay intent was explicitly removed or is
intentionally absent. A v0 peer never sends or interprets relay vocabulary.
Framing is unchanged, so the envelope ALPN generation remains 0 and no new
frame is required.

Relay-capable ReachKit apps keep relay candidates in a separate keychain record.
A previously authenticated relay road may be used as a lower-priority cold-dial
candidate before a new `Hello` can negotiate; the cluster CA and mTLS identity,
not the endpoint, still decide trust. A later v0 session neither refreshes nor
clears that relay record. An authenticated v1 omission also preserves it, so a
transient host-side outage cannot become permanent client-side removal and
does not require a server-pushed `HelloAck` after recovery. A later
authenticated v1 empty declaration explicitly clears it.

S32 selected a 100 ms direct-preference hedge: direct candidates start at time
zero and relay candidates start 100 ms later if direct has not won. That grace,
not task-admission order, made the measured 20 ms healthy-direct arm win
deterministically against an immediately completing relay. Both tiers share the
unchanged ten-second absolute budget. The same tiering applies to reattachment.
A healthy relay session is not disrupted merely because a direct road later
becomes available,
but every independent dial after session invalidation returns to the tiered
race instead of trying a proven direct road alone for the full timeout.

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

## Host ownership boundary

The host side of this topology is a backward-readable extension of the existing
mesh owner, not a second VPN service. Login-owned `mesh-intent.json` remains
canonical version 1 while it is direct-only. Configuring a relay produces strict
version 2 with one optional relay block; removing it increments the generation
and writes canonical version 1 again. The host private key is never copied into
intent.

The operator edits intent without invoking privilege:

```text
reachd mesh relay set --network 10.87.0.0/24 \
  --hub-public-key <base64-public-key> \
  --endpoint <numeric-host:port>
reachd mesh relay remove
```

Both commands print only generation and domain-separated public digests. The
separate `reachd mesh apply` ceremony still compiles one mode-`0600`
specification and visibly invokes the installed root owner through
`/usr/bin/sudo`. Enrollment and operator edits share one process-wide intent
lock, so a newly enrolled direct peer and its derived relay `/32` cannot be
lost to a concurrent relay edit.

The helper's strict version-2 specification retains the existing interface,
key, UDP port, MTU, direct address, direct connected route and direct peers. It
adds only the relay `.1/32`, exact device relay `/32` routes, and one
endpoint-bearing hub peer. The Darwin backend removes relay routes and the
relay alias before mutating that hub peer, computes an exact UAPI diff, and
preserves unchanged direct peers including their learned runtime state. An
endpoint-only hub change is in place; a key or AllowedIPs change removes and
re-adds the hub so staged traffic cannot cross ownership. Full peer, address,
route and MTU authority is reverified before the specification is atomically
promoted and fsynced, and readiness is published only afterward.

Status version 2 reports independent `direct` and `relay` component digests,
counts and readiness. A configured but unapplied relay is WAIT while verified
direct state remains PASS. A refused candidate retains the last-known-good
authority and a bounded outcome. False readiness, a leaked removed path,
generation rollback, or any peer/address/route/digest disagreement is FAIL.
Version-1 helper status remains readable during upgrade.

Direct calling cards remain deliberately direct-only in both dialects.
Listener certificates and local diagnostics still see every local address,
but pairing, `HelloAck.roads`, and legacy `addrs` exclude the relay address and
conservatively exclude every non-`10.86.0.1` IPv4 address on the interface that
owns the direct mesh. Desired intent and helper status add a second quarantine
source. A stale or misplaced relay alias therefore cannot leak into v0 or the
v1 direct tier; only authenticated v1 `relayRoads` can name it as relay.

S31 installed and exercised this host boundary on 19 August 2026. One local
reference hub proved add, idempotent reapply, endpoint-only update, relay-prefix
and AllowedIPs replacement, overlap refusal, helper crash recovery, and complete
removal without restarting reachd or changing direct identity. The exact-byte
review repair reran the same installed matrix on 20 August after making route
inspection fail closed and route deletion interface-owned. A final correction
then bound every transaction to an atomically claimed specification and made
teardown refuse any foreign route owner appearing after deletion. Installed
interruption/restart acceptance proved claimed generation 12 could not promote
newer pending generation 13; the complete matrix then restored canonical
direct-only intent generation 18 on `utun0`, with one direct peer and verified
absence of every relay alias, route, hub peer, pending artifact, and claimed
artifact. The final acknowledgement repair additionally binds each apply
request and response to the exact expected generation and public digest. Its
installed regression retained generation 19, staged 20, and acknowledged 20
only after 20 was active; the same bytes then restored canonical direct-only
generation 25. The accepted helper is `a784f257…b28ca8`, with relay configured
false/ready true and no residual relay or transaction artifact.

S32 then installed negotiated relay-road support without changing that helper.
The daemon and client selected dialect v1 over unchanged `reach/0`, exercised
authenticated replace/preserve/clear declarations, cold-opened over the local
relay, and carried one generation direct-to-relay and another relay-to-direct.
The exact backed-up v0 client still authenticated against the v1 daemon.
Corrected installed reachd `a9660a83…6b790` ended with helper generation 37 in
canonical direct-only state; helper `a784f257…b28ca8`, all identities, and
Keeper were unchanged. The installed matrix re-earned the exact v0 client,
100 ms direct-first, relay-only, both transition directions and clear against
those bytes. This is a client-visible transport capability, not an operational
relay deployment: no public endpoint or device provisioning exists.

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

Host ownership and negotiated relay roads now cover the Mac/reference-client
half. No operational relay endpoint, device provisioning, public deployment,
or Keeper relay behavior ships. Until Keeper is separately released, the
iPhone cannot receive the second address/hub peer required to use this road.
