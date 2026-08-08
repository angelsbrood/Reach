# Relay overlay contract

Reach does not currently ship a relay. This note fixes the contract a future
implementation must satisfy so that an inbound wall is an additive road, not a
new trust system disguised as transport.

## Topology

The relay is a self-hosted WireGuard hub. The daemon and each device establish
separate outbound WireGuard peer relationships to it and keep those NAT
bindings alive. The hub routes between those peers. Direct mesh addresses and
relayed overlay addresses remain distinct; ReachKit can therefore race both
and prefer direct roads without treating the hub as the cluster.

Future ceremony fields provision, at minimum, the hub public key and endpoint,
the device's relay overlay address, and the routes assigned to that peer. The
daemon receives equivalent peer material out of band or through a future host
configuration ceremony. Future authenticated road metadata marks relay
candidates lower priority than LAN, mapped, or direct mesh roads.

This vocabulary requires a negotiated future dialect. It must not be added as
an unknown frame type to v0, and it must retain legacy behavior when no relay
fields are present. The existing QR schema does not change merely because the
post-scan wire gains a relay-capable dialect.

## Security and observation boundary

The hub terminates both WireGuard hops. It can observe relay overlay addresses,
which peers communicate, timing, and traffic volume. It sees the QUIC/mTLS
ciphertext carried inside the overlay. As a network router it can drop, replay,
delay, or inject packets, and it can deny service.

The hub holds no Reach certificate authority, device certificate, app grant,
or session credential. The application connection remains mutually
authenticated and encrypted end to end between ReachKit and reachd, so the hub
cannot read prompts, generated content, grants, session tokens, or model
traffic, and cannot authenticate as either endpoint. This is a narrower claim
than “the relay sees nothing”: it sees network metadata and mTLS ciphertext,
but it is not a Reach trust participant.

## Deployment boundary

A user's VPS, a community host, or a vendor service can fill the same hub role.
No operator name appears in the protocol. Keepalives and outbound establishment
make the road work behind CGNAT and moving access networks, while the distinct
overlay address makes removal or failure of the relay leave every direct road
unchanged.

Implementation, provisioning UI, hub lifecycle, abuse controls, and a real
relay deployment are follow-on scope.
