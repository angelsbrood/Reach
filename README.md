# Reach

An open serving link between personal devices and self-hosted AI clusters.

[Reach](https://cassiespiral.com/work/reach) is the Foundation Models framework talking to itself across a trust
boundary you own: a serving daemon (`reachd`) fronts self-hosted open weights
with the framework's native semantics; a conforming provider package
(`ReachKit`) lets any iOS, macOS, or visionOS app adopt that cluster as its
model by swapping one dependency; and a single pairing ceremony provisions
both halves of trust — a mutually authenticated device identity at the
application layer, and membership in an embedded WireGuard mesh — in one
gesture. The daemon asks the current router to map both its QUIC session UDP
port and its WireGuard UDP port. A mapped QUIC listener still requires a
cluster-issued client certificate during TLS; WireGuard still requires an
enrolled peer key. Neither listener offers an unauthenticated application
door. Access is per-device and per-app; every session is
inspectable; there is no account anywhere.

## Layout

- `reachd/` — the macOS serving daemon: slot host with an MLX filling, QUIC
  listener with mutual TLS, Bonjour advertisement, cluster CA, session
  residency
- `ReachKit/` — the Swift package apps link: wire codec (`ReachWire`),
  transport (`ReachTransport`), identity (`ReachIdentity`), and the conforming
  model provider (`ReachKit`) for iOS, macOS, and visionOS
- `Keeper/` — the companion app prototype: the ceremony, the tunnel, the
  grant sheet
- `Example/` — a sample app that links ReachKit and nothing privileged
- `docs/` — [the wire](docs/wire.md), [the ceremony](docs/ceremony.md), [the
  demo](docs/demo.md), [running the daemon](docs/running.md), [the relay
  contract](docs/relay.md), and [spike verdicts](docs/spikes.md)

## Building

The keeper's packet-tunnel extension links a patched WireGuardKit, carried
as a submodule under `Keeper/vendor/`, so clone recursively:

    git clone --recursive https://github.com/angelsbrood/Reach

An existing clone catches up with `git submodule update --init`. The patches
are two lines — a tools-version floor and one explicit include — and the
fork's commit says why each exists.

## Status

Public prototype, and further along than the spine it started as. Four
things have each been accepted on hardware: the LAN profile (discovery →
QUIC/mTLS → a `LanguageModelSession` streaming from the host); the pairing
ceremony in both halves — a device's identity and its mesh membership from
one QR, then a per-app grant a human rules on the keeper; the away
path, where a session survives leaving the network it began on and falls to
the mesh without the app having been configured with either address; and
the cold start away, where an app that has never seen the network it is on
opens a session from stored trust alone — no discovery, dialing only the
roads an earlier session wrote down.
The demo is recorded — one unbroken take, July 2026 at Moon, on internal
networks: https://youtu.be/FmhNJYJ_o0A. What remains is the same take
behind a public uplink.

## Reachability

Automatic mapping is best-effort and enabled by default. The daemon uses the
macOS system broker (PCP, NAT-PMP, or UPnP as the router supports), renews the
leases for its lifetime, follows primary-network changes, and records current
diagnostic evidence in a private `reachability.json` beside its state. Session
and WireGuard mappings are independent, so a gateway may assign them different
external ports. Enrollment remains local and Bonjour-discovered; it is never
mapped.

An explicit `meshEndpoint` remains authoritative. If it is absent, a current
mapped WireGuard endpoint wins over the derived LAN fallback; the mapping is
still maintained while pinned so removing the pin takes effect without a
restart. Mapping failure changes no local behavior.

A mapping is not a universal public road. A private or CGNAT outer address is
usable only from that outer network, and a client already away when an endpoint
moves retains the old road until it next authenticates successfully. Direct
mapping principally serves single-NAT edges; [the published relay
contract](docs/relay.md) names the follow-on for inbound walls and moving
addresses without pretending that relay is implemented.

## Collaboration

Reach is designed and directed by Cassie Spiral at Moon and developed with
Codex and Claude Code across implementation, tests, and documentation.
Assisted commits identify the tool and model and retain a co-author trailer;
Claude Code commits also include a session link.

Identity designed by [Vanessa Spiral](https://vanessaspiral.com).

## License

Apache-2.0. Copyright 2026 Cassie Spiral.

Third-party code is carried under its own terms and marked as such: the
patched WireGuardKit submodule under `Keeper/vendor/`, the two wg-quick parser
files copied into `Keeper/PacketTunnel/`, and pinned `wireguard-go` embedded by
`mesh-helper/` are WireGuard LLC's under the MIT license. The copied sources
keep their SPDX headers and the host-helper attribution is in
`mesh-helper/NOTICE.md`.
