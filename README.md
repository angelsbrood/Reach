# Reach

An open serving link between personal devices and self-hosted AI clusters.

Reach is the Foundation Models framework talking to itself across a trust
boundary you own: a serving daemon (`reachd`) fronts self-hosted open weights
with the framework's native semantics; a conforming provider package
(`ReachKit`) lets any iOS, macOS, or visionOS app adopt that cluster as its
model by swapping one dependency; and a single pairing ceremony provisions
both halves of trust — a mutually authenticated device identity at the
application layer, and membership in an embedded WireGuard mesh — in one
gesture. The cluster is never exposed to the internet; access is per-device
and per-app; every session is inspectable; there is no account anywhere.

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
  demo](docs/demo.md), and [spike verdicts](docs/spikes.md)

## Building

The keeper's packet-tunnel extension links a patched WireGuardKit, carried
as a submodule under `Keeper/vendor/`, so clone recursively:

    git clone --recursive https://github.com/angelsbrood/Reach

An existing clone catches up with `git submodule update --init`. The patches
are two lines — a tools-version floor and one explicit include — and the
fork's commit says why each exists.

## Status

Pre-filing build, and further along than the spine it started as. Three
things have each been accepted on hardware: the LAN profile (discovery →
QUIC/mTLS → a `LanguageModelSession` streaming from the host); the pairing
ceremony in both halves — a device's identity and its mesh membership from
one QR, then a per-app grant a human rules on the keeper; and the away
path, where a session survives leaving the network it began on and falls to
the mesh without the app having been configured with either address. What
remains is the demo itself, recorded behind a public uplink.

## License

Apache-2.0.
