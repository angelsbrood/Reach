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
- `docs/` — wire protocol, ceremony, spike verdicts

## Status

Pre-filing build. The LAN profile (discovery → QUIC/mTLS → a
`LanguageModelSession` streaming from the host) is the current spine; the
pairing ceremony and the away path over the mesh follow.

## License

Apache-2.0.
