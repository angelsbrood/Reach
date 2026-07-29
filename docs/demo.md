# The ninety seconds

This is the demo Reach is built to make true, and the definition of done for
the pre-filing package. Everything in the repository exists to hold these
ninety seconds up, and nothing in it reaches past them.

## The beat sheet

> The daemon is running and `reachd pair` is on screen — scan it with the
> keeper — the grant sheet appears and is ruled — a sample app opens a session
> and streams on the LAN — walk out the door mid-generation — the stream
> survives onto cellular over the mesh — the generation completes in hand.

Seven beats. The last three are one continuous shot, because the claim being
made is precisely that nothing happens between them.

| | Beat | What it demonstrates |
|---|---|---|
| 0:00 | `reachd serve`, then `reachd pair` | A cluster of one machine, serving open weights behind the framework's own provider slot |
| 0:15 | The keeper scans the QR | One gesture; a Secure Enclave identity key and a WireGuard key minted and bound by one signature |
| 0:30 | A factory-fresh app sends its first prompt; the grant sheet appears | Access is per-app, and a human rules it — not a setting, not an account |
| 0:40 | Allow; the app collects and streams on the LAN | A third-party app adopting a cluster as its model by swapping one dependency |
| 1:00 | Walk out the door, mid-generation | The network the session began on stops existing |
| 1:10 | The stream continues over the mesh | The session was never bound to the road it started on |
| 1:25 | The generation finishes in hand | — |

## The rig

Three boxes: the host (a Mac serving open weights), the edge it sits behind,
and the phone. Nothing else, and nothing rented — no relay, no coordination
server, no account anywhere.

The one environmental requirement is that the phone can reach the host's edge
from outside it: a publicly routable address that forwards UDP 51820 to the
host. Behind a second router that means two forwards in series, and the address
pinned at the ceremony must be the *outer* one. Carrier-grade NAT (a
`100.64/10` lease) cannot carry this leg at all — the first-party road holds
that boundary, and a self-hostable relay is the funded answer to it. A user's
own mesh, which does its own traversal, crosses it today.

Those two share an address range, which is why `reachd doctor` asks a second
question about anything pinned in `100.64/10`: whether it is an address *this
host holds*. A lease handed out by a venue's router is CGNAT and the leg is
impossible there. The same address sitting on this machine is a mesh it has
already joined, and works — for a phone on that same mesh.

## Pacing

The door-walk has to land mid-stream, so the generation has to still be running
when the demonstrator reaches it. Two things make that reliable rather than
lucky: the sample app asks for **4096 response tokens** (the daemon's own
fallback is 512, which is what once made long answers feel truncated), and the
prompt asks for something with a natural length to it — a description, a short
story — rather than a fact.

Rehearse the walk itself. The transition is not instant and is not meant to
look instant: the stream visibly pauses for a few seconds while the client
re-attaches at the mesh address, then continues from exactly where it stopped.
That pause is the honest shape of the thing, and hiding it would be a worse
demo than showing it.

## Before recording

```
reachd doctor
```

Reports the host-side preconditions in one pass: whether the config parses,
whether the mesh endpoint is **pinned** rather than derived and what kind of
address it is, whether the mesh interface is actually up, the CA and its pin,
whether the wg config and the host's own key agree about which host this is,
wg peers, an active admin device, and whether a daemon already holds the ports.

Four levels, and the distinction between two of them is the point:

- **WAIT** — a step below has not been run yet, and running it resolves this.
  A machine that has just booted is mostly WAIT, and that is the checklist
  working.
- **FAIL** — something starting up will not fix. Only this affects the exit
  code, so a non-zero exit means *this host is wrong*, never *this host is
  cold*.
- **WARN** — worth knowing, and legitimate. A pinned RFC1918 address warns
  because two forwards in series is a real venue, not a mistake.
- **PASS** — checked, and it holds.

Read the mesh-endpoint line regardless of the tally. It is the one that
decides whether a phone standing outside can reach this host, and it is the
line the away leg fails on. A host that has a config and no pinned
`meshEndpoint` FAILs there: it will derive a LAN address, rehearse perfectly,
and hand the phone something no phone off this network can dial. A machine
with no config at all only WAITs — nothing has been set up yet, so nothing has
been left out.

Two things doctor deliberately does not claim. The peer count is peers in the
*file*; only `sudo wg show reach0` sees what the running interface carries, and
that needs root. And the mesh check observes a `10.86.0.x` address, not an
interface by name — those coincide only while the config says so.

It cannot see the edge — the port forward lives there, and a forward that was
configured once is not a forward that is in force. Check the live firewall
rules before every away rehearsal, not the record of having set them up.

Then, in order:

1. `wg-quick up reach0` — **before** `reachd serve`, so the mesh address is
   present in every artifact from the first instant. Nothing breaks if it comes
   up second: the listener binds by port, verification pins the chain and not
   the name, and the candidate list the away leg falls to is recomputed for
   every Hello. The order is cheap insurance, and it stays.
2. `reachd serve` — confirm the startup line reads `(pinned)`.
3. A LAN generation, to prove the spine.
4. The away leg, to prove the fall.

## What is real, and what is named

Real, during these ninety seconds: the certificates and the mutual TLS, the
Secure Enclave device key and its proof of possession, the WireGuard keys and
the tunnel, the per-app certificate the grant issues, and the tokens — a local
open-weights model on the host's GPU, generating.

Named as stubs, here and in the plan rather than discovered later:

- **App attestation is stubbed as local approval.** The grant sheet is a real
  approval flow and the certificate it issues is real; what is not yet proven
  is that the app is the bundle it claims to be. Server-side App Attest is the
  funded upgrade, and [the ceremony](ceremony.md) names exactly where it lands.
- **The wire codec bridges the framework's types by hand** — see
  [the wire](wire.md). A rebase onto native conformances is expected.
- **Session residency is minimal**: enough to carry one in-flight generation
  across a path change, which is the claim the demo makes and no more.

## Reproducible on request

The recording is made once; the demo runs live. A cluster of one machine, a
phone, and a door.

For a spine check with no second device and no network at all:

```
reachd selftest --mlx
```

which runs the daemon and a real `LanguageModelSession` in one process over
loopback, with freshly issued certificates and real weights behind the slot.
