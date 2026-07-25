# The wire

Reach is the Foundation Models framework talking to itself across a trust
boundary, and this is what crosses it. The protocol is deliberately small: one
envelope, one control stream, one stream per generation, and a ceremony that
shares the envelope but not the trust.

It is also **asymmetric, by necessity rather than taste**. The framework's
generation channel takes `Event` values built from static factories and offers
no public way to read one back. A daemon can therefore never receive a
framework event, serialize it, and forward it. So the daemon's slot produces
Reach's own `WireEvent` natively, and only the client-side executor turns those
back into framework events. The vocabulary below is the daemon's first
language, not a translation of one.

## The envelope

```
[u32 big-endian length][u8 frameType][JSON body]
                       └─── length counts these two ───┘
```

Bodies are JSON in v0. A frame is capped at 16 MiB — far beyond
text-generation scale, and a hard stop against a nonsense length from a broken
or hostile peer. A zero length is rejected, and an unrecognized frame type is
an **error rather than something to skip**: a peer that cannot name what it was
sent should not guess. `FrameReassembler` takes arbitrary chunks off a stream
and yields whole frames, one instance per stream direction.

| | Frame | |
|---|---|---|
| **1** | `Hello` | versions offered, client name |
| **2** | `HelloAck` | version, cluster, models, **addrs**, port |
| **3** | `SessionOpen` | model id |
| **4** | `SessionOpened` | session id, resume token, capabilities |
| **5** | `SessionResume` | session id, token, per-generation cursors |
| **6** | `SessionResumed` | per-generation state and final sequence |
| **7** | `GrantSubscribe` | admin device only |
| **8** | `GrantEvent` | a parked app request, for the sheet |
| **9** | `GrantRule` | the human's verdict |
| **10/11** | `Ping` / `Pong` | nonce echo |
| **12** | `ErrorFrame` | code, message |
| **20** | `GenerateBegin` | session id, generation id, request |
| **21** | `GenerateReattach` | session id, token, generation id, from-sequence |
| **22** | `GenerateCancel` | generation id |
| **23** | `EvAck` | cumulative sequence received |
| **24** | `Ev` | sequence, event |
| **30–34** | `EnrollBegin` … `EnrollComplete` | the device ceremony |
| **35–37** | `AppEnrollBegin` … `AppEnrollGrant` | the app ceremony |

The gaps between the bands are deliberate: a band can grow without renumbering
its neighbours.

## Two channels, and what each proves

Sessions speak **`reach/0`** over QUIC with mutual TLS; client certificates are
required at the data plane, and a certificate-less client is refused there
rather than at the application layer. The ceremony speaks **`reach-enroll/0`**
on a sibling listener with server-authenticated TLS only, because at enrollment
time the client's certificate is the thing being asked for.

Both are found over Bonjour — `_reach._udp` for sessions,
`_reach-enroll._udp` for the door, advertised under the same cluster name. The
session advertisement carries one TXT key, `ca`: the base64url SHA-256 of the
cluster CA's DER, which an enrolling app pins. (What that pin is and is not
worth is in [the ceremony](ceremony.md).)

QUIC idles at 30 s for sessions and 180 s for enrollment — the longer window so
a request parked at the grant desk outlives the 120 s a human has to rule on
it. Either side may `Ping`; the keeper's console does so every 10 s to hold its
subscription visibly open.

**Verification pins the chain, not the name.** Verify blocks run with
role-correct SSL policies and a nil host, so no hostname is checked. The
consequence is the architecture: *any address presenting the cluster's chain is
the cluster*. A session dialed at a LAN address, a mesh address, or an address
on a tailnet the daemon happens to sit on is the same session to the same peer,
and nothing above the transport has to know which one it took.

## The control stream

Client-opened, long-lived, one per connection.

```
  Hello{versions, client}                client ──► daemon
  HelloAck{version, cluster, models,
           addrs, port}                  daemon ──► client
  SessionOpen{modelID}                   client ──► daemon
  SessionOpened{sessionID, token,
                capabilities}            daemon ──► client
```

`HelloAck.addrs` is the part that earns its keep. The daemon declares **every
IPv4 address it answers on** — LAN, mesh, and any tunnel interface that happens
to be up — together with the port they answer on. A client whose path has just
died re-dials those as candidates and keeps the first that connects. The list
arrives over an already mutually authenticated stream, so trusting it grants
nothing that mTLS did not already grant.

Both fields are **optional on the wire**, which is the whole compatibility
story: a daemon that predates them simply omits them, and a client that
receives none falls back to the address it already had.

## A generation

One bidirectional stream per generation, opened by the client.

```
  GenerateBegin{sessionID, genID, request}   client ──► daemon
  Ev{seq: 0, event}                          daemon ──► client
  Ev{seq: 1, event}                              …
  EvAck{seq}                                 client ──► daemon
  …
  Ev{seq: n, .finished(reason)}              daemon ──► client
```

Sequences start at 0 and are per-generation. `EvAck` is **cumulative** —
everything at or below that sequence is received — and it trims the daemon's
replay buffer, which is capped at 4 MiB per generation.

The generation is owned by the session registry, not by the connection that
started it. When the transport dies the generation **keeps running** for a 120 s
residency window; completed generations are held 600 s so a client that
reconnects late still collects its ending. Re-attach is therefore not a retry:

```
  SessionResume{sessionID, token,
                [{genID, lastReceivedSeq}]}  client ──► daemon
  SessionResumed{[{genID, state, finalSeq}]} daemon ──► client
  GenerateReattach{genID, fromSeq}           client ──► daemon
  Ev{seq: fromSeq+1, …}                      daemon ──► client   (replay, then live)
```

A `GenerateBegin` carrying a genID the daemon already knows is treated as a
re-attach from sequence 0 — which makes losing the very first frame
recoverable instead of fatal.

`GenerateCancel` ends it early; the client's own task cancellation is what
sends it, and the generation finishes `.cancelled` rather than vanishing.

One in-flight generation per session is the tested v0 invariant. The registry
holds more; nothing above it has needed to yet.

## The event vocabulary

```swift
case responseAppend(entryID:text:segmentID:tokenCount:)
case responseReplace(entryID:text:segmentID:tokenCount:)
case reasoningAppend(entryID:text:segmentID:tokenCount:)
case toolCallAppendArguments(entryID:id:name:content:tokenCount:)
case usage(inputTokens:outputTokens:)
case finished(.complete | .cancelled | .error(String))
```

## The request

`Transcript` and `GenerationSchema` are natively `Codable` and ride as
themselves — a real framework-built transcript survives encode, decode and
re-encode byte-identically, and there is a test that says so. Only the options
types need hand mirrors: `WireGenerationOptions`, `WireContextOptions` and
`WireToolDefinition`, each with a `native()` round trip. That file is a seam,
not a design: when the framework core open-sources, the mirrors are deleted and
native conformances take their place.

## Named seams (v0, deliberate)

- **Sampling mode is lossy.** `GenerationOptions.SamplingMode` exposes no
  public read accessor — the `Kind` enum exists but nothing returns it. Greedy
  survives because it is detectable through `Equatable`; every other mode rides
  as `nil` and the host applies its own defaults. Feedback-worthy upstream, and
  resolved by the same rebase.
- **Request `metadata` is dropped.** Its values are existential
  `Sendable & Codable & Equatable`, which JSON coding cannot carry generically.
- **`toolCallAppendArguments` is reserved and never emitted.** Tool round-trips
  are funded scope; the case exists so adding them is not a wire break.
- **Bodies are JSON.** Chosen for legibility while the shape is still moving —
  every frame on this wire can be read by a human with a hex dump and patience,
  which during a ceremony debugged at a kitchen table is worth more than bytes.
