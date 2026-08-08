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

### Compatibility contract

The ALPN names the **envelope generation**; `Hello`/`HelloAck` negotiate the
JSON dialect carried inside it. Today both are generation 0, but they are
deliberately separate constants. A dialect-only bump keeps `reach/0`, offers
every supported dialect newest-first, and lets the daemon select its first
preferred common value. Only a change to the length/type/body framing earns a
new ALPN and deliberately partitions peers that cannot parse one another's
envelopes. Serving multiple ALPNs waits until such a framing change exists.

Three rules hold every future wire edit:

1. An unknown **optional JSON key on an existing frame is additive-safe**.
   Swift's decoder ignores it, and a missing optional key retains the legacy
   meaning defined by that frame.
2. A **new frame type requires a negotiated dialect**. Unknown type bytes are
   fatal, so every `FrameType` names the first dialect that may send it and
   both send and receive paths enforce the selected dialect.
3. An incompatible **framing change requires an ALPN change**. It must be
   deliberate and documented; a dialect bump alone never changes ALPN.

S10 measured the premises before implementation: unknown optional keys decoded
3/3; unknown type 255 failed 3/3 with `frame type 255 is not in this protocol
version's vocabulary`; and mismatched authenticated and enrollment ALPNs each
ended 3/3 as the opaque `stream open timeout`. The retained register is in
[spikes.md](spikes.md).

| | Frame | |
|---|---|---|
| **1** | `Hello` | versions offered, client name |
| **2** | `HelloAck` | version, cluster, models, **roads?**, addrs?, port? |
| **3** | `SessionOpen` | model id |
| **4** | `SessionOpened` | session id, resume token, capabilities |
| **5, 6** | *reserved* | retired; see below |
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
| **30–35** | `EnrollBegin` … `EnrollComplete`, `EnrollConfirmed` | the device ceremony |
| **40–42** | `AppEnrollBegin` … `AppEnrollGrant` | the app ceremony |

The gaps between the bands are deliberate: a band can grow without renumbering
its neighbours. That held for every band except this pair, where the app
ceremony had been placed flush against the device ceremony — so when the device
band grew its sixth frame, the app band moved to 40 to make room rather than
leaving the device ceremony scattered around its neighbour. The renumber cost
nothing: raw values are read in exactly two places, both in `Envelope.swift`,
and nothing persists a type byte.

## Two channels, and what each proves

Sessions speak **`reach/0`** over QUIC with mutual TLS; client certificates are
required at the data plane, and a certificate-less client is refused there
rather than at the application layer. The ceremony speaks **`reach-enroll/0`**
on a sibling listener with server-authenticated TLS only, because at enrollment
time the client's certificate is the thing being asked for.

Both are found over Bonjour — `_reach._udp` for sessions,
`_reach-enroll._udp` for the door, advertised under the same cluster name. The
session advertisement carries `ca`, the base64url SHA-256 of the cluster CA's
DER, and `v`, the daemon's supported dialects comma-separated in newest-first
preference order. The CA value is pinned during enrollment. The versions value
is advisory UI/discovery context only: stored roads never see Bonjour, and no
connection is accepted or rejected from TXT. The authenticated exchange is
authoritative. (What the CA pin is and is not worth is in
[the ceremony](ceremony.md).)

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
           roads?, addrs?, port?}        daemon ──► client
  SessionOpen{modelID}                   client ──► daemon
  SessionOpened{sessionID, token,
                capabilities}            daemon ──► client
```

`Hello.versions` defaults to every dialect the app supports. The daemon chooses
its first preferred common dialect before opening a session and echoes it in
`HelloAck.version`; no intersection returns `ErrorFrame(code: "wire-version")`
and creates no session. The client rejects a selection it did not offer. That
selected value then belongs to the session: generation begin and re-attach,
grants, keepalives, events and acknowledgements are all gated by it rather than
falling back to the process's preferred dialect.

`HelloAck.roads` is the endpoint-specific declaration: every entry is
`{host, port}` because gateways may translate the session mapping to a port
other than the listener's internal port. A client prefers this list, re-dials
its candidates in parallel, and keeps the first that connects. The list arrives
over an already mutually authenticated stream, so trusting it grants nothing
that mTLS did not already grant.

`addrs` plus `port` is retained as the legacy projection. It contains local
addresses and may include a mapped address only when that mapping preserved the
configured session port. An old client therefore never combines an external
address with the wrong port; a new client can use every endpoint. Missing
`roads` means the legacy shape, not an empty declaration.

The client also **keeps host and port together**, in the keychain beside the CA it pinned, so
they outlive the process that learned them and the app install that learned
them. That is what lets a session be *born* away rather than only survive
going there: a cold launch on a network that has never seen this cluster
races the roads it kept alongside the address it was configured with, and the
chain decides which of them is the cluster. Loopback is dropped on the way in
— the daemon's declared set carries it because that set doubles as the server
certificate's SAN list, and on another device it names that device.

All reachability fields are **optional on the wire**, which is the whole
compatibility story: a daemon that predates endpoint-specific roads omits them,
a new client lazily upgrades the old single-port store, and a client receiving
neither form falls back to the address it already had. `roads` adds no new
frame type and leaves dialect v0 unchanged.

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

**The cap is a bound on replay, not on the answer.** A generation that outruns
it while nobody is acking loses its oldest un-acked events, and a re-attach
asking for a sequence inside that loss is **refused** — `reattach-rejected`,
carrying a sentence about what happened — rather than served the far side of
the gap. Serving it would hand back a shorter answer than the one that was
generated, with nothing in the stream to say so. Reaching the cap needs 4 MiB
in flight faster than acks return, which is past text scale; what happens to
the cap itself at image or audio scale is residency-depth work and is not
settled here.

The generation is owned by the session registry, not by the connection that
started it. When the transport dies the generation **keeps running** for a 120 s
residency window; completed generations are held 600 s so a client that
reconnects late still collects its ending. Re-attach is therefore not a retry:

```
  GenerateReattach{sessionID, token,
                   genID, fromSeq}           client ──► daemon
  Ev{seq: fromSeq+1, …}                      daemon ──► client   (replay, then live)
```

Frame types **5 and 6 are reserved, not free.** They were `SessionResume` and
`SessionResumed`, a preamble for asking what became of several generations
before choosing one to re-attach. No client ever sent one, and re-attach does
the whole job in a single trip: it is a lossless handover, not a probe that
costs the generation something, so there was nothing a status call bought
first. The frames are deleted; the two type bytes stay retired, because a
daemon of this version still reads them as a resume and reusing them would be
silently misparsed rather than refused.

A `GenerateBegin` carrying a genID the daemon already knows is treated as a
re-attach from sequence 0 — which makes losing the very first frame
recoverable instead of fatal.

`GenerateCancel` ends it early; the client's own task cancellation is what
sends it, and the generation finishes `.cancelled` rather than vanishing.

A session holds any number of generations, keyed by generation id, and nothing
caps them. One in flight at a time is what every client does and what the tests
cover — it is a convention, not an invariant the daemon keeps.

### What a daemon restart does

Residency is a promise about a *process*. Nothing in the session registry
survives the daemon exiting, and that is the design rather than a gap: the
transcript, the tool definitions and the schema ride the wire on **every**
`GenerateBegin`, so the daemon holds no conversation between generations. A
restart therefore costs a round trip, not a conversation.

- **Identity, grants, the CA and the mesh survive** — they are on disk.
- **Sessions do not.** A `GenerateBegin` on a session the daemon no longer
  knows is refused `begin-rejected`, and the client opens a fresh session and
  begins again. Nothing reaches the person. This is also the ordinary path when
  a session simply ages out, which it does after 900 s idle.
- **A generation in flight is lost, and cannot be resumed.** Its buffer went
  with the process. The re-attach is refused `reattach-rejected`, and because a
  re-attach is only ever sent for a generation the client has already taken
  tokens from, that refusal is terminal: **the transport never silently
  re-begins an answer a person may have read, or one whose tool already ran in
  the app.** Re-asking is the app's call.

The daemon cannot tell a restart from a session that aged out — both are a
table with no such row — so it does not claim to. It says what is true either
way, and the client says what it means:

```
  the answer stopped partway and cannot be picked up again: the cluster has
  no session by that name — it was let go after sitting idle, or the daemon
  holding it restarted. Asking again starts a new one.
```

**Seam, named rather than implied:** a generation that outlives the process
would need per-generation durability, which is not built and is not the same
item as remembering a session. Measured on the rig at the time of writing: with
a supervisor putting the daemon back, an app learns its answer ended about ten
seconds after the process died; with nothing restarting the daemon, the client
spends its full residency window first, because from its side an absent cluster
and a walk out of range are the same thing.

## The event vocabulary

```swift
case responseAppend(entryID:text:segmentID:tokenCount:)
case responseReplace(entryID:text:segmentID:tokenCount:)
case reasoningAppend(entryID:text:segmentID:tokenCount:)
case toolCallAppendArguments(entryID:id:name:content:tokenCount:)
case usage(inputTokens:outputTokens:)
case finished(.complete | .cancelled | .error(String))
```

`toolCallAppendArguments` is emitted. It maps one-to-one onto the framework's
factory chain — `Event.toolCalls(entryID:action:)` →
`ToolCalls.Action.toolCall(id:name:action:)` →
`ToolCall.Action.appendArguments(_:tokenCount:)` — which is the only place a
framework tool-call event is constructed, on the client side, per S4's
construct-only finding. One turn's calls share an `entryID`, because the
framework groups them under a single `toolCalls` transcript entry.

**A tool round trip needs no new frame and no new session state.** The model
turn ends with the call in its transcript; the framework runs the tool in the
adopting app and re-invokes the executor with the transcript extended by
`toolCalls` and `toolOutput` entries; the daemon renders those and continues.
Sequential generations on one session, so the one-in-flight invariant holds.
The daemon never executes anything — it asks, and it is answered.

## The request

`Transcript` and `GenerationSchema` are natively `Codable` and ride as
themselves — a real framework-built transcript survives encode, decode and
re-encode byte-identically, and there is a test that says so. Only the options
types need hand mirrors: `WireGenerationOptions`, `WireContextOptions` and
`WireToolDefinition`, each with a `native()` round trip. That file is a seam,
not a design: when the framework core open-sources, the mirrors are deleted and
native conformances take their place.

When `schema` is present, reachd deterministically encodes the native
`GenerationSchema` as sorted-key JSON Schema and compiles it before sampling.
Unsupported encodings or grammar constructs are refused — never retried
unconstrained — with `the cluster could not constrain this response to the
requested schema: …`, followed by the engine's nonempty reason. Accepted
grammar deltas cross as the existing `responseAppend` events; reachd derives
usage from the prepared input and accepted output tokens, and reports
`.complete` only after the grammar accepts the response. Exhausting the
request's token budget is an error rather than successful incomplete JSON.
Requests without a schema stay on the established sampler unchanged.

Every offered tool schema is deterministically encoded and compiled before
sampling. The grammar is a model-format-neutral strict JSON envelope,
`{"name": <offered name>, "arguments": <that tool's schema>}`; tool order is
request order, duplicate names are refused, and response and tool grammar
caches have distinct key spaces.

For `.allowed` (and a missing mode), the existing native detector remains the
model's opportunity to choose prose or one or more tools. A parsed call is only
a private proposal: its id, selected name, order and candidate values are
retained, but its arguments never cross the wire. Each proposal is replayed
through that tool's one-alternative grammar under deterministic daemon-only
correction context, and only the accepted arguments are emitted. Repeated and
multiple calls keep source order and share their turn's entry id.

With a response schema and `.allowed`, probe prose remains buffered. A detected
call selects constrained call replay; no call discards the probe prose and
streams the constrained response. `.required` skips the unconstrained probe
entirely and runs the all-tools grammar, so it can produce only a valid offered
call or a legible error; a response schema does not override that requirement.
`.disallowed` still omits tools entirely. Actual probe and guided-pass usage is
summed, cancellation remains cancellation, and `.complete` follows only after
every selected grammar accepts. None of this adds a frame or changes dialect
v0; tool execution remains exclusively in the adopting app.

## Named seams (v0, deliberate)

- **Sampling mode is lossy.** `GenerationOptions.SamplingMode` exposes no
  public read accessor — the `Kind` enum exists but nothing returns it. Greedy
  survives because it is detectable through `Equatable`; every other mode rides
  as `nil` and the host applies its own defaults. The constrained response path
  and tool-argument paths are also currently greedy: their grammars control
  which tokens are legal, not the fidelity of how a legal token is sampled.
  Feedback-worthy upstream, and resolved by the same rebase.
- **Request `metadata` is dropped.** Its values are existential
  `Sendable & Codable & Equatable`, which JSON coding cannot carry generically.
- **Structured partial snapshots do not cross the wire.** The daemon streams
  accepted JSON text deltas and FoundationModels derives its current typed
  snapshots locally; the wire has no structured patch or partial-value event.
  Making those snapshots explicit is named M3 follow-on work, not part of
  response-schema enforcement.
- **Tool arguments arrive whole, not streamed.** Response text still streams
  token by token; a call's arguments cross in one `toolCallAppendArguments`.
  Arguments are grammar-constrained before that event, but the pinned native
  `ToolCallProcessor` exposes only completed candidate calls and the public
  event has no retraction mechanism. Safe incremental argument delivery is
  therefore a Tier 3 M3 seam rather than an implied future chunking toggle.
- **Usage has no ReachKit public accessor.** The daemon counts the real probe
  and constrained passes and the wire carries `.usage`; the client executor
  still drops it because FoundationModels exposes no appropriate update
  surface. A ReachKit-owned usage API remains follow-on work.
- **Bodies are JSON.** Chosen for legibility while the shape is still moving —
  every frame on this wire can be read by a human with a hex dump and patience,
  which during a ceremony debugged at a kitchen table is worth more than bytes.
