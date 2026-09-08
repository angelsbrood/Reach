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

Bodies are JSON in both supported dialects. A frame is capped at 16 MiB — far beyond
text-generation scale, and a hard stop against a nonsense length from a broken
or hostile peer. A zero length is rejected, and an unrecognized frame type is
an **error rather than something to skip**: a peer that cannot name what it was
sent should not guess. `FrameReassembler` takes arbitrary chunks off a stream
and yields whole frames, one instance per stream direction.

### Compatibility contract

The ALPN names the **envelope generation**; `Hello`/`HelloAck` negotiate the
JSON dialect carried inside it. The envelope remains generation 0 while the
current JSON dialect is v1 and peers offer `[1, 0]` newest-first. These are
deliberately separate constants. A dialect-only bump keeps `reach/0` and lets
the daemon select its first preferred common value. Only a change to the
length/type/body framing earns a new ALPN and deliberately partitions peers
that cannot parse one another's envelopes. Serving multiple ALPNs waits until
such a framing change exists.

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
| **2** | `HelloAck` | version, cluster, models, **roads?**, **relayRoads?**, addrs?, port? |
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

The private Linux service candidate carries this same session road through
MsQuic 2.5.11 using IETF QUIC v1, TLS 1.3 and `reach/0`. Disposable Ubuntu arm64
checks exercised private-CA authentication, peer-DER handoff and production
Apple transport interoperability. The Linux listener admits at most 16
connections, eight bidirectional streams per connection and 16 active streams
process-wide, with zero peer unidirectional stream credit. A compliant sender
can remain blocked on stream credit; that differs from an application refusal.
Unknown frame types and declarations above 16 MiB are refused before allocating
an oversized body or invoking a provider. There is no resumption or 0-RTT path.

The Linux service retains the shared generation/replay contract below: a stream
reattaches to the same generation after its acknowledged sequence, without a
second provider command or admission lease. Its 30-second transport idle
timeout is distinct from the 120-second detached residency window, swept on an
absolute one-second schedule. Shutdown awaits owned transport, host and provider
work within one shared 15-second deadline. See [the service candidate boundary](running.md#private-linux-service-candidate)
for the scope of these private installed-service checks.

On macOS, both are found over Bonjour — `_reach._udp` for sessions,
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
subscription visibly open, and ReachKit uses a bounded matching-nonce exchange
only while an in-flight generation has been silent.

**Verification pins the chain, not the name.** Verify blocks run with
role-correct SSL policies and a nil host, so no hostname is checked. The
consequence is the architecture: *any address presenting the cluster's chain is
the cluster*. A session dialed at a LAN address, a mesh address, or an address
on a tailnet the daemon happens to sit on is the same session to the same peer,
and nothing above the transport has to know which one it took.

## The control stream

Client-opened. The session-opening exchange may remain as that road's active
generation probe channel; when it has closed, ReachKit lazily opens a
Hello-only authenticated control stream through the exact same dialer. That
replacement does not send `SessionOpen` and therefore does not create another
session.

```
  Hello{versions, client}                client ──► daemon
  HelloAck{version, cluster, models,
           roads?, relayRoads?,
           addrs?, port?}                daemon ──► client
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

`HelloAck.roads` is the endpoint-specific **direct** declaration: every entry
is `{host, port}` because gateways may translate the session mapping to a port
other than the listener's internal port. The list arrives over an already
mutually authenticated stream, so trusting it grants nothing that mTLS did not
already grant. Relay aliases never enter this field or legacy `addrs`.

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

Dialect v1 adds a second, deliberately separate calling card:
`HelloAck.relayRoads`. It has three authenticated meanings:

- omitted preserves the relay candidates already stored for this cluster;
- `[]` authoritatively clears them; and
- a nonempty array atomically replaces them.

Explicit `null`, duplicates, malformed endpoints, noncanonical or non-private
hosts, and zero ports are rejected. The field is interpreted only when the
selected session dialect is v1. A newly built client speaking selected v0
ignores it and neither refreshes nor clears its relay state. Relay candidates
live under the separate Keychain service
`systems.reach.cluster-relay-roads`; no endpoint migrates between that record
and `systems.reach.cluster-roads`, and deleting the cluster identity deletes
both. If one store is unreadable the other remains independently usable; an
unreadable tier is never treated as an empty declaration.

S32 selected a **100 ms direct-preference hedge**. Direct candidates start at
time zero. Relay candidates start 100 ms later unless a direct has already won.
That positive grace made the measured 20 ms healthy-direct arm deterministic
against an immediately completing relay; at 0 ms the relay correctly won.
Every attempt still shares the existing absolute ten-second
deadline and every loser is cancelled. A cached road is reused only while its
authenticated session exists; invalidating that session makes the next
independent open return to the tiered race, so a blackholed former direct
winner cannot consume the deadline alone. A healthy relay session or resident
generation is not interrupted merely because a direct road later appears.
Reattachment uses the same tiering while preserving generation ID, replay
cursor, residency, and provider admission.

Only the currently authenticated road epoch may commit a v1 declaration. A
delayed control/probe reply cannot overwrite newer persistence. Accepted
sessions, generation receipts, and reattachments classify a source as
`relay-overlay` only when it falls inside the operator-configured relay prefix;
that privacy-safe label contains no endpoint, identity, prompt, output,
certificate, or token count. Keeper and enrollment do not consume this field;
device provisioning remains separately Held.

The corrected installed S32 authority is reachd `a9660a83…6b790` with the
unchanged helper restored to canonical direct-only generation 37. Its exact v0
client, v1 replace/preserve/clear, 100 ms direct-first and relay-only opens, and
both same-generation transition directions passed before that restoration.

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
replay store. The store retains the deterministic encoded `Ev` frame, not an
estimate of its Swift value: one generation may hold exactly one maximum v0
frame including its length prefix (**16,777,220 bytes**), and the process may
hold four such windows (**67,108,880 bytes**). Acknowledgement releases those
exact bytes and destroys the popped frame payload immediately; queue metadata
may compact later, but it retains no acknowledged or capacity-dropped `Data`.

**The bounds are on volatile replay, not on the answer or live delivery.** If
an append crosses either bound, the store may reclaim only older events from
that same generation. It never evicts another generation to make room. The
current stream continues, but the lost cursor is remembered; a re-attach
asking inside that loss is **refused** with the existing
`reattach-rejected`/`replayOutgrewTheBuffer` outcome rather than served the far
side of a gap. A request after the loss may still replay when its cumulative
cursor proves it already received everything discarded. Every replayed frame
is decoded and checked against its indexed sequence before it is served;
corruption invalidates that window and refuses rather than inventing a hole.

One event whose encoded envelope itself exceeds the wire's 16 MiB frame limit
cannot be delivered to any peer. The daemon replaces it at the same sequence
with a small `.finished(.error)` explaining that one event exceeded the frame
limit; admission is released as an error derived from that actual stamped
terminal, and it never reports incomplete output as success. Queued
generations have no events and consume zero replay bytes. The store is
memory-only and is
cleared on daemon shutdown, so none of these capacities imply transcript or
generation durability across process death.

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

### Provider admission

Residency and model execution are deliberately separate. The current MLX
filling declares capacity for one **public generation**. One generation may be
executing and three more may be resident in one global FIFO waiting room, with
at most one waiter from any session. The lease belongs to the generation, not
to its QUIC stream: duplicate begin, detach and re-attach neither enqueue nor
execute it again. Response-schema compilation, tool probing, constrained tool
replay and required calls are internal passes under that same lease.

The observable states are:

- **queued** — resident, receipt emitted and re-attachable, but model
  preparation has not begun and no replay bytes exist yet;
- **executing** — the generation owns the provider lease, including all of its
  internal model passes;
- **resident-detached** — queued or executing work whose current transport is
  gone; it retains the same reservation during the residency window;
- **replay-only** — terminal work retained for replay, with no provider lease;
- **completed** — terminal and retained for the ordinary completed window; and
- **reachable-but-busy** — no generation record was created because the three
  waiting places were occupied, or that session already had a waiter.

The last state uses the existing v0 `ErrorFrame` with code `cluster-busy`.
Because it is an authenticated service refusal, ReachKit surfaces its sentence
without dirtying the road, reopening the session or retrying the request. A
queued generation that has not acquired the lease after 120 seconds instead
finishes as an ordinary generation error saying that the cluster stayed
reachable; its filling is never invoked. No queue survives daemon restart and
no queue state is added to the wire.

The full-room refusal is: “the cluster is reachable, but its model slot and
three-place waiting room are full — ask again when current work finishes”. A
second waiter from one session is refused with: “the cluster is reachable,
but this session already has a generation waiting for its model slot — let it
finish or cancel it before asking again”. A queued timeout ends its resident
generation with: “the cluster stayed reachable, but this generation waited
120 seconds without reaching its model slot — ask again when current work
finishes”. These are service outcomes, not evidence about road health.

### Active-road liveness

ReachKit arms a two-second silence watchdog only after `GenerateBegin` or
`GenerateReattach`, and resets it on every `Ev`, including replay duplicates.
There is no idle polling. When a generation stays silent for that interval,
all concurrent generations using the same road coalesce behind one `Ping` on
that road's authenticated probe channel. The same two seconds bound its
matching `Pong`.

A pong with the exact nonce proves the daemon is alive on that road, so the
client keeps waiting while the model is queued or preparing its first token.
Provider admission separately caps a queued generation at 120 seconds and
then sends a terminal generation error; that reachable ending is not a road
failure. A stale, wrong, late, closed or errored pong proves nothing. One
bounded missing pong makes the current road dirty only if no generation event
arrived during the probe; an event is stronger evidence than a failed control
stream.
The existing road race then reattaches from the last received sequence. Before
the first event it resends the same idempotent `GenerateBegin` and receives a
fresh ten-second cold-open budget. Once any `Ev` has arrived, the attempt has a
resident generation to recover and every later stream ending or path change
uses the 120-second residency deadline, even when that attempt originally
opened inside the cold budget. A stale result from an older road epoch cannot
dirty its replacement, and a probe channel is released when its last generation
lease ends.

Successful recovery is invisible to the app. Exhausting every candidate keeps
the existing “no road reached the cluster” refusal. The only new diagnostic is
a privacy-safe notice containing elapsed silence and the internal road epoch;
it contains no endpoint, identity, prompt or token data. These rules use the
baseline-v0 `Ping`/`Pong` vocabulary and change no compatibility boundary.

`GenerateCancel` ends it early; the client's own task cancellation is what
sends it, and the generation finishes `.cancelled` rather than vanishing.

A session may own several generations keyed by generation id, including one
executing and one queued, but it may contribute only one generation to the
global waiting room. Provider capacity is therefore enforced without reviving
the old and incorrect “one generation per session” convention.

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
- **A generation in flight is lost, and cannot be resumed.** Its exact replay
  frames went with the process. The re-attach is refused `reattach-rejected`, and because a
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

### Five different kinds of recovery

S27 measured the process boundary rather than treating every saved byte as
durability:

- **Volatile transport replay** is shipped. Exact framed events survive a road
  or stream change while the same daemon process and generation record live.
- **Launchd service recovery** is shipped. It starts a coherent daemon with the
  same cluster identity, grants, roads and model configuration; its session,
  admission and replay tables begin empty.
- **KV-cache serialization** exists in the pinned MLX dependency. It stores
  model tensors, but not one versioned checkpoint containing the iterator
  token, sampler/RNG, logit processor, detokenizer, usage, event cursor,
  grammar matcher, tool parser or call identity. S27 also found truncated and
  bit-flipped cache files that the loader accepted, so this surface is not an
  execution-integrity contract.
- **Exact public-generation durability** is not shipped. Ordinary, guided,
  allowed-tool and required-tool routes all lack complete serializable state.
  Persisting only one route, or only completed output, would not satisfy the
  public generation's identity and no-duplicate-output promise.
- **Tool effects are client-owned.** Once a call crosses the wire, the daemon
  cannot know whether the adopting app executed it. Exactly-once recovery would
  require an explicit acknowledgement or idempotency contract; restarting the
  model and minting another call is not recovery.

The measured stop deliberately adds no transcript database, worker, frame,
dialect or partial checkpoint. A client that had already observed the lost
generation still receives the sentence above and must explicitly ask again.

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
Requests without a schema use the unconstrained sampler described below.

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

## Crossing-value audit

The v0 surface was audited field by field on 8 August 2026. Every encoded
value has one of three outcomes: **HONORED** at the receiving side, **NAMED**
here as an intentional compatibility or product seam, or **GRADUATED** into a
separate design problem. Nothing was removed: required v0 keys remain encoded
for old peers, and the optional context keys remain public intent rather than
dead storage.

| Crossing surface | Verdict |
|---|---|
| `Hello.versions`; `HelloAck.version`, `cluster`, `addrs`, `port`, `roads`; `RoadEndpoint.host`, `port` | **HONORED** — dialect selection, authenticated cluster identity, and endpoint-specific road refresh |
| v1 `HelloAck.relayRoads` | **HONORED** — selected-v1 omission preserves the separate authenticated relay store, empty clears it, and nonempty replaces it; selected v0 ignores it |
| `SessionOpened.sessionID`, `token`, `capabilities` | **HONORED** — generation identity/reattach and the `ClusterDial`/`doctor` capability result |
| `Ping.nonce`; `Pong.nonce`; `ErrorFrame.code`, `message` | **HONORED** — active-road liveness requires an exact, timely nonce match; the daemon echoes it and both sides turn remote refusals into typed failures |
| `GrantEvent`'s request, provenance, app identity and fingerprint; `GrantRule.requestID`, `allow` | **HONORED** — the sheet renders the request and its ruling resolves that same parked request |
| `GenerateBegin.sessionID`, `genID`, `request`; `GenerateReattach.sessionID`, `token`, `genID`, `fromSeq`; `GenerateCancel.genID`; `EvAck.seq`; `Ev.seq`, `event` | **HONORED** — authorization, replay position, cancellation, acknowledgement, ordering and payload all affect generation state |
| Request transcript; tool name, description and parameters; schema; temperature, token limit, sampling and tool mode | **HONORED** — every value that reaches reachd selects prompt, grammar, budget or an actual unconstrained sampler pass |
| `responseAppend`, `responseReplace`, `toolCallAppendArguments`, `usage`, and every `finished` reason, including their ids, segments, text, counts and errors | **HONORED** — response/tool events enter the framework channel; completed usage enters Reach's monitor; endings determine success, cancellation or error |
| Device enrollment token/name/versions, challenge nonce/version, both public keys and proof, certificate/CA, every `WGProvision` field, completion and confirmation | **HONORED** — negotiation precedes token use; proofs, provision, `ok`, and `applyPending` all change ceremony outcome |
| App enrollment bundle/name/versions, challenge, key/proof, grant certificate/CA, and `EnrollComplete.ok` | **HONORED** — negotiation precedes parking; the ruling is correlated to the request; a false close keeps the ruled grant parked and is not logged as success |
| `Hello.client` | **NAMED** — required v0 peer-label copy; decoded but not used for authorization or behavior |
| `WireGenerationRequest.id` | **NAMED** — required v0 crossed copy; the envelope's `genID` remains the daemon authority, while ReachKit correlates completed usage with the native local request id |
| `WireContextOptions.includeSchemaInPrompt`, `reasoning` | **NAMED** — faithfully mirrored public intent that reachd does not currently apply; grammar enforcement is independent of prompt inclusion and reasoning output is disabled |
| `reasoningAppend` and all of its fields | **NAMED** — reserved receiver vocabulary; reachd emits no reasoning event in v0 |
| `HelloAck.models`; `ModelDescriptor.id`, `displayName`, `capabilities`; `SessionOpen.modelID` | **GRADUATED** — the catalog is displayed/sent but does not authoritatively select or refuse a model. The catalog's meaning, authoritative side and mismatch copy are one Held model-selection-authority design item |

`GrantSubscribe` has no body to ignore. The unknown-key rule still makes old
decoders safe when optional fields are added; it does not turn any required v0
field into deletion permission. The v1 relay field is additive rather than a
reinterpretation of a v0 key. `responseReplace` is honored receiver
vocabulary even though today's daemon only appends. Framework request
`metadata` is not in this table because v0 cannot encode it and therefore it
does not cross.

## Named seams (v0, deliberate)

- **Sampling has two remaining boundaries.** `GenerationOptions.SamplingMode`
  exposes no public read accessor — the `Kind` enum exists but nothing returns
  it. Greedy can be detected through `Equatable` and represented on the wire;
  other native modes ride as `nil`. Every explicit value that does reach the
  daemon is now honored by ordinary prose and `.allowed` tool-proposal passes:
  the host default remains categorical temperature `0.6`; negative or explicit
  zero is greedy; `.greedy` overrides temperature; invalid low top-k disables
  that filter; top-p at or below zero is greedy and at or above one is the full
  distribution; seeds reach a fresh pass-local sampler. Constrained response,
  required-call and constrained tool-replay paths deliberately remain greedy.
  S15 showed that sampling through the hard-completion zone can exhaust 512
  legal tokens. S16's hybrid sampled normal/soft choices and completed the
  exact retained matrix 36/36 with hard-zone argmax, but S17 then produced a
  grammar-accepted integer outside Swift `Int` and failed the requested typed
  decode at deterministic seed 29. S18 proved a bounded numeric grammar can
  close that overflow hole: seed 29 decoded and exact integer/finite-Double
  boundary tests passed. It still stopped when the unchanged adversarial
  schema exhausted 512 tokens at temperature 1.0 after 28/36 matrix cases.
  That candidate was rolled back rather than widened into a completion parser
  or larger hand-tuned bias.
  S19 then attacked the installed greedy path directly with `1e309`,
  `2e-324`, both adjacent `Int` overflows and a 100-digit integer, three runs
  apiece. All 15 streams completed as shorter decoder-safe values; no typed
  mismatch reproduced. No Reach schema normalization or dependency pin ships
  for a defect the current path did not reach. Type-safe numeric grammar
  semantics remain architectural hardening, and become a prerequisite again
  before any future constrained-sampling path can be considered safe.
  The framework accessor and constrained typed-completion problem remain
  separate follow-ons; none is described as on-device equivalence.
- **Request `metadata` is dropped.** Its values are existential
  `Sendable & Codable & Equatable`, which JSON coding cannot carry generically.
- **Foundation Models' locally derived snapshots are the current authoritative
  structured surface.** The daemon streams accepted grammar-constrained JSON
  text deltas; Foundation Models turns that same incomplete JSON into
  `Snapshot.content` and `rawContent` on the client. S28 completed 21/21 real
  TLS/wire/daemon/guided executions and found no structured information absent
  from that text-derived surface. The framework executor exposes no public
  action for injecting a server-authored `GeneratedContent`, so a wire partial
  would add a second cadence and authority rather than replace the text stream.
  Whole-value and JSON-Pointer candidates were payload models only, not codecs
  or replay proofs. An explicit structured event is Held behind either a real
  non-Foundation-Models consumer or a public structured executor action; it
  would still require negotiated vocabulary and a fresh ordering/authority
  ruling. Dialect v0 retains no structured patch or partial-value event.
- **Tool arguments arrive whole, not streamed.** Response text still streams
  token by token; a call's arguments cross in one `toolCallAppendArguments`.
  Arguments are grammar-constrained before that event, but the pinned native
  `ToolCallProcessor` exposes only completed candidate calls and the public
  event has no retraction mechanism. Safe incremental argument delivery is
  therefore a Tier 3 M3 seam rather than an implied future chunking toggle.
- **Completed usage is Reach-owned.** `ReachLanguageModel.usage` is a shared
  `ReachUsageMonitor` for copies of one model and a fresh monitor for a newly
  initialized model. Its async `latest` value and bounded `updates()` stream
  publish one `ReachGenerationUsage(requestID:inputTokens:outputTokens:)` only
  after the matching generation finishes successfully. Cancellation, error,
  replay, and a legacy daemon with no usage event publish nothing. Plain
  generations report backend counts; multi-pass tool and guided routes report
  accumulated prepared-input and accepted-output totals. ReachKit neither
  references nor emits Foundation Models' `updateUsage` action.
- **Context intent is carried but not applied.** `includeSchemaInPrompt` and
  `reasoning` remain optional v0 mirrors. Schema constraints hold whether or
  not the schema is repeated in prompt text; no reasoning event is emitted.
- **Model selection is not yet authoritative.** The model catalog and requested
  model id stay on v0 for compatibility, but their meaning and refusal behavior
  are the Held model-selection-authority seam named by the audit above.
- **Bodies are JSON.** Chosen for legibility while the shape is still moving —
  every frame on this wire can be read by a human with a hex dump and patience,
  which during a ceremony debugged at a kitchen table is worth more than bytes.

## Inactive durable-session vocabulary (S87, dialect 2)

This is an offline protocol/compatibility candidate, **not runtime adoption**.
`Wire.version` remains 1; default offers remain `[1, 0]`, and default envelope
encoding is dialect 0. ALPN (`reach/0`, `reach-enroll/0`), Bonjour/enrollment
defaults and retired frame values 5/6 are unchanged. Only an explicit synthetic
`Wire.negotiate(offered: [2, 1, 0], supported: [2, 1, 0])` selects 2 here.
No production caller advertises a durable profile or opens a durable session.

`FrameType` values 50–60 are introduced in dialect 2. Default, v0 and v1
encoding refuse every value in this band. `DurableMessage.decode` and
`DurableNegotiation.receive` gate the selected dialect **before body decode
or dispatch**. `RawFrame.decode` alone and `JSONDecoder` do not establish a
selected dialect or accepted session. Direct DTO decoding proves syntax only;
the raw-frame boundary additionally checks actual encoded body size.

| Value | Frame | Fields / meaning |
|---|---|---|
| 50 | DurableCapabilities | `modelID`, explicit `profiles`; empty is unavailable |
| 51 | DurableSessionOpen | `requestID`, `modelID`, `profile`, `durable: true` |
| 52 | DurableSessionOpened | Matching `requestID`, `session`, original opaque `ticket` |
| 53 | DurableGenerateBegin | `requestID`, `reference`, original `ticket`, existing `WireGenerationRequest` in `request` |
| 54 | DurableGenerationAccepted | Matching `requestID`, `reference`, `kind: begin/recover`, original `context`, `contextDigest` |
| 55 | DurableGenerateRecover | `requestID`, `reference`, original `ticket/context/contextDigest`, `clientRoot`, `witness` |
| 56 | DurableBatch | `reference`, `contextDigest`, `first/count/commit/skip`, original full `bytes` |
| 57 | DurableReceipt | `requestID`, `reference`, whole-prefix `witness` |
| 58 | DurableReceiptAccepted | Exactly matching `requestID/reference/witness` |
| 59 | DurableToolKnowledge | `reference`, `contextDigest`, exact `callID/name/arguments` bytes, `state`, conditional `outcome` |
| 60 | DurableRefused | Matching `correlation`, bounded `reason` |

The Swift frame aliases use `DurablePacket<...Payload>`; `payload` is flattened
in JSON (there is no `payload` wrapper key). Validate and encode frame packets
through `FrameCodec` or `DurableMessage`, not standalone payload components.
`session` contains `modelID/profile/sessionID`; `reference` contains `session`,
`generationID` and stable `operationID`. A refusal correlation contains
`requestID/operation`, plus `sessionID/generationID` for begin, recover or receipt;
open correlations omit both. A refusal never creates a new operation identity.

### Explicit requester-side selection

`DurableNegotiation` is a pure requester-side checker for one selected
session/generation exchange. It has no runtime callback, provider, clock,
storage, key, automatic identity generation, retry, renewal or fallback path.
The caller supplies a dialect already selected by its handshake and explicit
local opt-in (default false). The only recognized profile is
`reach-durable-session-v1`.

The peer's incoming model-scoped capability declaration precedes an outgoing
explicit durable open. Known profile, matching model and local opt-in are all
required to send that request. Only its matching incoming opened response
establishes protocol selection. A local success DTO cannot do so. Missing or
unknown capability, disabled opt-in and incompatible model/profile fail with
typed `DurableWireError`; declaring capability alone never accepts a session.

Begin uses the selected reference and original ticket. S88 also allows a fresh,
declared, opted-in requester to send recovery using its original ticket and
reference from selected disk state, without opening a replacement session.
This enters pending `recovering`; it does not fabricate opened or accepted state.
Known profile and the exact configured model remain required. Pending exchanges
reject capability/open overwrite. The original ticket and session remain selected
after the matching recovery acceptance and on subsequent recovery.

The matching
incoming accepted response must name the pending request, generation/operation
and kind. Recovery preserves exact original context and client-root/witness
bindings; it has no create/begin fallback. Batch, receipt and knowledge require
the accepted generation/context. Receipt acknowledgement must match the entire
pending witness. Failed decode, send, direction or correlation checks leave
state unchanged. `observeVolatileOpen` discards durable state: an ordinary
SessionOpen remains volatile even at dialect 2.

A matching refusal is possible during open, begin, recovery or receipt. It is
returned as a typed `.refused` message and closes the exchange; it does not
silently begin volatile work. Reasons are `unavailable`, `incompatible`,
`unauthorized`, `expired`, `unknown-lost`, `invalid` and `busy-full`. Stale or
unrelated replies cannot establish selection. The checker's `accepted` phase
means correlated protocol selection,
not authenticated caller admission or persistence readiness.

### Data bounds and authority

All new frame packets validate constructed values on encode and decoded values
on decode. Required fields reject omission and null; enums are strict. Optional
outcome/correlation fields reject explicit null and conflicting presence.
Unknown optional JSON keys remain additive. Profile-list uniqueness is semantic
validation; **JSONDecoder does not guarantee duplicate object-key rejection**.

- Profile lists contain at most eight unique, nonempty ASCII names of at most
  64 bytes each. Other free identifiers are nonempty UTF-8 of at most 256 bytes.
  Session and client-root UUID strings use canonical lowercase spelling.
- Original opaque ticket bytes are 41–4,096 bytes. Original opaque client
  context is nonempty and at most 1 MiB. Both remain exact binary `Data` carried
  in base64; their interiors are never decoded/re-encoded by ReachWire.
  Wire checks only digest spelling; it does not recompute or authenticate the
  context's digest. A trusted adapter must verify its relation to the original
  bytes and current authenticated retained state. Recovery correlation preserves
  both the original context bytes and the declared digest independently.
- The full S84 witness contains `version: 1`, `policy: s84-host-client-v1`,
  `context`, `clientRoot`, UInt64 `revision/high`, `terminal`, `prefix`,
  `registrations` and `calls`. Digests are lowercase 64-hex. High is at most
  65,536; high zero requires revision zero, nonterminal and zero registrations;
  positive high requires positive revision. Registrations are 0–32.
- Durable first/high is **one-based**, with high zero meaning no durable
  receipt. Legacy Ev/EvAck keeps its zero-based event sequence. Terminal does
  not mean tool effects completed; this receipt is not an app-display receipt.
- Batch first is positive; count is 1–4,096; checked last is at most 65,536;
  skip is `0..<count`; commit is lowercase 64-hex. Full original batch bytes
  are nonempty and at most 8 MiB, preserved even for positive skip. Parsing
  neither truncates to the suffix nor verifies committed history/boundaries.
- Call ID/name/argument bytes preserve exact UTF-8 identity, limited to
  256/1,024/8 MiB, with nonempty ID/name. `state: unknown` has no outcome;
  `state: known` requires an S83-shaped outcome with version 1, kind
  `success/failure`, exact result bytes and digest. Its sorted, unescaped-slash
  canonical JSON is at most 1 MiB, including base64 and JSON overhead. Carrying
  the digest does not verify its trusted S83 call/context binding.
- The transport cap remains 16 MiB (type plus body). New control JSON bodies
  are at most 2 MiB; batch/tool-knowledge JSON bodies are at most 14 MiB,
  including overhead and unknown optional keys. Only the new band uses sorted
  JSON keys **with unescaped slashes**. Legacy encoding remains byte-identical.

No ticket is issued or MAC-verified, record created, receipt committed, effect
executed or caller authenticated by this module. Wire data carries no local
paths, keys, injected clock, `allowed`, create flags or retained caller authority.
Knowledge and acknowledgements grant no invocation permission. Missing/unbegun/
unknown outcomes must not become known failure, automatic retry or a claim that
an effect never executed.

Adapters must verify tickets, original context, witnesses, prefix/call
history and outcomes against current authenticated retained state before acting.
Issued/expiry values inside opaque data remain in the **issuer's clock domain**;
do not compare remote raw monotonic time to local monotonic time or renew it.
S83's same-host clock policy is not a solved cross-host policy. Changed/missing
state requires honest refusal or uncertainty. Runtime capability readiness,
authorization/consent, remote persistence and retention are later adoption work.

HelloAck's existing relay declaration semantics apply at v1 **or later**. This
narrow codec inheritance preserves all v0/v1 bytes and does not advertise v2.
The offline `Tools/DurableSessionProtocol/run.py` comparison binds those changed
bytes against committed S86 source. The unavailable historical golden corpus
is excluded explicitly; skipped/no-op tests are not new S87 proof.

### Offline adapter candidate (S88)

`Tools/DurableSessionWireAdapters` connects this vocabulary to the real S82–S86
implementations through separate host and client adapters. It uses current full
ReachWire sources, a bounded raw binary frame lane and local same-boot fixtures.
Both entries require explicit dialect 2, opt-in/readiness and the configured model
and profile before durable entry. It does not change shipping dispatch or offers.

The host derives sessionID from the issuer-verified ticket namespace, checks the
current exact caller and issuer clock, and rechecks authorization before publication.
Complete canonical WireGenerationRequest bytes, original request UUID, model,
profile, route and adapter revision bind the stored provider request ID; the
wire operation ID binds its operation ID. Only the explicit deterministic tiny
`ordinary` and `required` request mappings are supported. Native fixture preparation
is local host glue, not a general prompt preparer or remote authentication policy.

Fresh client entry supplies bootstrap location and current local authorization.
S85 acquisition and S86 selected encrypted state supply its original ticket/context;
the host verifies retained request/history and S84 attachment before returning the
real acceptance. Original batch bytes and first/count/commit/skip cross the wire
unchanged. Client S83 receipts are checked by S84 before host retirement. Exact
receipt retry uses the retained tombstone fingerprint and does not require live
request/context export after retirement.

Tool knowledge is read from the authorized selected journal, or checked as a
read-only peer report against retained context/call/outcome bindings. Receiving it
cannot create intent, grant permission, overwrite a local outcome or attest that
an effect ran. The required-tool fixture keeps its counted local effect and trusted
completion oracle separate from wire reports. Client knowledge remains independently
readable after host retirement. Remote transport adoption, cross-host clocks and
real tool effects remain outside this candidate.

S89 adds a trusted-local selected-request policy to these tool adapters while
retaining the fixed S88 policy by default. The new `Tools/DurableRequestPreparation`
candidate binds complete canonical requests and a locally selected immutable
model/tokenizer/template/policy descriptor, then prepares bounded ordinary text
or explicitly required tools through the public synchronous chat-template path.
Its actual tokens, resolved options and stable IDs are persisted in the existing
provider binding. First begin acceptance checks the client's exact locally sent
binding before journal enrollment. Fresh recovery validates the selected policy
and stored preparation before host attachment/acceptance, then restores without
request preparation or replacement tokens/options/IDs/seed. No frame layout or
shipping capability/dispatch changes. S89's offline tiny-Llama proof uses known
non-secret disposable fixture keys; S88's Keychain/acquisition/crash evidence is
reused for its unchanged scope.

S90 extends that same preparer with the owner-selected
`s90-public-chat-schema-v1` revision; `s89-public-chat-tools-v1` stays the default.
The schema route requires a portable response schema, no offered tools/reasoning,
no required tool mode, explicitly false `includeSchemaInPrompt`, nil/greedy sampling
and nil/zero temperature. Maximum tokens defaults to 512 and accepts 0...512.
Throwing extraction applies the existing shared whole-request bounds before full
serialization. Schema bytes feed the guided grammar, while text/history use the
same chat-template path; schema-only changes may preserve tokens but change the
complete request identity and grammar. Stored guided binding validation precedes
attach/acceptance and uses the selected native identity, tokens, canonical schema,
policy and stable IDs. It does not reconstruct a raw request during recovery.
Grammar compilation remains a native boundary after model factory evaluation and
potentially accepted begin, before prefill; portable admission does not promise
arbitrary compiler support. Accepted EOS produces the existing usage/complete tail;
insufficient budget and cancellation do not invent success usage. The additive
`Tools/DurableSchemaPreparation` harness proves actual tiny-Llama selected-disk
continuation with a visible checkpoint prefix and zero fresh request preparation.
Wire layouts, shipping offers [1,0] and default opt-in/readiness are unchanged.

S91 adds owner-selected `s91-public-chat-allowed-v1` on the same local preparer.
With 1...8 unique offered tools, nil/allowed tool mode uses the existing allowed
coordinator; required remains required and disallowed refuses. Tools plus response
schema and context/reasoning controls remain excluded. Actual template tokens and
canonical tool schemas, fixed JSON parser, deterministic entry/parser IDs and one
selected model/cache/codec for both passes form the persisted allowed declaration.
Selected validation runs before attach/acceptance; no raw request is reconstructed
on recovery. Maximum 0...512/default512 applies independently to probe and guided
passes, with nil/greedy sampling and nil/zero temperature; final usage sums passes.
Repair-history/grammar encodes and later new-pass factories/prefills are legitimate
recovery work, distinct from original request preparation. Empty zero-budget prose
may complete with usage, while guided exhaustion remains non-success. Existing
undeclared-name refusal, ordered settled calls, cancellation and final-ready-wins
semantics remain; no tools execute here. S89/S90 revisions/defaults and all shipping
wire layouts/offers/readiness remain unchanged. The additive offline harness proves
Llama prose continuation and separately bound structural two-call integration;
it does not claim newly executed Llama-guided tool selection or production adoption.
