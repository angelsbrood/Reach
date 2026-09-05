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
