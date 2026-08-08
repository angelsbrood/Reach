# Spike verdicts

Each spike runs on a `spike/*` branch that is never merged; what lands here is
the decision. Kill criteria come from the pre-filing plan.

| Spike | Question | Status |
|---|---|---|
| S4 | Does `LanguageModelSession` accept a third-party `LanguageModel`/executor at runtime, and does an MLX filling stream behind the slot? | **PASS** (2026-07-21) |
| S1a | QUIC with mutual TLS between provisioned certificates (client-cert challenge + CA pin), loopback | **PASS** (2026-07-21) |
| S1b | Behavior of the QUIC connection across a Wi-Fi → cellular interface transition (migration vs re-attach) | **PASS** (2026-07-22) — re-attach at the mesh address *is* the transition; migration has nothing to migrate to; `.handover` off |
| S2 | Development-signed packet-tunnel extension carrying WireGuardKit traffic on device | **PASS** (2026-07-22) — kill fired on the personal team, reversed same day by program enrollment; embedded tunnel verified end to end |
| S3 | Headscale as a supervised subprocess with programmatic pre-auth key minting | **PASS** (2026-07-21) |
| S5 | Does a road the user already owns — their own tailnet — work as a Reach candidate without code? | **PASS** (2026-07-24) — by construction, then confirmed on hardware: the session fell to the tailnet with the Reach tunnel down, and the mesh sat idle |
| S6 | How does the framework's session drive a tool round trip through a third-party executor? | **PASS** (2026-08-05) — the transcript loop, and it is forced: the channel is send-only, so no `respond` call can receive tool output. `capabilities` is a hard gate, not a label |
| S7 | Does the slot model emit tool calls the host can parse? | **PASS** (2026-08-05) — `gemma-4-e4b` 5/5, ~0.85 s per round trip; MLX parses the call itself, and the grammar has no escaping, which is why arguments cross whole |
| S10 | What does a pre-negotiation peer actually survive? | **PASS** (2026-08-08) — unknown optional JSON keys tolerated 3/3; unknown type 255 fatal 3/3; authenticated and enrollment ALPN mismatches each ended in opaque `stream open timeout` 3/3 |

## S10 — what an old peer actually survives (2026-08-08)

Measured before the negotiation implementation in the loopback rig, three
times per case:

- An existing frame with an unknown optional JSON key decoded successfully
  **3/3**. This is the additive-field tool.
- Unknown frame type byte 255 failed **3/3** with the exact error `frame type
  255 is not in this protocol version's vocabulary`. A new type is therefore
  never additive by itself.
- An authenticated client offering `reach/255` to a `reach/0` listener failed
  **3/3** as `could not open a connection to the cluster: stream open timeout`.
- An enrollment client offering `reach-enroll/255` to a `reach-enroll/0`
  listener failed **3/3** with the same timeout.

The last two are the retained before-state: ALPN remains the hard boundary for
an envelope change, but dialect incompatibility now reaches the stable
generation-0 envelope and returns a directional `wire-version` frame before
creating a session, consuming a device token, or parking an app request.

## S6 — the framework runs the tool and comes back (2026-08-05)

Three probes in a plain CLI process: a real `LanguageModelSession`, a real
`Tool`, a local executor, no wire and no weights.

- **The transcript loop is not a preference, it is the only shape the API
  admits.** `LanguageModelExecutorGenerationChannel` is send-only from the
  executor's side — there is no path by which one `respond` call receives tool
  output. The session runs the tool in-process and **re-invokes** the executor
  with the transcript extended by `.toolCalls` and `.toolOutput`. Observed:
  `instructions | prompt | toolCalls | toolOutput | response`.
- **`capabilities` is a framework-enforced gate.** A model declaring
  `LanguageModelCapabilities([])` handed a tool-bearing session does not
  silently ignore the tools: the framework throws
  `LanguageModelError.unsupportedCapability` and `respond` is **never called**.
  So declaring `.toolCalling` is what makes tools reachable, and it must land
  with working support rather than ahead of it.
- **`GenerationSchema` encodes to JSON Schema** — `type`, `properties`,
  `required`, `title`, `additionalProperties`, `x-order` — and survives a
  `Codable` round trip byte-identically. A tool spec is therefore one
  `JSONEncoder` away, which is exactly how Apple's own adapter builds it.
- A `toolOutput` carries the **call's** id, not the id of the `toolCalls` entry
  holding it.

## S7 — the slot model calls tools (2026-08-05)

Measured through `reachd selftest --mlx --tools`, which is where it can run:
MLX's metallib is only locatable in an executable layout, so `swift test` from
a terminal cannot load it at all.

**`gemma-4-e4b`, 5 runs: 5/5 called the tool**, every run choosing
`Europe/Vienna` for "What time is it in Vienna?", ~0.85 s per full two-turn
round trip warm. The demonstration model does not have to change.

Two facts that shaped the daemon more than the emission rate did:

- **MLX already parses the call.** `MLXLMCommon.ToolCallProcessor`, configured
  from the model's `model_type`, swallows the `<|tool_call>…<tool_call|>` span
  out of the chunk stream and yields a parsed `Generation.toolCall`. The markers
  never reach the daemon, so there is no scanning to do — the case that dropped
  it was a `default: break`.
- **Gemma's call grammar has no escape mechanism.** Its only string delimiter is
  the special token `<|"|>`, and a `}`, `,` or `<|"|>` inside a string value is
  emitted verbatim and is unrecoverable by any parser. That, not convenience, is
  why arguments cross whole.

## S4 — the provider slot is real (2026-07-21)

A third-party `LanguageModel`/`LanguageModelExecutor` conformance streams
through a real `LanguageModelSession` in a plain CLI process: the framework
instantiates the executor via `init(configuration:)`, calls
`respond(to:model:streamingInto:)`, and factory-constructed channel events
surface as `streamResponse` snapshots. No entitlements involved. An
in-process rehearsal of the whole spine — session → executor →
transcript-to-chat mapping → MLX generation (`MLXLMCommon.generate`) →
factory events — streams real tokens, multi-turn included.

Rulings this confirms or forces:

- **Channel `Event`/`Action` payloads are construct-only** on the public
  surface (verified by API grep and runtime Mirror dump: payloads live in
  private storage with no read path). The daemon therefore speaks Reach's
  own wire-event vocabulary natively and never serializes framework Events;
  only the client-side executor constructs them.
- ~~**The announced off-the-shelf `MLXLanguageModel` provider does not ship
  in tagged `mlx-swift-lm`**~~ (checked 3.31.4). **Stale as of 2026-08-05:**
  the repo pins a *revision past that tag* (`83f3ef6dc5bc`, for Gemma 4), and
  that revision carries a whole `MLXFoundationModels` library — a public
  `MLXLanguageModel` and `.Executor`, plus `TranscriptConverter`,
  `SchemaConverter`, `SamplingModeMapper` and `ToolCallingConversions`. It has
  been in the tree the daemon builds against since before the take was shot.
  Every helper is internal, so none of it can be imported, and the adapter is
  an *in-process* FM model where reachd is a wire server — so driving
  `MLXLMCommon` directly behind the slot remains the primary path. Its value is
  as a reference implementation, and it settled two questions for the tool pass.
  **This does NOT trigger the roadmap's FM-core tripwire:** FoundationModels
  itself is still a closed system framework read through a `.swiftinterface`,
  and `GenerationOptions`/`Transcript.ToolDefinition` are still not natively
  `Codable`, so `Mirrors.swift` does not retire.
- First streamed token ~2.1 s after container load (gemma-3-1b-qat-4bit on
  an M5 Pro); warm-cache model load a few seconds, cold download ~95 s.
- Build notes that will bite later if forgotten: the Metal Toolchain is a
  separate Xcode component (`xcodebuild -downloadComponent MetalToolchain`);
  `#huggingFaceLoadModelContainer` requires importing `MLXHuggingFace`,
  `HuggingFace`, and `Tokenizers` (packages: swift-huggingface,
  swift-transformers); `MLXLMCommon` declares its own `LanguageModel`
  protocol, so FoundationModels conformances must be written qualified
  (`FoundationModels.LanguageModel`); `UserInput`/`Chat.Message` are not
  Sendable and must be constructed inside `ModelContainer.perform`.

## S1a — mutual TLS over QUIC holds (2026-07-21)

QUIC between a listener and client on loopback, server identity and client
identity both issued by a throwaway CA: handshake completes, a
bidirectional stream round-trips data, and a cert-less client is refused at
the data plane (stream reset; the tunnel never serves). `ALPN` negotiated;
`sec_protocol_options_set_peer_authentication_required` is enforced.

Transport rulings for the spine:

- **Servers must accept QUIC via `newConnectionGroupHandler`** and take
  streams from `group.newConnectionHandler`; a bare
  `listener.newConnectionHandler` yields stream-connections that stall in
  `.preparing`.
- **Verify blocks need the role-correct SSL policy**: the default policy
  checks `serverAuth` EKU, which wrongly rejects client certificates on the
  server side — set `SecPolicyCreateSSL(false, nil)` when verifying
  clients, then pin anchors to the cluster CA with
  `SecTrustSetAnchorCertificates` + `SecTrustSetAnchorCertificatesOnly`.
- **TLS 1.3 clients reach `.ready` before the server's verdict lands** —
  negative tests (and any client-side "am I in?" logic) must probe the data
  plane, not trust `.ready`.

## S1b — re-attach is the transition (2026-07-21 partial, ruled 2026-07-22)

On an iPhone 17 Pro Max (iOS 27) streaming a long generation from the Mac
over the studio LAN: Wi-Fi switched off mid-stream for ~5 s, then back on.
The visible stream froze, the daemon kept generating inside its residency
window, the client's reconnect loop re-attached when the path returned,
replayed from its last received sequence, and the generation — 2,272
characters — completed intact.

**Scoping, stated rather than discovered:** the migration-vs-re-attach
question for a true Wi-Fi → cellular transition cannot be answered before
the mesh exists, by construction — on cellular there is no route to the
daemon's LAN address, so there is nothing for a QUIC connection to migrate
*to*. Constant addressing across paths is precisely what the WireGuard
mesh provides; the final S1b ruling (and any use of `.handover`
multipath) lands with S2 and the away leg, tested against the mesh IP.
Until then, session-layer re-attach is not just the guaranteed path — it
is the only well-defined one, and it is verified.

### The ruling (2026-07-22) — the away leg answered it by construction

The away leg ran in-building against a travel router we govern: the phone
streaming a generation on our own SSID, then hopping mid-stream to the
building's, so the daemon's LAN address went unroutable exactly as it does
at the door. The session froze for seconds, fell to the mesh address
through the router's WAN port map, and completed; the tunnel's counters
moved with it (47 KiB in, 78 KiB out), so the generation itself rode
WireGuard rather than merely handshaking over it.

**Migration is not the transition, and cannot be.** QUIC migration
preserves the *destination* address and changes only the client's local
path — but the walk-out is precisely the event that makes the destination
unroutable. There is nothing to migrate *to*. Re-attaching at the mesh
address **is** the transition, and it is the only form the transition can
take. The corollary is the good news: once a session rides 10.86.0.1,
WireGuard's own endpoint roaming absorbs every later path change beneath
QUIC, which never sees them — an on-mesh session is path-agnostic by
construction. `.handover` multipath is therefore off everywhere, and the
planned A/B against it is deleted rather than deferred: it would compare a
working mechanism against an inapplicable one.

What made the fall possible is a wire change, not a transport trick. The
daemon's `HelloAck` now declares every address it answers on, the mesh
address among them, over the already-authenticated control stream — so the
list is exactly as trusted as the session carrying it, and trusting it adds
nothing mutual TLS had not already granted. The client keeps those
addresses as dial candidates; on path death or path change it races all of
them and keeps whichever connects first. An `NWPathMonitor` cancels the
live stream the moment the path moves, so the re-dial starts in
milliseconds instead of at the 30 s idle timeout, and `QUICStream.open`
honors cancellation so the race's losers die promptly. A session that began
over Bonjour discovery on the LAN ends up on the mesh without the app ever
having been told either address exists.

The first attempt failed informatively and is worth recording: WireGuard
ingress was already proven — a handshake and 680 bytes arrived through the
port map — but the *session* never followed, because the client dialed the
cluster by its Bonjour service name, which resolves to nothing on a foreign
network. Reachability was never the missing piece; knowing where else to
knock was.

## S2 — the entitlement gate, refused then granted; the embedded tunnel holds (2026-07-22)

**Final verdict: PASS.** The kill fired first and honestly — see below — and
was reversed the same day when the developer account was upgraded to the
paid program. On retry the profiles minted for both bundle ids with the
packet-tunnel entitlement, the go bridge built, and the whole away-leg
data path ran end to end: WireGuardKit inside the extension, handshake
within seconds of Start, and a mutually-authenticated QUIC session
streaming a generation to the daemon's mesh address (10.86.0.1) — ~8 KiB
each way on the interface counters for one session. The official-app
fallback below remains recorded as the exercised de-risk path.

Build frictions worth remembering (all patched in a local checkout at
`~/Library/Caches/reach-vendor/wireguard-apple`; follow-up: push the
two-line fork under the studio account and repoint the project):
wireguard-apple's manifest declares platform constants its own
swift-tools-version (5.3) never had — bump to 5.9; WireGuardKitC.h uses
BSD types without `<sys/types.h>` under the 27 SDK's strict modules; the
wg-quick parser is app code, not part of WireGuardKit — two MIT-licensed
files ride along in the PacketTunnel target; and the go-bridge script
phase must point at the local package path, with Homebrew's go on PATH.

### The kill, as it first fired

The Keeper shell and its packet-tunnel extension built against WireGuardKit
hit the kill criterion at the first gate, precisely and informatively:
*"Personal development teams, including 'Cassandra Spiral', do not support
the Network Extensions capability."* The only team Xcode holds an account
for is a personal one; the packet-tunnel entitlement is not grantable on
it. (WireGuardKit's package build is unverified for the same reason —
signing blocks before compilation.)

Per the plan's pre-authorized demotion, **the official WireGuard app is
now the away-leg path**: the keys are still ours and real, the phone's
wg-quick config travels by QR, and the tunnel's consent dialog is still
the system's own. The proto-keeper app and extension remain in-tree,
buildable the day a paid team exists — the seam is the ceremony's
provisioning target (embedded adapter vs. exported config), nothing in
the wire or the daemon changes. The beat sheet's "no third-party app in
the demo's frame" is honestly weakened to "one open-source app in the
frame" until the account upgrade; the restated milestone at filing prices
the embedded path where it always was, in funded scope.

## S3 — headscale supervises cleanly (2026-07-21)

headscale v0.29.2 (official darwin_arm64 release binary) launched as a
subprocess with a generated config: socket up in under a second, user
created, **pre-auth key minted programmatically**, nodes listed — the whole
sequence scripted end to end in 0.8 s with no interaction. Config
requirements on 0.29.x: explicit `dns.override_local_dns: false` +
`nameservers.global: []` when MagicDNS is off; a non-empty DERP map even
with the embedded DERP server disabled (a STUN-only local region file
satisfies it); a short `unix_socket` path (macOS caps unix socket paths at
~104 chars — Application Support paths are too long);
`preauthkeys create --user` takes the numeric user ID.

Per the mesh ruling, S3's outcome affects only the fallback control-plane
path (official Tailscale client + pre-auth key) and the funded multi-device
ledger; the demo's primary away path is a static WireGuard peer provisioned
through the ceremony.

## S5 — a road the user already owns (2026-07-24, code side)

**The question.** Reach ships a mesh so that a civilian always has a road.
But many people already run one — a tailnet, most commonly — and the
honest test of the architecture is whether Reach can *use* theirs without
being taught about it. Concretely: with Tailscale carrying the phone (iOS
grants exactly one VPN slot, so the Reach tunnel is down) and the Mac on
the same tailnet, does a session that began on the LAN survive the hop by
falling to the Mac's 100.x address?

**Verdict: yes, by construction. No code lands.** Three existing pieces
compose into the answer, none of which were written with tailnets in mind:

- `LocalAddresses.ipv4()` enumerates every `AF_INET` interface the host
  holds and filters nothing but a duplicate loopback. Tunnel interfaces are
  interfaces: the mesh's own 10.86.0.1 appears there today, which is why
  the away leg works at all, and a tailnet's 100.x appears the same way the
  moment it is up.
- `HelloAck` carries that list, and the hub turns each address into a dial
  candidate; the race dials them all and keeps the first that connects.
  Nothing ranks or prefers — the race is the arbiter.
- The verify block pins the cluster's CA with a nil host, so *any* address
  presenting the cluster's chain **is** the cluster. A certificate issued
  for LAN addresses authenticates a mesh dial, and would authenticate a
  tailnet dial identically.

So the pre-authorized escape hatch — a trivial interface-inclusion
predicate, which would also have governed which addresses the server
certificate honestly claims — is not needed and is not written. Systematic
VPN interop stays where it was scoped: M3.

**Boundaries, stated rather than discovered.**

- Candidates are learned when a session opens. A road that appears
  *mid-session* is picked up at the next session open, not retroactively.
- A cold start away from home has no learned candidates at all: discovery
  is mDNS, which does not cross a foreign network, and nothing is persisted
  between launches. The demo's shape — a session begun at home, walked out
  of the door — never meets this, but a shipped product would; candidate
  persistence is named M3 work, not a defect discovered late.
- Loopback is declared to every peer and is meaningless to all of them
  except a client on the same host (a simulator, where it is exactly right).
  Off-box it is refused immediately and costs one failed dial in a race
  that was already parallel.

### Confirmed on hardware the same day (2026-07-24)

Tailscale was brought up on the Mac (split-tunnel, no exit node) and the
daemon restarted. It announced itself without being asked to:

    [reachd] Reach Cluster serving gemma-3-1b on :47337
             (127.0.0.1, 192.168.8.104, 10.86.0.1, 100.66.143.31)

— loopback, LAN, first-party mesh, and tailnet, in one list, from one
`getifaddrs` walk that knows nothing about any of those categories.

On the phone, enabling Tailscale takes the single iOS VPN slot and drops
the Reach tunnel, which is what makes the test honest: the first-party
mesh is *unavailable*, so only the tailnet can carry. A generation was
started on the LAN and the phone was moved to a foreign network
mid-stream. It completed.

Which road carried it, evidenced both ways. Positively: the tailnet peer
showed `active; relay "sfo", tx 299660 rx 79460` — 293 KiB pushed from the
Mac, the size of the generation. Negatively: the WireGuard peer's last
handshake was 4 m 36 s old, and WireGuard rekeys every 120 s whenever it
has anything to send, so a handshake that stale is proof the mesh sat idle
straight through the run.

The relay is worth dwelling on. The Mac sits behind a travel router,
behind a building router, behind a router-level VPN; direct traversal
failed and Tailscale fell back to its own DERP relay in San Francisco.
Reach neither knew nor cared. It dialed 100.66.143.31 because that address
had been declared over an authenticated control stream, and the road
worked out how to be a road. Reach ships no relay by design; a road that
brings its own is that road's business. **Reach always brings a road,
gladly uses yours, and the session never learns which one it took.**
