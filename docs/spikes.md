# Spike verdicts

Each spike runs on a `spike/*` branch that is never merged; what lands here is
the decision. Kill criteria come from the pre-filing plan.

| Spike | Question | Status |
|---|---|---|
| S4 | Does `LanguageModelSession` accept a third-party `LanguageModel`/executor at runtime, and does an MLX filling stream behind the slot? | **PASS** (2026-07-21) |
| S1a | QUIC with mutual TLS between provisioned certificates (client-cert challenge + CA pin), loopback | **PASS** (2026-07-21) |
| S1b | Behavior of the QUIC connection across a Wi-Fi → cellular interface transition (migration vs re-attach) | pending — needs device |
| S2 | Development-signed packet-tunnel extension carrying WireGuardKit traffic on device | pending — needs device |
| S3 | Headscale as a supervised subprocess with programmatic pre-auth key minting | **PASS** (2026-07-21) |

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
- **The announced off-the-shelf `MLXLanguageModel` provider does not ship
  in tagged `mlx-swift-lm`** (checked 3.31.4; it lands with the FM core
  open-sourcing, announced for later this summer — the tripwire already
  watched). Driving `MLXLMCommon` directly behind the slot is the primary
  path, not a fallback.
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
