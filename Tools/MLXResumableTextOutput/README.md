# MLX resumable plain-text output candidate

S73 adds a local paused text-output layer over the accepted S72 raw-token
candidate. It is a dependency patch for review, not upstream adoption or Reach
runtime durability. No production dependency, service, parser or route changes.

## Compose and pause

`ResumableTextOutput.prepare` takes the declared S72 model, prompt tokens, raw
identity/options/cache specs/codecs, plus an immutable deterministic tokenizer and
`ResumableTextOptions`. It returns C0 with the raw driver's already-settled pending
token. `capture()` freezes the matching raw and output state in one value.

`advance()` consumes at most one raw token and returns a `Batch`: the raw token
(if any), ordered text/terminal records, and the exact post-batch checkpoint.
Even a step with no visible text returns its checkpoint. There is no queue,
AsyncStream producer, pending delivery cursor or host acknowledgment protocol.
Text records contain UTF-8 `Data`; compare bytes and chunk boundaries, not Swift
String canonical equivalence or whole-sequence decode.

This lane explicitly disables parsing. JSON, braces and tool markers remain
literal text except for configured stops. Legacy `tools: nil` still creates a
tool parser and is not this lane's output oracle. No chat template, detokenizer
replacement, grammar, tool coordinator or reasoning-channel split is introduced.

The unchanged pinned `NaiveStreamingDetokenizer` supplies common-prefix emission,
incomplete-byte suppression and newline last-token reset. The unchanged
`StopStringFilter` supplies empty-stop normalization, earliest complete match,
partial-prefix retention and one unmatched-prefix flush at termination. A shorter
completed stop wins immediately; incomplete detokenizer bytes are never flushed.

| Transition | Returned semantic output |
| --- | --- |
| Ordinary raw token | Count it even if its text is hidden or buffered |
| Explicit stop/EOS or unknown ID | Exclude it from generation usage; include it in raw count; end with `stop` |
| Matching stop string on the last allowed token | End with `stop`, ahead of `length` |
| Exhaustion / zero maximum tokens | End with `length`; zero limit performs no model work |
| `cancel()` | Flush an unmatched stop prefix once and return `cancelled` with its checkpoint |
| Already terminal `advance()` / `cancel()` | Return nil, including after fresh restore; no terminal redelivery |
| `close()` | Silently discard live state; future capture/advance refuses; older snapshots remain usable |

Terminal records carry prompt, generation and raw counts, plus reason.
They contain no elapsed time or throughput; callers own that telemetry. The
generation count measures ordinary consumed tokens, not the number of chunks.

S72 settles lookahead before returning a raw token. S73 preserves that contract
and closes the raw driver at an output terminal, retaining its matching frozen
child checkpoint. Restore and further terminal calls do no model, sampling,
prefill or RNG initialization work. It does not promise that earlier lookahead
never occurred. A failed advance returns no usable batch and closes the wrapper.

## Snapshot and refusal boundary

Composite schema 1 binds S72 schema 2 and prerequisite patch
`35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab`.
It holds the exact child checkpoint, its digest, tokenizer identity, explicit
stop/unknown IDs, normalized stops, detokenizer segment tokens and emitted bytes,
the emitted position within that segment, partial-stop buffer/stopped flag,
semantic counts, last consumed token and already-delivered terminal reason.

Restore validates schemas, identities/options, child/output binding, token ranges,
counts, terminal consistency, UTF-8 and bounded current-segment state before
restoring the raw child. It may decode the current segment or its emitted prefix
to validate captured value state; it does not regenerate model history. The owner
attests that tokenizer identity names the exact immutable implementation and
configuration, with deterministic, side-effect-free, bounded decode cost.

Limits are 65,536 current-segment tokens, 256 KiB per decoded/retained segment,
32 nonempty stop strings of at most 4 KiB each, 256 stop IDs, and a 4 KiB partial
stop buffer. Unexpected decode growth refuses. Actual encoded output state plus
returned records is at most 1 MiB; at most three records are returned per batch.
There is no pending output to serialize. Child encoded/live-tensor caps remain
8 MiB each. The actual encoded composite, including nested base64/envelope
overhead, is checked against 16 MiB.

These trusted local candidate snapshots use checksums for accidental corruption.
They are not encrypted, attacker-authenticated, portable across arbitrary
backends, crash-safe host commits or client exactly-once delivery. Restoring an
earlier checkpoint deliberately reproduces its corresponding suffix.

## Reproduce offline

```sh
python3 -B /Users/nellymoon/Documents/Swift/Reach/Tools/MLXResumableTextOutput/run.py \
  --reach /Users/nellymoon/Documents/Swift/Reach
```

The runner authenticates all five accepted S72 files, exports exact clean local
sources/submodules into an owned private directory, applies S72, then applies
this four-file additive delta. This patch is against S72-applied source, not a
replacement copy of S72 or a patch to install in shared checkouts. It binds the
ordered patch stack and confirms all S72 source bytes remain unchanged.

`Package.swift` is a private offline harness template; use the runner instead of
running SwiftPM in the tool directory. The tiny Llama target reuses unchanged
library sources. Dependencies remain mlx-swift-lm `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8`,
mlx-swift `0bb916c67f4b9e5c682cbe02a42c701c93ab5021`, swift-numerics
`0c0290ff6b24942dadb83a929ffaaa1481df04a2`, and swift-argument-parser
`6a52f3251125d74daf04fcbd5e6f08a75d074382`, including pinned Cmlx submodules.
No package resolution from the network, download or toolchain upgrade occurs.

Use the selected arm64 macOS 27 host, Xcode-beta developer directory, Swift
`swiftlang-6.4.0.33.1` and Python 3.14.7. GPU access is required. The runner copies
the accepted local `default.metallib`, SHA-256
`684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5`,
to its private build. SwiftPM native-mode deprecation warnings remain in logs.

## Focused proof

The runner requires 16 newly executed XCTest methods: eight output semantics
methods, four checkpoint/refusal methods, and the four unchanged
`StreamingDetokenizerTests`. Output tests compare exact ordered chunk bytes at
every cut of seven Unicode/newline/stop/literal scenarios. Focused stop-filter
assertions avoid unrelated registry/VLM targets.

Nine fresh producer/restore pairs cover Unicode C0, incomplete Unicode, a visible
prefix, drained length; two partial-stop boundaries and drained stop; and two
fixed tiny library-Llama cases. They span greedy/owned-key stochastic sampling,
Simple/Rotating caches, nonempty typed state and representative cache/history
wrap without a Cartesian matrix. Every producer exits before restore starts.
The state-bearing native fixture forces split Unicode and stop tokens; Llama
uses independently recreated fixed weights. No real prompts, tokenizer assets
or pretrained weights are used.

Workers compare exact raw tokens, ordered UTF-8 records, semantic terminal state,
RNG and integer metadata. Floating logits/cache/state retain S72's same-backend
`atol=1e-6`, `rtol=1e-5` comparison. Expected output is comparison evidence only;
restore receives the composite checkpoint and independently identical fixtures.

S72's accepted native lane, original 41-test/32-pair campaign and seven RC1
checks are reused evidence for the unchanged raw child. They are not rerun or
reported as newly executed S73 proof.

Each run retains ordinary logs, commands/timings, source/artifact bindings,
selected results and resource observations under `/private/tmp/reach-mlx-text.*`,
then removes owned source/build/fixture copies. Limits are 16 GiB scratch,
64 MiB simultaneous synthetic fixtures, 128 MiB tiny tensors and at least
20 GiB free space. Build jobs are at most four; only one build/test command and
one fixture worker runs at a time. The runner times out and joins owned work;
resource observations are at command boundaries, not continuous peak monitoring
or exhaustive opaque-descendant history.
