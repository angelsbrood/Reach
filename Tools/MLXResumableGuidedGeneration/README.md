# MLX resumable guided-generation candidate

S74 is a local native dependency candidate for paused JSON-schema generation.
It preserves the guided matcher, settled model state and output position across
fresh processes. It does not adopt an upstream API, change Reach production
dependencies or establish Reach runtime durability. Tools, parsers, stochastic
guided sampling, route coordination and host storage remain outside this lane.

## Paused API and recurrence

`ResumableGuidedGeneration.prepare` accepts pretokenized batch-one text, an S72
model identity/cache declaration/typed-state registry, a deterministic tokenizer,
an exact `ResumableGrammarSpecification` and `ResumableGuidedOptions`. C0 contains
the actual settled last-position prefill logits and complete supported model
state. Zero token budget performs no model work.

`advance()` returns one consumed token and its sampled/forced/ending origin, up
to two ordered UTF-8 `Data` records, and the matching post-batch checkpoint.
A step may have no visible text. There is no AsyncStream, output queue, callback
producer, acknowledgment journal or host transaction. Earlier frozen checkpoints
remain immutable and deliberately reproduce their own suffixes.

The model schedule is explicit: prefill in declared bounded chunks, then one
single-token forward for every ordinary sampled or forced token, in output
order, including the final ordinary token at budget exhaustion. An intercepted
EOS is accepted by the matcher but is neither forwarded nor decoded. All model
work is settled before a batch escapes.

This schedule intentionally differs from the pinned legacy callback loop's FF
branch, which forwards the forced IDs without first forwarding the sampled ID.
The candidate accounts for that sampled input. Its independent recurrence tests
check actual input sequences, cache offsets and typed model-state arithmetic;
uninterrupted-versus-restored equality alone is not the recurrence oracle.
Legacy production is unchanged. S72's autonomous sampled lookahead is not used
as a guidance-injection API; its supported codecs are reused through one new
common-module helper.

## Grammar, pending work and output

The compiler inputs bind exact JSON schema bytes, vocabulary/type, tokenizer
implementation/configuration identity, EOS/unknown IDs, fast-forward setting and
vendored xgrammar v0.1.30 (`d476a48dcd8fa3b5afeddbe850e73bb3b1dcf505`). Tokenizer
owners attest immutable, side-effect-free, bounded deterministic encode/decode
and encoded token IDs within the declared vocabulary. No tokenizer assets or
chat-template construction are performed.

The checkpoint records every successful matcher accept with sampled, forced or
ending origin. The consumed prefix gives the model/output frontier; all remaining
IDs are a bounded pending forced suffix. Grammar may lead the model/output only
by that recorded suffix. Each advance drains one pending ID without another
accept or sample. Caller-visible pauses inside a nonempty forced suffix are
supported.

Restore compiles the exact grammar and replays successful accepts once through
an additive single-accept bridge method. Replay never queries or accepts extra
FF work. It validates the reconstructed mask/termination and pending/frontier
consistency, then restores model tensors/state and the output segment. It does
no prompt/model replay, sampling, usage increments or emission. v0.1.30's
unsupported matcher fork/serialization is not used.

The native fixture-only literal EBNF entry is exposed under
`@_spi(ResumableGuidedFixtures)` so the harness can prove genuine FF. It uses the
same core, not a product tool-grammar route. The selected literal produces six
forced IDs after its opening quote, including three UTF-8 bytes of “中.” The
pinned FF implementation leaves the final boundary quote to the sampler.

The unchanged pinned detokenizer handles common-prefix emission, incomplete-byte
suppression and newline last-token reset. The new common helper preserves its
segment tokens, emitted UTF-8 and emitted position. Restore derives a private
detokenizer value from the entire consumed non-ending acceptance prefix, using
the same bounded append/decode steps as generation, then compares all saved
segment tokens, emitted bytes and position. This proves the actual reset boundary
as well as incomplete-byte buffering. Per-step text is discarded; derivation
publishes no records and performs no model/prompt replay or usage increments.
Visible text is not substitute matcher/model state. Incomplete detokenizer bytes
are never flushed at an ending. No accumulated
text is needed for semantic decisions, and no stop-string or tool parser runs.

## Selection and endings

Only greedy constrained selection is supported. The candidate reuses the pinned
mask and greedy helper, including bias padding/truncation to the declared logit
width. Positions outside grammar vocabulary cannot be selected. A mask with no
finite allowed logit refuses instead of promoting an invalid argmax.

The mask-gated completion policy preserves the legacy normal/soft/hard zones:
no closing bias in normal, configured closing bias in soft, and non-closing plus
EOS penalties of -10,000 in hard. Configured whitespace bias applies after its
tracker latches. Only sampled decisions update that tracker; forced tokens do
not. The consecutive count and permanent latch are captured and verified by
replaying sampled history. Exact bias arrays, reserves, threshold and IDs are
bound to the snapshot; no generic callback processors are accepted.

The ending policy is explicitly `accepted-stop-v1`. An accepting grammar
frontier (EOS permitted) is distinct from termination after a successful EOS
accept. `complete` requires the latter. An unknown ID alone never means schema
completion, and a premature disallowed EOS refuses.

| Boundary | Result |
| --- | --- |
| Allowed EOS accepted on the final permitted step | `complete`, with one intercepted ending |
| Budget exhausted before accepted stop, even if EOS is now permitted | Explicit `incomplete`; no successful-JSON claim |
| Budget exhausted inside pending FF | `incomplete`, retaining accepted but unconsumed pending IDs |
| Zero budget | First advance returns `incomplete` and its checkpoint; no model call |
| `cancel()` | One `cancelled` terminal batch, no model work or incomplete-text flush |
| Terminal restore / repeated advance or cancel | Nil; no new model work or duplicate records |
| `close()` | Silent discard; future capture/advance refuses; older snapshots remain usable |

Budget counts consumed sampled/forced/ending positions; terminal usage separately
reports ordinary sampled, forced, intercepted ending, accepted and pending counts.
No timing/throughput is encoded as semantic identity. A failed advance returns no
usable batch and closes the operation; it need not undo already-settled private
model work. Failed restore does not mutate an independent live operation.

## Bounds and encoding

Composite schema 1 binds the exact S72/S73 prerequisite identities and a new
model-component schema. It contains the exact encoded model component, its
digest, grammar history/mask, options, frontiers, whitespace state, output state
and already-delivered terminal reason. Restore checks schema, compatibility,
UTF-8, token ranges, counter/origin/matcher consistency and the model/output join.
Corrupt, truncated, oversized or incompatible values refuse; no silent restart.

Actual encoded composite size is at most 16 MiB including nested overhead.
The model component is at most 8 MiB; each live cache tensor retains S72's 8 MiB
cap and schema-2 allocation-capacity checks. Encoded guidance/output plus returned
records is at most 1 MiB. Limits are 64 KiB grammar, 4,096 vocabulary entries /
256 KiB encoded vocabulary, 65,536 successful accepts, 4,096 pending FF IDs,
256 KiB decoded/retained text segment, 4,096 bias entries with finite magnitude
at most 10,000, and at most two records per batch. Growth refuses rather than
evicting state required for continuation.

These are trusted local synthetic compatibility checks and corruption checksums,
not encrypted or attacker-authenticated host commits, arbitrary-grammar resource
guarantees, portable backend snapshots or client exactly-once delivery.

## Reproduce offline

```sh
python3 -B /Users/nellymoon/Documents/Swift/Reach/Tools/MLXResumableGuidedGeneration/run.py \
  --reach /Users/nellymoon/Documents/Swift/Reach
```

The runner authenticates all ten accepted S72/S73 files and exports exact clean
local sources/submodules. It applies unchanged S72, unchanged S73, then this
12-path delta in private scratch, proving all prerequisite patched outputs stay
unchanged. Five new implementation files, five new test files, and narrow bridge
replay/whitespace-state access changes comprise this delta. There is no edit to
the legacy guided loop, accepted artifacts, shared checkout, C/C++ shim or
vendored source. `Package.swift` is a private template; use the runner rather
than SwiftPM in this tool directory.

Native xgrammar targets retain the pinned C++17 standard, grammar-functor
exclusion/wrapper, header paths, namespace defines and linker settings. No VLM,
FoundationModels, cloned matcher or downloaded model/tokenizer is required.
The exact local pins are mlx-swift-lm `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8`,
mlx-swift `0bb916c67f4b9e5c682cbe02a42c701c93ab5021`, swift-numerics
`0c0290ff6b24942dadb83a929ffaaa1481df04a2`, swift-argument-parser
`6a52f3251125d74daf04fcbd5e6f08a75d074382`, and their accepted Cmlx submodules.

Use the selected arm64 macOS 27 host, Xcode-beta developer directory, Swift
`swiftlang-6.4.0.33.1`, Python 3.14.7 and native GPU access. The accepted copied
metallib SHA-256 is `684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5`.
No network resolution, download, toolchain change or shared .build write occurs.
The native SwiftPM deprecation warning remains in logs.

## Focused proof and cleanup

The runner requires 15 new XCTest methods across matcher, core/recurrence, model,
text and checkpoint/refusal tests, plus 34 selected unchanged Swift Testing cases
for whitespace tracking/bias, closing/forced completion, mask relocation and stop
token sources. The output-history regressions reject the cut-3 truncated Unicode
buffer, a longer suffix and an impossible emitted position without model work
or mutation of an independent live operation. Positive native restores cover the
newline reset and subsequent nonlinear whitespace decoding. It does not run the
whole guided suite or any clone gate.

Eight producer/restore pairs cover JSON C0, incomplete Unicode, visible prefix,
terminal; literal partial-FF, visible-with-pending and incomplete-budget terminal;
and fixed tiny library Llama composition. They include nonempty typed state and
Simple/Rotating caches. Every producer exits before restore starts. Expected
records are read only after continuation for comparison. Tokens, accept/origin
history, model-input sequences, offsets, ordered UTF-8 records, masks and integer
metadata compare exactly; floating logits/cache/state use same-backend
`atol=1e-6`, `rtol=1e-5`. The producer separately proves complete input recurrence.

S72's native lane, 41-test/32-pair campaign and seven RC1 checks, and S73's
16-method/nine-pair campaign are reused evidence for unchanged prerequisites.
They are not rerun or counted as new S74 evidence.

Each run retains ordinary commands/logs, source/patch/artifact bindings, results,
timings and resource observations under `/private/tmp/reach-mlx-guided.*`, then
removes its source/build/fixture copies. Task limits are 16 GiB scratch, 64 MiB
simultaneous synthetic fixtures, 128 MiB tiny tensors and at least 20 GiB free.
Build jobs are at most four; one build/test command and one worker run at a time.
Owned work is timed out and joined. Resource checks occur at command boundaries;
no continuous peak or exhaustive opaque-descendant claim is made.
