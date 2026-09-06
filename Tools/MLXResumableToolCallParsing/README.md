# MLX resumable tool-call parsing candidate

S75 is a local CPU-only checkpoint candidate for the actual pinned
`ToolCallProcessor`. A fresh process continues the same remaining string chunks
with the same ordered response UTF-8 bytes, calls, argument values and call IDs.
It covers all ten pinned `ToolCallFormat` cases, including specialized Mistral
and LFM2 ordered EOS behavior. It does not execute tools or join a model loop.

## API and settled boundary

```swift
let configuration = try ResumableToolCallConfiguration(format: .json, tools: nil)
let parser = try ResumableToolCallProcessor.prepare(configuration: configuration)
let namespace = parser.namespace // retain as part of the expected immutable binding
let c0 = try parser.capture()
let batch = try parser.consume("<tool_ca") // records may be empty
let restored = try ResumableToolCallProcessor.restore(
    batch.checkpoint, configuration: configuration, namespace: namespace)
let next = try restored.consume("ll>...")
let final = try restored.finish()
```

A caller may supply a 32-character lowercase hexadecimal namespace at prepare;
otherwise prepare allocates one UUID namespace and saves it in C0. Restore checks
the expected configuration and namespace and never allocates a new namespace.
The facade exclusively owns its processor and exposes only ordered operations.
At every returned checkpoint the legacy call array and ordered queue are both
empty. A batch contains its ordered records and corresponding drained checkpoint;
there is no delivery queue, acknowledgment journal or host transaction.

`capture` freezes the current value. Restore reconstructs the real parser from
format/configuration and restores its four-state machine, exact buffer and ID
state without consuming chunks, flushing EOS or replaying the input history.
The JSON scanner derives quote/depth/escape while scanning the saved buffer; it
has no separate mutable cursor. Incomplete start/end tags, quoted/nested JSON,
Unicode strings and partial arguments remain buffered according to pinned rules.

`finish` applies the pinned EOS path once. A finished restore or repeated finish
returns nil; consume after finish refuses without processing the chunk. Finish
means parser completion, not a valid-call or model-success claim. Malformed,
unparseable and residual text follows the existing ordered sanitization rules.
The contract uses the same namespace and chunk sequence; it does not promise
universal rechunking invariance.

A failed consume/finish closes the facade and returns no usable partial batch.
Records accumulated privately by the nonthrowing pinned parser never escape a
failed call. `close` silently discards the instance; earlier independent frozen
checkpoints remain usable. Failed restore cannot mutate another live instance.

## Configuration, values and call IDs

Offered tools are `[[String: JSONValue]]?`, with nil distinct from an empty list.
There is no arbitrary Sendable-object or closure configuration overload. Prepare
and restore use the same explicit typed conversion into the pinned parser.
Restorable configuration bytes are included and compared, rather than carrying
only a digest. Unsupported depth, sizes and nonfinite numbers refuse.

The tagged value codec preserves Int versus Double, Double bit patterns including
negative zero, null, booleans, arrays, objects and exact UTF-8 strings. This avoids
losing type distinctions through `JSONValue`'s untagged decoder, which prefers Int
for a number such as 1.0. Tool-call records preserve the values actually returned
by the pinned parser; response records use `Data` so comparison does not use Swift
String canonical equivalence. No accumulated response transcript is required.

The opt-in `sha256-counter-v1` allocator hashes the fixed domain, saved namespace
and decimal attempt position. Ordinary generated IDs are `call_` plus 32 lowercase
hexadecimal characters; Mistral uses nine uppercase hexadecimal characters,
within its alphanumeric syntax. Unique nonempty supplied IDs are preserved.
Missing, empty and duplicate IDs receive fresh IDs without dropping the call.
Every attempted candidate advances the saved position, including collisions;
the saved issued set prevents reuse. Restore verifies that all attempted candidates
are present in that set before future allocation. Counter exhaustion refuses.

This is bounded correlation identity, not a global uniqueness service, secret,
authorization token or client effect identity. Legacy public initialization,
processing and random UUID generation remain unchanged outside the opt-in lane.

## Bounds and refusal

| Value | Limit |
| --- | --- |
| Input chunk | 64 KiB UTF-8 |
| Retained parser buffer | 256 KiB UTF-8 |
| Actual encoded typed configuration | 64 KiB |
| Issued IDs / returned records per batch | 4,096 each |
| Individual ID / function name / JSON object key | 256 / 4,096 / 4,096 UTF-8 bytes |
| JSON value depth / entries per collection | 16 / 4,096 |
| Individual JSON string / response record | 256 / 512 KiB UTF-8 |
| ID allocation attempts / chunk-or-finish sequence | 8,192 / 1,000,000 |
| Actual encoded checkpoint / batch including checkpoint | 1 / 2 MiB including envelope overhead |

Effective capacity can be lower when an encoded aggregate reaches its cap.
Unsupported growth refuses instead of truncating state or dropping output.
The pinned bare-JSON 32,768-character safety valve remains unchanged and is
separate from the candidate's byte limits.

The versioned envelope uses SHA-256 for ordinary corruption detection. Restore
checks compatibility, configuration, UTF-8, state/format/buffer relationships,
finished/sequence consistency, fixed ordered/drained policy and the issued-ID /
allocation join. It does not try to prove full input-history reachability or
provide authenticated/encrypted host persistence.

One inherited limitation remains: pinned `Parsers/ParserUtilities.swift` lines
169 and 223 convert Double directly to Int without finite/range checks. Extreme
numeric schema-conversion inputs can trap in the pinned parser. This candidate
makes no arbitrary-input crash-safety claim and does not repair individual parsers
or their conversion helpers. Parser syntax/normalization behavior remains pinned.

## Reproduce offline

```sh
python3 -B /Users/nellymoon/Documents/Swift/Reach/Tools/MLXResumableToolCallParsing/run.py \
  --reach /Users/nellymoon/Documents/Swift/Reach
```

The dependency-free macOS package compiles the sixteen selected Tool subtree
files plus unchanged ChatConventions.swift and ReasoningConfig.swift, with two
candidate source additions. These use Foundation and the system CryptoKit module.
The actual parser source pin is mlx-swift-lm
`83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8`. The runner authenticates clean local
source, exports selected tracked bytes, records the current native Swift/Xcode
versions and uses private SwiftPM/module-cache/build paths. No MLX, Metal, xgrammar,
model weights, tokenizer, network resolution or GPU approval is needed.
`Package.swift` is a private template; use the runner instead of building here.

The five-path patch changes only ToolCallProcessor's private opt-in state/ID hooks
and adds two candidate sources and two test files. ToolCallFormat, individual
parsers and all existing test bytes are unchanged. The runner also applies S72,
S73, S74 then S75 in a separate source-only selection, verifies all 22 accepted
prior output hashes and the same S75 outputs, and authenticates all fifteen prior
product files. This proves source composition only; it does not run or accept a
joined generation/tool route. Prior model/guidance campaigns are reused.

## Focused native proof and cleanup

Ordinary reproduction runs nine new XCTest methods and the complete unchanged
ToolTests suite (63 actual Swift Testing tests). It enumerates executed methods
and titles. New fixtures exercise all ten formats at every declared chunk cut
including C0 and finished, deeper tagged/bare/inline JSON and escaped quotes,
XML schema conversion, both specialized EOS paths, call-text-call order, malformed
residuals, supplied/missing/empty/duplicate/collision IDs, value fidelity and bounds.
Independent comparisons use the legacy ordered parser and explicit expected
function names/arguments/response bytes. Only legacy random IDs are normalized
for that comparison; resumed IDs are always compared exactly.

Nine representative sequential producer/restore pairs cover C0, buffered tagged
and bare JSON, schema-aware XML, Llama inline, Mistral and LFM2 EOS, already-advanced
ID allocation with collisions, and a finished checkpoint. Each producer exits
before restore starts. Restore reads only its checkpoint, expected immutable
configuration/namespace and remaining chunks; expected answers are read after
continuation. Ordered record batches and final checkpoint bytes must match exactly.

The runner retains ordinary logs, commands, source/product/checkpoint/binary hashes,
actual test/process results and resource observations under
`/private/tmp/reach-mlx-tool-call.*`, then removes its private source/build/fixture
copies. Limits are 4 GiB combined owned scratch, 16 MiB fixtures and 2 GiB free disk;
at most four build jobs and one build/test or fixture worker at a time. Commands
are timed out and joined. Observations occur at command boundaries, without
continuous peak or exhaustive opaque-descendant claims.

This is the parser dependency slice only. Model/parser integration, required or
allowed route coordination, tools/effects, EXO, host publication, client persistence,
Reach runtime adoption, upstream work and releases remain outside this result.
