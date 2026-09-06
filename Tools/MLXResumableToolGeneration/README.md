# Native resumable tool-aware generation candidate (S76)

This local dependency candidate joins S73's native model/text output and S75's
ordered tool parser in one immutable, settled checkpoint. A restored native process
generates the remaining parser input. This is one unconstrained generation/proposal
pass. It does not execute tools or implement the full allowed/required coordinator.

The additive patch introduces `ResumableToolGeneration`, its checkpoint, and two
focused test files. It applies after the unchanged S72 → S73 → S74 → S75 patches at
`mlx-swift-lm` revision `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8`.
The runner authenticates all twenty prerequisite products and all 27 prior composed
output hashes. No shared source, parser/helper, production manifest or pin is edited.

## Contract

`prepare` takes the same model, input/identity, raw options, cache specifications,
state codecs, immutable tokenizer/text options as S73, plus S75's typed offered-tool
configuration and a 32-character lowercase hexadecimal namespace. It validates the
parser before starting the accepted raw driver's settled prefill/lookahead. Prepare
is not a no-model-work operation, except under the existing zero-token limit.

Each `advance` consumes at most one S73 raw step. Every nonempty text record is
converted losslessly from UTF-8 and consumed once by S75, in its original chunk
order, without splitting/coalescing or token re-decoding. The returned `Batch`
contains the S73 raw token if any, ordered parsed records, and both post-step child
checkpoints. Even a step with no visible records returns its settled checkpoint.

Normal stop or length first feeds any final text/withheld-prefix flush, finishes the
parser once, then appends exactly one S73-derived semantic terminal. Prompt,
generation and raw counts come from S73; parser operations and hidden syntax do not
invent token usage. Stop-before-length and intercepted EOS/unknown semantics remain.

Explicit `cancel` performs no model step. It discards S73's cancellation-flush text,
does not consume or finish S75, freezes its last settled checkpoint, closes both live
children and returns only the cancelled terminal. Previously returned records remain
returned. An unfinished parser with buffered syntax is valid only in the explicit
`cancelledFrozen` disposition. Terminal restore cannot recover that buffer into a new
call. This is a local output policy, not an exactly-once tool-effect guarantee.

Already-terminal `advance`/`cancel` return nil without work or redelivery. `close`
silently releases both children; future capture/advance/cancel refuse. A failed
step, child operation or outer encoding closes both children and exposes no usable
partial batch. Older independent snapshots remain usable. Calls are serially
confined and no work runs between calls; child mutation handles are not exposed.

## Checkpoints and records

Version 1 binds exact child bytes, their candidate/schema checks, the cancellation
policy, disposition and forwarded nonempty-chunk count. The parser sequence is
derived as that count plus exactly one normal EOS; cancellation adds none. Raw/text
positions, C0, terminal lifecycle and parser finished state must agree. The outer
SHA-256 checksum covers the actual encoded document, including both child values.

Construction checks bounded encoding and joins. Restore always calls the full S73
and S75 restoration paths, including raw value/cache/RNG/state-codec validation for
normal and cancelled terminals. It never treats the raw `document()` envelope check
as complete value validation. Terminal children are validated and closed without
model/prefill/sample, parser flush, ID allocation or output. Bounded deterministic
tokenizer validation is allowed under S73's immutable tokenizer contract. Any
partially restored child is closed on failure.

`ResumableToolGenerationRecord.parsed` nests S75's tagged record codec. Encoded
arguments preserve Int versus Double, negative-zero bits, nested JSON values and
UTF-8 bytes. Comparisons use encoded records, not `ToolCall` equality or untagged
JSONValue decoding. The public batch encoder includes actual checkpoint/base64
overhead. No transcript, parser replay, pending-delivery queue or acknowledgment
ledger is retained. Expected model/raw/options/cache/codec/tokenizer and
tool-configuration/namespace bindings are supplied explicitly at restore.

Checksums are ordinary corruption checks, not authentication or proof of arbitrary
history. This trusted local composition does not resist a party rewriting mutually
consistent states and recomputing checksums. Restoring an earlier legitimate
checkpoint intentionally repeats its suffix. Timing/throughput are not semantic
checkpoint identity.

## Bounds and inherited limitations

- S73 remains capped at 16 MiB; S75 at 1 MiB. Raw encoded state and individual live
  cache tensors keep their inherited 8 MiB caps.
- Each forwarded text chunk is at most 64 KiB. A larger S73 segment refuses and
  closes the combined operation; it is never silently rechunked.
- Actual encoded composite is at most 32 MiB. Actual encoded batch, including the
  checkpoint, is at most 48 MiB. New records alone are at most 2 MiB and 4,097
  records: at most 4,096 parsed response/call records plus one terminal. Aggregated
  results from the raw step and EOS are checked together before publication.
- At most 999,999 forwarded chunks reserve room within S75's million-operation
  counter for normal EOS. The raw 65,536-token limit and one text chunk per active
  step imply tighter effective counts. All other child limits remain, including
  the 256 KiB parser buffer, 4,096 issued IDs and 8,192 allocation attempts.
- Inherited child limits also make the effective maximum encoded batch smaller
  than the outer 48 MiB ceiling; all bounds count actual encoding overhead.

The continuation contract uses the same namespace and chunk sequence, not universal
rechunking invariance. Pinned parser syntax, numeric conversion, sanitization and
EOS semantics remain unchanged. `Tool/Parsers/ParserUtilities.swift` lines 169 and
223 convert Double to Int without finite/range guards; extreme numeric schema
inputs can trap. There is no arbitrary-input crash-safety or parser/helper repair
claim. Pinned `TextToolTokenLoopHandler` uses legacy process/drain ordering and is
not an exact ordered-output oracle for this candidate.

## Offline native verification

From this directory, with the exact local Reach dependencies and accepted metallib:

```sh
python3 -B run.py --reach /Users/nellymoon/Documents/Swift/Reach
```

Use normal platform approval for native Metal when the sandbox does not expose a
device. Do not bypass a denial. No network, dependency fetching, weights/tokenizer
download, shared cache write or toolchain change is required. The runner uses private
local dependency exports, `MLXLMCommon`, a two-file fixed tiny Llama target, and
MLX/MLXNN/MLXOptimizers. It preserves S74 sources but does not compile its guidance,
xgrammar or C++ targets. Private packaging overlays only route local dependencies
and select the focused targets/tests.

The eleven new XCTest methods cover 43 declared cut/restoration cases across
generated JSON with both cache kinds, schema-aware XML, specialized Mistral EOS,
cancelled/frozen syntax, normal prefix flush, zero budget and fixed tiny Llama.
The state fixture parameterizes vocabulary and performs real MLX tensor/cache and
typed-state updates with the owned sampler key. Explicit names, arguments, IDs,
response bytes, record order and usage supplement an independently advanced
S73-plus-S75 ordered reference. Tests include partial Unicode, newline reset,
withheld stops, supplied/missing/duplicate/colliding IDs, terminal no-work checks,
typed record fidelity, nested schema/binding/position/lifecycle corruption,
encoded/aggregate bounds, overlarge forwarding and a post-model-advance child fault.

Eleven sequential producer/restore pairs exercise C0, partial tag, partial Unicode
inside arguments, advanced IDs, stop prefix, normal terminal, XML, specialized EOS,
cancel boundary, cancelled terminal and tiny Llama. Each producer exits before its
restore process starts. Restore receives only the composite and compiled immutable
model/fixture definitions. It does not receive prefix tokens or a future parser
string stream. Expected output is opened only after native continuation completes.
Raw-token suffixes, encoded ordered records and parser state are exact; floating
model/cache/logit values use accepted same-backend `atol=1e-6`, `rtol=1e-5` checks.
Integer, RNG and typed-state metadata stay exact. Each nested checksum is checked
against its actual serialized bytes. The Llama prose case proves composition, not
parsed-call production by Llama.

Accepted S72–S75 child campaigns are reused, not blanket-rerun or counted as S76
proof. The runner retains ordinary commands/logs, exact input/output hashes, test
enumeration, process results and command-boundary resource observations under owned
0700 `/private/tmp/reach-mlx-tool-generation.*`. It removes its exact private
source/build/fixture roles on settlement. No persistent job is launched.

Combined owned scratch is limited to 16 GiB, simultaneous synthetic fixtures to
64 MiB and tiny model tensors to 128 MiB; at least 20 GiB disk must remain free.
Checkpoints are bounded at 32 MiB and expected files at 48 MiB, with a separate
64 MiB combined fixture check. Each pair's files are deleted before the next pair.
At most four build jobs and one build/test or worker run at once, with timeouts and
owned process joins. `--companion-root /private/tmp/reach-s76.<suffix>` optionally
includes the owned development scratch in combined resource observations. These
are boundary observations, not continuous peaks or exhaustive descendant tracking.

Reach runtime/pin adoption, structural tool guidance, route coordination, host/client
persistence, publication, EXO, upstream submission and release remain outside S76.
