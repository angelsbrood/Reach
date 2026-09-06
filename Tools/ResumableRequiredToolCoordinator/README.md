# Resumable required-tool coordinator (S78)

This local Reach-owned candidate wraps accepted S77 structural generation and
returns actual `WireEvent` batches. It is an isolated native package, not an
adoption into MLXFilling or the Reach runtime.

## Settled operation

`RequiredToolCoordinator` is a synchronous exclusive owner. Prepare takes explicit
entry/call IDs, an immutable binding, actual model/input, tokenizer and state codecs.
The binding includes required route/policy/version, request identity, ordered exact
raw name/schema definitions, model/prepared-input identity, cache and codec identity,
tokenizer/grammar specification and guided options. Names/schema definitions build
the grammar; an unrelated mutable offered-name list cannot select a call afterward.
The child binds all actual codec descriptors in addition to the caller's codec
implementation identity. Tokenizer/model/codec owners retain the inherited contract
that matching identities attest compatible deterministic implementations.

Prepare validates the binding and actual input digest before native model work.
Normal child prefill may then run. At C0 the explicit IDs are saved. There is no
ID-generator API in the coordinator or its restore/delivery paths.

Advance returns a bounded batch of events plus its post-operation checkpoint:

1. **generating:** actual child text chunks append to a private whole UTF-8 buffer;
   returned event arrays are empty.
2. **ready:** accepted EOS completes the child and permits whole-envelope parsing.
   The offered name and normalized object arguments are latched; this settled
   batch remains empty and carries a restorable ready checkpoint.
3. **emitted:** the next advance returns exactly one ordered batch containing
   `toolCallAppendArguments(saved entryID, saved callID, name, arguments, tokenCount: 1)`,
   `usage`, then `finished(.complete)`, with its emitted checkpoint.

Usage output is sampled plus forced **consumed** tokens, excluding intercepted
EOS and pending accepts. A parseable closed object without accepted EOS is not
completion. Incomplete/budget-exhausted child state produces only a legible error
ending. Active cancellation produces one cancelled ending without model work,
text flush, call or usage. Completion wins at ready: cancellation there delivers
the same normal final batch. After emitted, advance/cancel return nil. Silent close
discards live resources and pending delivery; prior snapshots remain usable.
Unexpected errors close the live operation without returning a partial batch.

Restoring ready returns the same batch on the next advance/cancel. Restoring emitted
returns nil. These are settled provider boundaries, not durable host publication,
receipt or tool-effect atomicity. A future host must persist checkpoint and event
batch together before publishing them; S78 does not implement that storage step.

## Child projection and consistency

The sole dependency addition is
`Libraries/MLXGuidedGeneration/ResumableGuidedCheckpointView.swift`. It changes no
existing child codec, generation loop, model, parser, bridge, shim or vendored source.
The view requires a matching checkpoint from an already validated native operation.
Coordinator restore always performs full native child restore first, including at
ready/emitted. Envelope-only decoding and this view are not standalone acceptance.

The view replays bounded consumed non-ending accepts through the existing
`ResumableGuidedTextValue.append` and concatenates every returned delta. It does not
use just the current segment's `emitted`, which loses earlier newline-reset output,
or one decode of all tokens, which can differ from streaming semantics. It makes
no model/prefill call, matcher accept, FF query, sampling step or event delivery.

The outer document binds exact child bytes/digest, whole private buffer, immutable
binding, phase/outcome, normalized selected call and counters. Restore compares them
to the derived child view and re-parses a completed envelope. It rejects contradictory
joins while leaving other live operations unchanged. Checksums and focused mutation
checks cover ordinary corruption and consistency; they do not establish arbitrary
history-forgery safety.

Grammar/envelope helpers follow the selected current ToolGuidance source: fixed
JSON-escaped name/arguments prefixes, structural_tag/or/tag alternatives, each
tool's root-local json_schema, and closing brace. Complete-envelope parsing requires
an offered name and object arguments, normalized with sorted keys and unescaped
slashes. Native grammar acceptance owns argument-schema enforcement. This helper
is not a new general schema validator or FoundationModels request adapter.

## Offline package and proof

```sh
python3 -B run.py --reach /Users/nellymoon/Documents/Swift/Reach
```

Use normal platform approval for native Metal when required; never bypass a denial.
The runner exports only existing clean pinned local sources and an authenticated
metallib. It uses private module/build/package caches, local dependency overlays and
no network, downloads, shared cache/source writes or toolchain upgrade. Actual
ReachWire/WireEvent.swift is copied byte-exact into a tiny ReachWire target. The
established native C++17 grammar target settings and fixed two-file Llama target
are retained. No full daemon/app/FoundationModels harness is imported.

Apply pinned base then unchanged S72–S77 and the sole additive S78 view patch. All
30 accepted Reach products and 33 prior dependency outputs authenticate and remain
byte-exact. Final composition contains 34 outputs. Reach-owned coordinator, shared
fixtures, fresh worker and two focused tests stay within the eleven new product files.

Ten focused native tests cover explicit single/multiple offered names, escaped
names/content, Unicode, root-local refs, arrays/enums, incompatible alternatives,
private streaming, pending FF and FF off; C0 through ready/emitted; before EOS,
zero/incomplete/cancelled ends, ready cancellation, silent close and unexpected
failure. Projection tests cover earlier text across actual newline resets and
recomputed bad outer/child joins, including native validation at terminal restore.
Changed bindings, codecs, corrupt/truncated/versioned documents, encoded growth
bounds and mismatched projection/checkpoint pairs refuse.

Eighteen sequential fresh producer/restore pairs exercise C0, pending FF, partial
name/arguments, Unicode, newline reset, before EOS, ready, emitted, ready cancellation,
cancelled, incomplete, zero/partial budget, both alternatives, FF off and fixed tiny
library Llama. The same fixture target is used by tests and workers. Each producer
exits before restore starts. Restore receives only the checkpoint and compiled
immutable fixture/binding definitions; native continuation finishes before expected
suffix evidence is read.

Events, IDs, usage, endings, private bytes, frontiers and integer metadata compare
exactly. Independent explicit argument/event oracles and single-token input/cache/
typed-state recurrence supplement continuation comparisons. Model/cache/logit floats
use `atol=1e-6`, `rtol=1e-5`. Nested checksums bind actual child/model bytes. The tiny
library Llama is identified separately from the analytic state model. Accepted
S72–S77 campaigns and S74 RC1 are reused; no blanket prior suite or old-binary rerun
is counted as new coordinator proof.

## Bounds and cleanup

Actual encoded outer checkpoint is at most 32 MiB, embedded actual child at most
16 MiB, encoded outer control plus returned records excluding child at most 1 MiB,
whole private envelope and normalized arguments each 256 KiB, offered tools 32,
UTF-8 name bytes 1024, each nonempty entry/call ID 256 bytes, and three returned
events. Combined structural source retains the child's 64 KiB cap. All inherited
child vocabulary, accept/frontier, tensor/cache/component, text, bias and counter
bounds remain unchanged. Growth refuses without discarding required state.

Owned 0700 scratch is `/private/tmp/reach-required-tool-coordinator.*`; optional
`--companion-root /private/tmp/reach-s78.<suffix>` includes development scratch in
observations. Combined allocation is bounded at 16 GiB, simultaneous synthetic
fixtures at 64 MiB, tiny model/state tensors at 128 MiB, and free disk at least
20 GiB. Expected evidence files are at most 32 MiB. At most four build jobs and
one build/test or worker run at a time, with ordinary timeout and owned joins.

The runner retains command logs, input/source/composition hashes, exact selected/
passed test enumeration, fresh matrix and command-boundary resource observations.
It removes only its private source/build/fixture/helper role when settled. These
are not continuous peak, RSS or exhaustive opaque-descendant guarantees.

Production/runtime/pin adoption, allowed-tools multipass coordination, host/client
storage, actual tool effects, EXO, upstream submission, release and later slices
remain outside S78. Keeper is Held; physical work remains deferred.
