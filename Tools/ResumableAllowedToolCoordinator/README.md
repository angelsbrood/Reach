# Local resumable allowed-tool coordinator candidate

S79 composes actual S76 proposal generation and S77 guidance into a Reach-owned,
synchronous allowed-tool operation. S78's public structural-envelope helpers and
guided checkpoint projection are compiled unchanged. The harness uses the current
`ReachWire.WireEvent`; it does not change the daemon, app, pins or shared checkout.

Run from a local checkout with the pinned sources and Metal library already present:

```sh
Tools/ResumableAllowedToolCoordinator/run.py --reach /absolute/path/to/Reach
```

The runner authenticates 41 accepted S72–S78 products, eight selected Reach sources,
four package pins and their two nested source roots, and the established Metal
library. It exports tracked local sources without fetching, applies unchanged
S72–S78 patches, then adds only
`Libraries/MLXLMCommon/ResumableToolGenerationCheckpointView.swift`. The 34 previous
composition outputs remain exact; the resulting composition has 35 outputs. Swift
package/cache overlays, fixed two-file Llama target, fixtures and builds stay in an
owned `/private/tmp/reach-allowed-tool-coordinator.*` root. The optional owned
`--companion-root /private/tmp/reach-s79.*` is included in resource observations.

## Operation and binding

Use `AllowedToolCoordinator.prepare`, `advance`, `capture`, `restore`, `cancel`
and silent `close` under one exclusive synchronous owner. Each returned batch
contains ordered events and the checkpoint after that operation. Restore returns
no events; it does not repeat a prior batch. This is a local provider boundary,
not durable host commit, publication, receipt or exactly-once effects. A future
host must commit its event/checkpoint pair before publishing it.

The immutable `AllowedToolBinding` includes request/entry IDs, parser namespace,
ordered offered definitions, optional response schema, original prepared tokens,
model/backend/dependency/cache/codec identities, tokenizer vocabulary and options.
The same offered definitions derive parser configuration and each single-tool
structural grammar. At least one offered tool is required. Model/tokenizer/codec
implementation identities remain owner-attested, as in the accepted children.
The runtime model factory receives the exact prepared pass and must do no model
forward or prefill work itself.

The actual proposal parser issues IDs and public tagged `ResumableToolCallRecord`
values. The coordinator retains them without UUID fallback or typed-number loss.
Without a response schema, nonempty probe prose streams immediately. With a schema,
probe prose stays private. On a normal probe stop/length ending, proposals take
precedence over schema fallback; otherwise select schema or prose. Validate every
proposed name before preparing any replay. An unknown later name therefore rejects
the entire replay sequence with a legible error, preserving earlier visible prose.

Replay messages use the exact repair system/user text from `MLXFilling.replayInput`
and normalized arguments from the actual saved proposal. The local preparation
policy `S79-json-messages-tokenizer-v1` encodes the sorted JSON message array after
a versioned policy prefix with the bound tokenizer. Exact message bytes, tokens,
digest, proposal index/ID and derived child identity are saved and rechecked. This
is intentionally a local deterministic preparation contract, not production
chat-template/processor adoption. Schema fallback uses the original prepared input.

Tool guidance stays private until accepted EOS and successful unchanged
`parseEnvelope` extraction. Native grammar acceptance enforces the selected schema;
a parseable JSON prefix alone cannot publish a call. A nonfinal accepted call
settles at call-ready, then publishes one whole call and stops at interpass. Only a
later advance prepares the next replay. Same-tool repeats retain distinct saved
IDs and order. The last call publishes with aggregate usage and complete ending
in one batch. Schema output streams exact nonempty guided chunks; prose/schema
completion publishes only aggregate usage and complete ending. Usage counts every
prompt, hidden syntax and consumed sampled/forced token once, excluding intercepted
EOS and accepted-but-unconsumed fast-forward tokens.

Cancel at final-ready delivers the same normal final batch without model work.
Cancel at active, route-ready, nonfinal call-ready or interpass boundaries emits
one cancelled ending, no new call or aggregate usage, and starts no later pass.
Already-terminal children remain terminal when outer cancellation settles a
boundary. Incomplete guidance emits an error while preserving prior returned text
or calls. Unexpected errors close the operation with no partial batch; earlier
independent snapshots remain usable. Terminal operations never redeliver.

## Checkpoint authority and limits

Only one full child checkpoint is retained. Restore fully restores that actual
native child, including at ready/interpass/final-emitted boundaries, before reading
its inspection view. It does no model/prefill/sample work, parser EOS, ID allocation,
next-pass preparation, usage increment or event delivery. The new read-only S76
view requires capture equality with a validated operation and exposes actual
counters, terminal/disposition, parser frontier and issued IDs. It is not a native
validator by itself.

Prose history, proposal order/arguments and discarded-pass contributions are
explicitly outer-owned trusted-local history. The retained S76 view joins the exact
proposal ID set and counters; it cannot reconstruct older prose or arguments.
After replacement, those values have bounded internal consistency checks, not
native reauthentication of discarded snapshots. For the retained guided child,
the unchanged S78 view joins complete current-pass bytes across newline resets,
counts and terminal state; a ready envelope is reparsed. Checksums detect ordinary
corruption and are not signed hostile-history proofs.

Actual encoded limits: outer checkpoint 64 MiB, retained S76 child 32 MiB or guided
child 16 MiB, returned batch 96 MiB, outer control/history plus returned records
4 MiB. Keep at most 32 offered tools/proposals/replays, 4,096 parsed records/events
(final batch at most three), 512 KiB combined prose, 256 KiB current guided bytes
or normalized arguments, 512 KiB replay messages and 65,536 prepared tokens. Names
are at most 1,024 UTF-8 bytes, entry/call IDs 256 bytes, schemas/generated structural
sources and parser configuration 64 KiB. All inherited child bounds remain intact.
Required history is refused, never trimmed. The inherited extreme-number parser
conversion limitation is outside any arbitrary-input crash-safety claim.

## Native evidence

Eleven focused XCTest methods cover explicit route/event/argument/ID/usage outcomes,
typed records, dynamic input, native continuation, delivery/cancellation boundaries,
incomplete output, refusal joins, encoded limits and failure isolation. Twenty-six
sequential fresh producer/restore pairs cover all routes and meaningful proposal,
Unicode, pending fast-forward, newline/reset, accepted-EOS, multipass, ready,
delivery and terminal cuts. Each producer exits before restore starts. The restore
worker continues natively before opening expected suffix evidence; exact events,
IDs, usage, state and input/cache frontiers are compared. Native logits and floating
cache/state values use explicit tolerances, with independent analytic fixture
recurrence and a fixed tiny actual library Llama representative. The unknown-later
fixture uses the actual XML-function parser because the JSON parser filters unknown
names against offered definitions before emitting proposals.

The runner retains logs, exact selected/started/passed test enumeration, worker
results, product/source/patch bindings and command-boundary resource observations.
Accepted S72–S78 parser/codec/native and RC1 history campaigns are reused, not rerun.
Run with at most four build jobs, one build/test command or worker at a time, 16 GiB
combined owned allocation, 256 MiB simultaneous fixtures, 128 MiB tiny MLX tensors,
and at least 20 GiB free disk. Fixture checkpoints stay within 64 MiB and expected
suffix files within 96 MiB. Commands are timed and joined; observations are not
continuous memory peaks, RSS or exhaustive opaque-descendant tracking. Owned private
source/build/fixture copies are removed after settlement; logs/evidence remain.

Only terminal Architecture PASS and Planning closeout accept this local candidate.
Host storage/publication, effects, production input preparation, runtime/pin adoption,
physical-host testing, EXO, upstream changes and release remain outside S79.
