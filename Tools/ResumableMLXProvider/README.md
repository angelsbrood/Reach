# Local resumable MLX provider boundary

S80 provides one synchronous Reach-owned boundary over actual ordinary text (S73),
guided response (S74/S77), required tools (S78), and allowed tools (S79). It compiles
the unchanged S78/S79 coordinators and current `ReachWire.WireEvent` in isolated
targets. It does not modify the daemon, app, dependency pins or accepted children.

```sh
Tools/ResumableMLXProvider/run.py --reach /absolute/path/to/Reach
```

The offline runner authenticates 53 accepted products, nine selected Reach sources,
six clean pinned source roots and the established Metal library. It applies only
the unchanged S72–S79 patches to private exports and verifies all 35 composed
outputs. There is no S80 native patch or view. Tests and workers share fixtures,
including fixed tiny library Llama weights; no network or downloaded assets are used.

## Binding and operation

`ProviderBinding` contains operation/request IDs, version, policy and one concrete
tagged route binding. Ordinary/guided routes take explicitly prepared tokens, model/
backend/dependency/cache/codec identities, tokenizer/grammar/options and response IDs.
Required/allowed routes retain their exact accepted contracts and local input policy.
Model, tokenizer and codec implementation identities remain owner-attested.

`assess` checks bounded declarations and known supported scalar options without
model-factory, prefill or generation work. It reports a conservative reservation
or a legible unsupported reason. It does not expose module-internal child validators
or promise that later grammar construction, native validation or allocation succeeds.
Actual prepare/restore still perform the complete selected child's checks.

`prepare` requires a caller-owned token and at least `reservationBytes` of declared
credit before native work. Normal settled child prefill/lookahead is allowed. The
returned operation has an immutable, event-empty C0 available through
`pendingCandidate()`. C0 must be acknowledged before another step.

`advance` and `cancel` require the current owner token, exact accepted descriptor,
available conservative credit and a non-overflowing next ordinal before child work.
They invoke the child at most once, freeze ordered event bytes and its matching
checkpoint, then wait for exact acknowledgement. Empty events still require an ack.
Pending access returns the same frozen bytes. Another advance/cancel while pending
refuses before factory/model/route work. Silent close always remains available.

`acceptCommit` performs no child work or event delivery. It accepts only the exact
pending descriptor for the owner. Repeating the last accepted descriptor is
idempotent, including while a newer candidate is pending; that duplicate must leave
the newer pending candidate intact. Other stale, foreign, skipped or altered acks
refuse without mutation. A terminal candidate must be acknowledged before the
operation becomes terminal; subsequent advance/cancel returns nil.

The operation retains one accepted descriptor and one pending candidate, with one
native child. It does not retain a historical checkpoint log. The host owns frozen
committed records and prior event bytes. `close` discards pending/live state silently
without acknowledging it or modifying independently retained values.

## Frozen encoding and restore

Version 1 uses sorted-key JSON without escaped slashes. Each candidate stores the
exact encoded event array and child-containing provider checkpoint as byte payloads.
The descriptor binds operation/route, ordinal, previous accepted identity, both
payload digests and terminal metadata. Its identity is the SHA-256 of its frozen
descriptor bytes. The checkpoint includes matching metadata but no descriptor
digest, avoiding a recursive hash. Nested base64 and JSON expansion count toward
actual encoded limits. This is a local encoding, not a negotiated wire frame or host
sequence number. Text projection rejects invalid UTF-8; comparisons use event bytes
and chunk boundaries rather than Swift String canonical equivalence.

`restore(committed:expected:runtime:owner:)` takes the caller's designated committed
candidate and may install a new local owner token. It checks bounded outer encoding,
digests and metadata joins, then fully restores the selected native child, including
terminal snapshots. It matches the public child phase/terminal where available and
retains the original accepted descriptor. It creates no pending batch and does no
model/prefill work, new route preparation, usage increment or replacement-ID allocation.
Stored events are not redelivered; the host owns replay of its exact committed bytes.

A host recovering after an uncommitted later candidate must select its authoritative
earlier committed record. The provider never guesses an older record, falls back to
ordinary generation, or treats a serialized pending bit as commitment. Recomputing
unpublished suffix work is allowed; replacing already committed event bytes is not.

Acknowledgement and committed-record selection are trusted local caller assertions,
not durable-write proofs. Owner tokens are object-local identities, not OS locks,
leases, remote fences or anti-cloning capabilities. Outer event/commit history and
S79 discarded prose/proposal/pass history remain caller-owned; children cannot
independently reconstruct it. Required/allowed public emitted phases establish
terminal status, without inventing access to their discarded event history.
Checksums are not AEAD, signed-history authentication or rollback protection.

## Projection and limits

Ordinary text maps each exact nonempty chunk to responseAppend with bound IDs and
tokenCount 1. Stop/length yields semantic prompt/generation usage and complete;
cancel preserves the permitted stop-prefix flush then cancelled, without successful
usage. Guided text maps chunks similarly; accepted EOS yields sampled-plus-forced
consumed usage and complete, excluding intercepted EOS and pending accepts.
Incomplete yields a bounded error; cancel adds no incomplete-text flush or usage.

Required/allowed ordered events pass through unchanged, including stable call IDs,
private syntax, whole final tails, route-specific usage and ready-wins cancellation.
No atomic final tail is split to fit credit. Cancellation itself is an acknowledged
prepared transition with the same pre-work reservation. Unexpected post-work mapping,
encoding or allocation failure closes the operation without returning a partial
candidate; prior independent committed records remain usable.

The fixed reservation is **192 MiB** before prepare/advance/cancel; no smaller-credit
optimization is attempted. Actual provider checkpoints are capped at **128 MiB**,
event/control payload excluding child state at **8 MiB**, and complete candidates at
**192 MiB**, with at most 4,096 events and 256-byte provider/owner/event IDs. Child
identity/tool-name/schema/token/cache/history limits remain unchanged. Ordinals use
checked UInt64 arithmetic. Required state is refused, never trimmed or relabelled.
Inherited parser extreme-number limitations remain outside arbitrary-input safety.

## Focused evidence

Seven XCTest methods cover actual four-route C0/empty/nonempty/terminal barriers,
exact and duplicate-last acknowledgements, wrong owners/commits/credit, overflow,
native terminal restore, changed bindings/routes/schema, corruption/encoded limits,
UTF-8 byte distinctions, cancellation policies, silent close and post-work failure
isolation. Explicit events/IDs/usage/tails supplement continuation comparisons.

Twelve sequential fresh producer/restore pairs cover all routes and representative
C0, visible, guidance-pending, required-ready, allowed-interpass, caller-discarded
uncommitted-later and committed-terminal boundaries, including one tiny real Llama
continuation. The producer exits before restore starts. The host fixture contains
only its selected committed candidate and prior prefix; expected future suffixes
are opened after native continuation. Event bytes/IDs/usage/endings and ordinals
are exact. Native float tensors/logits use explicit tolerances; future descriptor
hashes may reflect those tolerated differences. Within each execution, candidate
bytes and acknowledgements are exact. Prior raw/guided recurrence and S72–S79/RC1
campaigns are reused, not repeated as new proof.

Owned 0700 roots use `/private/tmp/reach-resumable-mlx-provider.*`, optionally with
`--companion-root /private/tmp/reach-s80.*`. Limits: 16 GiB combined allocated
scratch, 512 MiB simultaneous fixtures, 192 MiB each expected/selection file,
128 MiB tiny model/state tensors, 20 GiB free disk, four build jobs and one build/
test or worker at a time. Logs, selected/started/passed enumeration, worker results,
source/product/composition hashes and command-boundary resource observations remain.
Owned private copies are removed after joined work. This is ordinary supervision,
not continuous RSS, latency sizing or exhaustive opaque-descendant tracking.

Terminal Architecture PASS and Planning closeout are required for acceptance.
Host storage/publication, encryption/keys, OS ownership, receipts/effects, production
input/runtime/pin adoption, EXO, upstream/release and later slices remain outside S80.
Keeper stays Held and physical work remains deferred.
