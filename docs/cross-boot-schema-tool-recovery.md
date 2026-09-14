# Combined schema and tool recovery across reboot

S105 extends the explicit native recovery qualification to an allowed request
with one canonical response schema and one offered portable tool. It uses the
existing `.allowed` route and original authority, clock, admission, checkpoint
and receipt formats. Execution and review verdicts belong to the private S105
handback; this document describes the contract.

The ordinary `reachd` and tiny Llama artifact qualify schema fallback after a
private no-call probe. The separate `reach-allowed-recovery-fixture` executable
qualifies tool precedence despite the response schema. Its identity remains
`s104-structural-allowed-v1`; its immutable scripts and native state/cache/codec
algorithm are unchanged. This fixture does not establish learned Llama tool
selection, and the normal daemon still rejects its configuration.

Both branches keep probe prose private. Complete observed proposals select tool
guidance; otherwise the existing coordinator lazily selects schema guidance.
More than one proposal refuses before next-pass preparation or publication.
The existing parser and all-name behavior remain unchanged, including the JSON
parser's filtering of unoffered names. An unsupported unused fallback schema is
not compiled on the tool branch. If selected schema compilation fails after the
model factory is evaluated, no model-state preparation or native forward occurs;
the refusal preserves the last accepted candidate and does not invent a terminal.

Original and derived pass inputs contain 1–512 tokens, prefill is 256, and probe
and guidance use the same requested maximum M in 1–64. M is a per-pass limit.
Response and tool declarations share the existing preparation byte/tree/depth
bounds. Provider bytes remain at most 16 KiB and canonical frames 64 KiB. Full
stored declaration reconstruction precedes runtime factories. Schema input uses
the exact original token IDs, index zero, no proposal ID and no repair messages.
Tool input remains the authenticated selected-proposal repair. Recovery never
re-encodes the original request, template or tokens; legitimate repair/grammar
encoding is recorded separately.

Read-only progress projects completed contributions and returned schema bytes
from the exact acknowledged candidate and fully validated child. Successful
schema usage is twice the original prompt count, plus probe generation and
completed guided sampled/forced output. Successful tool usage includes the
original and repair prompt counts. Active, failed or cancelled guidance adds no
unfinished-pass usage. Host final publication validates the exact branch,
selected call and aggregate counts against that history.

The model-free client retains original response-schema and sole-tool provenance.
It rejects a combined call after any public response prefix, while preserving
the nil-schema route's legitimate prose-before-call behavior. Schema responses
may stream before success. Exhaustion may retain response bytes followed by
`finished(error)` in the same batch, with zero calls and no success usage.
Cancellation keeps its existing singleton terminal policy. Receipt acceptance,
reopen and exact duplicate replay validate prefix/call digests, zero/one call
count and terminal state; persisted intents and outcomes remain refused.

Each action performs at most two active probe/guided advances, with all existing
checks, commit, acknowledgement, synchronization, delivery and receipt boundaries
between them. Phase changes end the unit. Initial and selected next-pass prefill
and finalReady delivery remain separate actions. The ceiling is two forwards and
ten receiver seconds per action, with 64 actions per owner, 128 nonces per witness
and 16 registrations. Feasibility derives protocol costs from the actual phase
trace and reserves at least two owner actions and eight witness nonces.

`Tools/CrossBootSchemaToolRecovery/run_vm.py` uses one disposable four-CPU/eight-GiB
receiver VM. Host feasibility precedes launch; guest feasibility precedes original
roles. Each primary crosses a cold reboot at positive private probe state and a
second at active guidance with pending forced work. Schema guidance must already
have a visible nonterminal prefix; tool guidance remains private. Host-ahead
schema bytes replay before native work, and saved forced tokens are consumed
before sampling. The same original witness and admission survive both reboots.

Each lane has a distinct serial reference pair and witness, using one
uninterrupted owner. Every event byte, selected progress state and per-pass native
input/offset trace must match. Fresh finalReady workers validate the child and
emit with zero forwards. Fresh terminal and duplicate workers run with model and
original reads denied and perform zero model loads, compiles or forwards.

A separate original pair delays eleven seconds after actual schema-pass prefill
and must refuse publication. Evidence retains observed prefill, elapsed delay,
the last accepted commit and honest disk-reconciliation uncertainty. A numerical
rejected clock sample is reported only when existing machinery exposes it. S104
tool-prefill refusal and named historical clock cases are reused only for their
unchanged dependencies.

Owned UID503 guest roles retire through exact original receipts and executables
before guest payload and clone disposal. The campaign retains directly observed
process joins, unchanged Keychain metadata, sampled resources and failed attempts.
Limits remain 32 GiB owned allocation, 3 GiB fixtures, 20 GiB conservative added
volume charge, 30 GiB host free, 128 MiB native peak, 192 MiB per log and 1 GiB
retained evidence. No effects, multiple calls, production/default or transport
adoption, publication, release, later phase or Keeper work is opened.
