# Combined schema-and-tool durable preparation (S92)

This offline composition selects `s92-public-chat-schema-tools-v1` on the existing
S89–S91 preparer. It admits a response schema with 1...8 unique offered tools in
nil/allowed mode, explicitly false `includeSchemaInPrompt`, and nil reasoning.
Combined required/disallowed modes refuse. The other routes keep their existing
rules; S89 stays default and old revision identities/admission remain unchanged.

Actual text and tool definitions enter the existing public chat template. The
response schema guides fallback without prompt injection: changing only its
constrained value preserves original tokens while changing request identity,
stable entry/parser IDs and fallback output. Both kinds of schema use RC1's
throwing capture before serialization or trapping accessors and share the whole
request 64 KiB / 8,192-node / depth-32 limits. Stored names, tool schemas and response
schema also share one byte/tree budget. Original tokens remain bounded to 1...2,048.

The existing allowed declaration retains fixed JSON parsing, canonical tool and
response schemas, original tokens, same selected model/cache/codec for probe and
guidance, native/text policy and deterministic IDs. S92 domains include the optional
canonical fallback; S91 domains/bytes stay exact. Stored validation compares the
complete selected declaration before attachment. Authenticated storage remains the
original-request authority; validation does not recreate a request digest preimage.
Sampling is nil/greedy, temperature nil/zero, maximum 0...512/default512 independently
for every pass. Final usage includes hidden probe work and completed guidance once.

The unchanged coordinator hides schema-present probe prose. Ordered proposals win
and produce settled tool calls; otherwise schema guidance uses the exact original
prepared tokens. Tool passes keep the existing repair-message path. Native fallback
compilation is lazy: an unsupported grammar can fail after accepted begin and probe
work, after fallback factory evaluation but before its model-state preparation or
forwards. That thrown error is not automatically converted into a wire terminal.
An unused unsupported fallback is never compiled on the tool branch. Combined zero
budget produces incomplete/error with no final usage; insufficient guidance preserves
committed output. Existing cancellation/final-ready-wins policy remains unchanged.

Run with the existing pinned checkouts and Metal artifact present:

```sh
python3 Tools/DurableSchemaToolPreparation/run.py --repo /Users/nellymoon/Documents/Swift/Reach
```

Two primary reference/checkpoint/fresh triples use the same preparer and encoded
adapters. Actual tiny-Llama proves hidden probe plus schema fallback, including a
visible nonterminal checkpoint prefix. A separately identified structural state model
proves hidden prose plus two ordered tool proposals, recovery during first guidance,
and a later new tool pass with no schema factory/output. Its immutable scripts, pass
selection and prompt-count policy are bound into its descriptor independently of
requests and oracles. Native logits still depend on real inputs/cache/state; this
structural family does not prove learned tool choice or masquerade as Llama.

Fresh workers receive only fixed family, mode/root/output and selected retained disk
state. Original preparation/template/request tokenization/issue/begin stay zero.
Repair-history and grammar encodes, and later new-pass factories/prefills, are counted
separately as legitimate work. Restored active children must do positive new work
from retained offsets before comparison oracles are read. Bindings/context/reference,
batches/events/IDs/usage and per-pass input/offset suffixes compare exactly; native
logits/state use rtol 1e-5 and atol 1e-6.

The runner selects current causal S89–S91 preparation tests, two dependent S88 adapter
tests and focused S92 cases; the portable client's linkage stays MLX-free. Compact
native variants cover constrained schema changes and zero/short fallback budgets.
Deeper unchanged coordinator/parser/cancel/store/Keychain/crash/effect evidence is
reused within its tested scope; no historical worker campaign runs.

Four build jobs, serialized tests/workers, 16 GiB owned allocation, 3 GiB fixtures,
20 GiB sampled free disk, 192 MiB per evidence/log and 128 MiB MLX allocator/model
limits apply. Direct owned children are joined and owned source/build/binary/fixture
roles removed at settlement; bounded logs/evidence/failures remain. Measurements are
sampled boundaries, not exhaustive descendants/RSS or physical-erasure guarantees.
Known non-secret fixture keys only; no Keychain API, credentials, network or real tool
effects. No coordinator/provider/adapter/store/Wire/native/pin or shipping edits;
offers stay [1,0], opt-in/readiness off, and production adoption remains later work.
