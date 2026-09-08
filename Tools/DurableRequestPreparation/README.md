# Durable request preparation candidate (S89)

With its default `s89-public-chat-tools-v1` revision, this offline tool prepares real bounded text/tool requests for the existing S88
durable adapters. It is not daemon/SDK adoption or a production model registry.
The default adapter policy remains the exact two-request S88 fixture contract.
A trusted local owner explicitly supplies `RequestPolicy`, its immutable
`ModelDescriptor`, and the host's persisted-preparation validator. Frame contents
and model-name strings cannot select a policy.

The portable contract and client composition contain no MLX dependency. The
descriptor attests actual local configuration/weight material, tokenizer
algorithm/vocabulary/configured template, preparation revision, backend/pins,
cache/codec and text/guided policy. The native owner checks the selected descriptor
against current artifact attestations; it cannot introspect arbitrary closures.
The fixture uses unchanged deterministic `FixtureModel(kind: "llama", ...)` and
its actual weight digest, two simple KV caches and empty codecs.

The complete canonical request (including UUID, IDs, metadata and options),
descriptor, model/profile and route produce a 170-byte persisted request identity.
This is distinct from the native digest of actual prepared tokens. First begin
acceptance must match the exact request binding remembered by the client before
journal creation or enrollment. Recovery authenticates the original selected
disk context/ticket and validates the stored preparation before host attachment.
It does not render, tokenize, issue/begin, replace stable IDs/seed or call
`LanguageModel.prepare`. Existing checkpoint restore remains the native authority.
Request tokenizations and total tokenizer encodes are counted separately. Fresh
entry has zero of both; subsequent required continuation may encode native grammar
completion/fast-forward text through unchanged XGrammar/CompletionReserve code.
Those encodes are reported and do not reconstruct or replace prepared input.

Preparation synchronously maps ordered text to public `Chat`/`UserInput`, calls
`DefaultMessageGenerator.generate(from:)`, then calls the selected configured
`Tokenizer.applyChatTemplate` with `enable_thinking: false`. There is no fallback
template or fixed token input. The fixture serializes bounded canonical JSON
messages/tools and an assistant prefix, then encodes UTF-8 bytes plus one.
Historical tool IDs/names/object arguments and result associations are preserved;
unresolved, duplicate, malformed or mismatched call/result associations refuse.
Text segment content is concatenated in order without invented separators.
Historical entry/segment IDs and inert prompt/response/call metadata are retained
in the complete request binding but are not model input. Prompt options/context
controls, response formats/schema, assets, reasoning, structured segments and
historical offered-tool declarations refuse. Current tool definitions are encoded
through the portable schema's throwing Encodable entry. A single-value tree
capture preserves pre-serialization bounds and propagates retained deferred
conversion errors; neither precondition-backed `jsonValue` nor the Apple getter
is read. Unexpected encoder shapes refuse.

Admission is text-only, <=64 KiB canonical request, 1–64 entries, <=64 segments
per entry, <=8 calls per historical batch and 1–2,048 in-vocabulary tokens.
Strings/JSON trees are bounded before serialization; template appends enforce
64 KiB before growth. Required requests offer 1–8 unique tools and explicitly
select `.required`. Ordinary requests offer no tools and permit absent/allowed/
disallowed tool mode. Offered tools with other modes are outside this candidate.

Maximum response tokens accepts 0–512 and defaults to 512. Ordinary greedy or
explicit zero temperature uses argmax. Top-K accepts 1 through vocabulary size;
top-P accepts 0–1, with zero selecting argmax. Stochastic temperature defaults to
0.6 and requires an explicit seed on top-K/top-P. Finite nonnegative representable
temperatures and finite filter ranges are required. Greedy overrides an admitted
temperature; no random seed is generated. When argmax has no seed, its unused
native seed field is zero. Required accepts nil/greedy sampling with nil/zero
temperature; nil defaults are explicitly greedy. Positive temperature or a
stochastic sampling case refuses. Selected EOS/UNK/stops, prefill size 64, cache,
codec, greedy closing and whitespace policy are internal descriptor-bound values.

Run `python3 Tools/DurableRequestPreparation/run.py --repo /absolute/Reach`.
The runner copies authenticated S88 inputs and the same six pinned checkouts,
applies the unchanged 35-output native composition, builds offline with four
jobs, tests the selected adapters and new preparation code, and runs serialized
fresh-process ordinary/required tiny-Llama continuations. A second required
singleton schema proves n=8 versus n=7. Comparison oracles are read after fresh
native work; they are never recovery inputs. Native observations prove actual
prefill tokens and compare continuation inputs/cache offsets/logits with
rtol 1e-5 and atol 1e-6, plus exact bindings/batches/events.

Only known non-secret disposable key constants are used. No Keychain API,
network, listener, VM, installed app, real tool or effect campaign runs. Existing
S88 acquisition/crash/publication and deeper native/crypto/clock/effect evidence
is reused for unchanged mechanisms. Every attempt retains bounded logs and
results. Direct owned children are joined and owned fixture/build trees removed;
resource observations are sampled boundaries, not exhaustive descendants, RSS
or physical-media erasure claims. Limits are 16 GiB aggregate allocated disk,
3 GiB fixtures, >=20 GiB sampled free disk, 192 MiB per log/evidence and 128 MiB
native peak/weight tensors. Canonical source installation and terminal Architecture
review are separate from the runner's local PASS.

## Explicit schema revision (S90)

`ModelDescriptor.schemaRevision` selects `s90-public-chat-schema-v1` on this same
preparer. No encoded descriptor field was added, and the old default revision,
ordinary/required request identities, tokens and bindings retain their S89 bytes.
`NativePreparationFixture` and `PreparationPair` accept an explicit revision;
their defaults remain unchanged. Guided runtime selection reuses the existing
provider, adapters, stores and native grammar implementation.

The selected schema route requires no offered tools/reasoning, no required mode,
and explicitly false `includeSchemaInPrompt`; nil/true refuse. Sampling is
nil/greedy, temperature nil/zero, maximum 0...512 with default 512. The response
schema uses the same throwing tree extraction and shared whole-request bounds.
It becomes a canonical guided specification; text/history still use the same
chat/template path without schema prompt injection. Stored guided declarations
must match the selected native identity, tokens, grammar, vocabulary/tokenizer,
EOS/UNK, cache/codec, options and stable IDs before attach/acceptance.

Compiler compatibility is checked by the existing native prepare/restore path,
not portable admission or `assess`: it may fail after accepted begin and model
factory evaluation but before prefill. See `../DurableSchemaPreparation/README.md`
for the focused offline native continuation harness and its literal reuse scope.
