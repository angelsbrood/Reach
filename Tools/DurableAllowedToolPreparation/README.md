# Allowed-tool durable request preparation (S91)

This offline composition selects `s91-public-chat-allowed-v1` on the existing
S89/S90 request preparer. S89 stays the default; its encoded descriptor and
ordinary/required bindings and the S90 schema revision remain unchanged. The
owner attests the selected revision and actual local artifacts. Frames cannot
upgrade this capability by naming a model.

With this revision, 1...8 unique offered tools and nil/allowed tool mode select
the allowed route. Required remains required; disallowed with offered tools
refuses. Context/reasoning controls must be nil. Tools combined with a response
schema refuse. No-tool ordinary and schema-only admission retain the old rules.
Sampling is nil/greedy and temperature nil/zero. Maximum tokens accepts 0...512
(default 512) independently for the probe and each guided pass. It is not a
whole-turn limit; final usage sums completed contributions.

Actual ordered text and tool names/descriptions/canonical schemas enter the same
public chat/template path. RC1 throwing schema extraction and the shared 64 KiB,
8,192-node/depth-32 request limits precede serialization and original preparation.
The resulting 1...2,048 original tokens, fixed JSON tool parser, canonical tools,
same selected model/cache/codec for both passes, options and deterministic entry/
parser IDs form the existing AllowedToolBinding. Stored validation reconstructs
that selected declaration before attach/acceptance, without reconstructing the
original request digest preimage. No provider, coordinator, adapter, store, wire,
shipping, parser implementation, native output or dependency pin changes.

The parser uses `<tool_call>{"name":...,"arguments":...}</tool_call>` proposal
syntax. Guided passes retain the existing repair-message policy, parser call IDs
and ordered settled tool events. The JSON parser filters undeclared proposal names; they are
not treated as successful optional-tool calls, and later declared proposals remain eligible. This tool executes no real effect.
Late derived-input/grammar failures remain late failures. Zero probe budget can
finish as empty prose with usage/complete, while guided exhaustion has no invented
success usage. Cancellation and final-ready-wins are unchanged coordinator policy.

Run against canonical Reach with the pinned checkouts and Metal artifact already
present:

```sh
python3 Tools/DurableAllowedToolPreparation/run.py --repo /Users/nellymoon/Documents/Swift/Reach
```

The harness has two explicit proof families using the same preparer and encoded
adapters. Real tiny-Llama weights prove optional-tool prompt consumption and prose
continuation. The existing structural state model proves prescribed two-call
proposal/guided integration. Its immutable scripts, pass selection and prompt-count
policy are bound into its actual structural descriptor; both passes use one simple
dim-4 cache and the existing state codec. It does not masquerade as Llama or prove
learned tool choice. Runtime scripts come only from fixed owner-selected configuration
and the coordinator's authenticated AllowedPreparedPass. S89/S90 Llama-guided proof
is reused only for unchanged engine scope.

Fresh workers receive only fixed fixture family, mode, disk root and output path.
Original preparation/template/request tokenization/issue/begin must stay zero.
Repair-history re-encodes, native grammar encodes and later new-pass factories and
prefills are legitimate and counted separately. Active-probe and active-guided
continuations compare exact bindings/context/reference, batches/events/order/IDs/
usage and per-pass native input/cache-offset suffixes; logits use rtol 1e-5 and
atol 1e-6. The fresh restored child must make positive work before oracle comparison.

The runner builds with four jobs and serializes tests/native workers. It retains
bounded ordinary logs, snapshots, copied/native bindings, selected/started/passed
counts, failed attempts and sampled resource observations; directly owned children
are joined and exact private source/build/fixture roles removed at settlement.
Known non-secret fixture keys only, with no Keychain API, network, credentials,
old worker campaign, production adoption or shipping offer change. Client/policy
linkage remains MLX-free; shipping offers remain [1,0] with readiness/opt-in off.
