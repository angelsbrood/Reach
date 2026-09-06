# Resumable native structural guidance (S77)

This local dependency candidate adds a `structuralTag:` initializer and explicit
`structural-tag` kind to S74's `ResumableGrammarSpecification`. Dispatch uses the
existing native `GrammarConstraint(tokenizer:structuralTag:fastForward:hostTokenizer:)`
initializer. The model loop, checkpoint core, matcher replay, pending forced-token
frontier and output-history validation remain unchanged.

The result is generated UTF-8 text and semantic endings. S77 does not construct a
ToolCall, allocate call/entry IDs, execute tools or publish partial arguments. Full
allowed/required routing, proposal selection/replay and effect publication remain
separate Reach-owned work.

## Specification and compatibility

The exact structural source, vocabulary/type, tokenizer identity, EOS/unknown IDs,
FF option and compiler identity remain encoded in the specification. Structural
source is passed directly to the pinned structural compiler, without lowering it
in Swift to ordinary JSON or literal EBNF. The Reach-shaped fixture uses a strict
`structural_tag` containing an `or` of tool-specific `tag` alternatives: fixed
JSON-escaped name/arguments prefix, each tool's own `json_schema`, and closing brace.
Embedded `$defs`/`$ref` remain root-local; no pointer rewriting or schema hoisting
is performed.

Schema 1 remains unchanged because kind/source already serialize and full restore
compares exact encoded specifications. Existing `json-schema` and fixture-only
`literal-fixture` encodings/dispatch remain unchanged. Unknown kinds refuse.
The compatibility check compiles the exact accepted S74 grammar file, creates
old-kind checkpoints in that native binary and restores them in the new native
binary. It also proves that old S74 full restore rejects the new structural kind;
successful envelope-only decoding is explicitly not treated as acceptance.

For that private old-API build only, the unused structural fixture-construction
branch is changed to an available initializer so the worker can link. Neither the
old-kind runs nor the decoded structural-refusal path executes that branch. The
old library grammar bytes are authenticated, and the new proven executable is
retained independently during the compatibility build.

## Retained paused-generation contract

Prepare validates bounded specification/options and compiles the actual grammar
before model work. Restore recompiles exact source, replays each successful accept
once through the existing single-accept path, and validates full model, matcher,
consumed/pending, whitespace and output-history joins. It performs no new FF query
or accept during replay, prompt/model replay, sampling, usage increment or output.
Bounded deterministic tokenizer derivation remains part of the inherited contract.

Every sampled token is consumed by the model before its accepted forced suffix;
each forced input is consumed once. A partially chosen name/argument is preserved
by actual history and frontier, not guessed from visible text. Snapshots retain
accepted-but-unconsumed forced tokens. Record chunks and UTF-8 bytes stay exact.

The inherited `accepted-stop-v1` policy requires an accepted EOS/terminated grammar
for `complete`. Budget exhaustion is `incomplete`, including a fully closed,
parseable envelope for which EOS is allowed but has not been accepted. Zero budget
performs no model work. Cancellation returns one cancelled terminal without model
work or text flush; repeated terminal operations return nil. Close silently
discards, failures return no usable partial batch, and prior snapshots remain usable.

## Scope and bounds

Apply pinned base → unchanged S72 → S73 → S74 → S75 → S76 → S77. The runner authenticates
all 25 prerequisite Reach products and all 31 prior dependency outputs before S77.
Only `Libraries/MLXGuidedGeneration/ResumableGrammarState.swift` may differ afterward;
the other 30 outputs stay exact. Two new focused tests complete the three-path delta.
No bridge/shim/vendor, model, loop, checkpoint, parser, pin or shared source is edited.

All S74 limits remain: 16 MiB actual composite, 8 MiB model component and individual
live cache tensor, 1 MiB encoded guidance/output plus returned records, 64 KiB source,
4,096 vocabulary entries/256 KiB encoded vocabulary, 65,536 accepts, 4,096 pending
FF tokens, 256 KiB retained/decoded text and at most two records per batch. Existing
finite bias/counter limits also remain. Growth refuses without dropping required
state. Checksums detect ordinary corruption; no hostile-forgery or arbitrary-history
proof is claimed.

Only the selected literal/tag/or/json_schema structural forms are covered. The
pinned one-argument native parser receives no tokenizer-info; token-aware structural
formats are not a support claim. Existing embedded-schema whitespace is preserved,
not canonicalized. There is no arbitrary-schema/format correctness, hostile-input
crash-safety or resource-hardening claim. A completed structural envelope alone is
not permission to invoke a tool.

## Offline native verification

```sh
python3 -B run.py --reach /Users/nellymoon/Documents/Swift/Reach
```

Use normal platform approval for native Metal when required. Do not bypass a denial.
The runner uses local pinned exports and the authenticated existing metallib; no
network, dependencies/assets download, toolchain upgrade or shared cache write.
The private S74 package lane includes actual MLXGuidedGeneration, MLXCXGrammar,
MLXLMCommon and a fixed tiny two-file Llama target. Vendored C++17, wrapper/exclusion,
namespace defines and header settings are preserved. No FoundationModels/app harness
is imported to construct the synthetic structural JSON.

Eight focused XCTest methods exercise 61 selected cut/restoration cases (including
ten focused old-kind cases). They cover single and multiple offered names, escaped
names/content, Unicode, incompatible per-tool schemas with root-local refs, arrays
and enums, C0, partial name/arguments, observed nonempty pending FF, accepting but
not terminated state, FF-off, completion/incomplete/cancelled terminals and tiny
library Llama. A separate pinned structural matcher verifies actual prefixes and
termination. Explicit generated token/chunk/envelope oracles and independent model
input/cache/typed-state recurrence supplement continuation comparisons.

The narrow initial native probe observes a nonempty structural forced suffix and
requires actual EOS termination; literal-fixture FF is not structural evidence.
The eleven new fresh producer/restore pairs target C0, pending FF, name, arguments,
Unicode, alternative selection, complete/incomplete/cancelled terminals, Llama and
FF-off. Each producer exits before restore. Restore receives only the checkpoint
and compiled immutable fixture/binding definitions. Native model continuation
generates the suffix; expected output is opened only afterward. Token/origin
history, pending/masks/counters, records and integer metadata compare exactly;
model/cache/logit floats retain `atol=1e-6`, `rtol=1e-5` comparisons. Nested checksums
are verified against actual bytes. Llama is identified separately from the forced
analytic model and is not a route/tool-publication proof.

Focused refusals include changed kind/source/name/schema/alternative order/options/
vocabulary, malformed sources, corrupt/truncated/oversized values and contradictory
accept/pending/model/output/lifecycle joins. An independent valid operation remains
unchanged. Unchanged S72–S76 campaigns and S74 RC1 output-history proof are reused;
they are not blanket-rerun or counted as new structural evidence.

The runner retains commands/logs, exact product/source/patch bindings, test enumeration,
fresh-process and compatibility results, and command-boundary resources under owned
0700 `/private/tmp/reach-mlx-structural-guidance.*`. It removes only its private
source/build/fixture/helper roles on settlement. At most four build jobs and one
build/test or worker run at a time, with timeouts and owned joins. No persistent job
is launched; observations are not continuous peaks or exhaustive descendant history.

Combined owned scratch stays below 16 GiB, simultaneous synthetic fixtures 64 MiB,
tiny model/state tensors 128 MiB, and at least 20 GiB disk remains free. Checkpoints
are bounded at 16 MiB and expected files at 32 MiB, with a separate combined 64 MiB
check. Pair fixtures are deleted when settled. Optional `--companion-root
/private/tmp/reach-s77.<suffix>` includes owned development scratch in observations.

Reach runtime/pin adoption, full route coordination, host/client persistence, EXO,
upstream submission, release and later slices remain outside S77. Keeper is Held;
physical work remains deferred.
