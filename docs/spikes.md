# Spike verdicts

Each spike runs on a `spike/*` branch that is never merged; what lands here is
the decision. Kill criteria come from the pre-filing plan.

| Spike | Question | Status |
|---|---|---|
| S4 | Does `LanguageModelSession` accept a third-party `LanguageModel`/executor at runtime, and does an MLX filling stream behind the slot? | **PASS** (2026-07-21) |
| S1a | QUIC with mutual TLS between provisioned certificates (client-cert challenge + CA pin), loopback | **PASS** (2026-07-21) |
| S1b | Behavior of the QUIC connection across a Wi-Fi → cellular interface transition (migration vs re-attach) | **PASS** (2026-07-22) — re-attach at the mesh address *is* the transition; migration has nothing to migrate to; `.handover` off |
| S2 | Development-signed packet-tunnel extension carrying WireGuardKit traffic on device | **PASS** (2026-07-22) — kill fired on the personal team, reversed same day by program enrollment; embedded tunnel verified end to end |
| S3 | Headscale as a supervised subprocess with programmatic pre-auth key minting | **PASS** (2026-07-21) |
| S5 | Does a road the user already owns — their own tailnet — work as a Reach candidate without code? | **PASS** (2026-07-24) — by construction, then confirmed on hardware: the session fell to the tailnet with the Reach tunnel down, and the mesh sat idle |
| S6 | How does the framework's session drive a tool round trip through a third-party executor? | **PASS** (2026-08-05) — the transcript loop, and it is forced: the channel is send-only, so no `respond` call can receive tool output. `capabilities` is a hard gate, not a label |
| S7 | Does the slot model emit tool calls the host can parse? | **PASS** (2026-08-05) — `gemma-4-e4b` 5/5, ~0.85 s per round trip; MLX parses the call itself, and the grammar has no escaping, which is why arguments cross whole |
| S10 | What does a pre-negotiation peer actually survive? | **PASS** (2026-08-08) — unknown optional JSON keys tolerated 3/3; unknown type 255 fatal 3/3; authenticated and enrollment ALPN mismatches each ended in opaque `stream open timeout` 3/3 |
| S11 | What does a real `@Generable` response do before the daemon honors its schema? | **FAIL / FUNCTION GAP** (2026-08-08) — all six shapes, three runs each with prompt schema on and off, were refused by FoundationModels before the executor ran: 36/36 exact `unsupportedCapability`; no schema or transcript crossed the wire |
| S12 | Can the pinned grammar engine constrain FoundationModels schemas within the warmed latency gate? | **PASS** (2026-08-08) — five schema shapes compiled; warmed first accepted delta 30–39 ms; xgrammar 0.1.30 cannot fork, so the required fresh-compile fallback costs ~13 ms for the two-field schema and ~120–135 ms for the adversarial benchmark |
| S13 | Can generic structural guidance repair allowed tool calls and force required calls across the planned schema range? | **STOP / REPLAY FAILED** (2026-08-08) — nested and fixed-array calls failed unconstrained 3/3 and repaired 3/3, and generic required produced a valid Gemma 4 call; the adversarial replay nevertheless exhausted 512 tokens through legal numeric runaway 3/3, firing the plan's stop before implementation |
| S14 | Was S13's adversarial stop a missing parser, or a wrong completion policy? | **PASS** (2026-08-08) — treating comma as a structural exit and digits as content completed the exact adversarial schema 3/3; negative, decimal and nested-number controls also passed 3/3, so no parsing table or Swift schema state machine was needed |
| S15 | Does S14's completion repair survive probabilistic sampling? | **STOP / SAMPLING FAILED** (2026-08-08) — at temperature 0.2 the first four shapes accepted and decoded, but the exact adversarial shape's second run exhausted 512 legal tokens; the locked kill fired before permanent code, a fork pin or the higher-temperature arms |
| S16 | Can requested sampling retain a deterministic hard-completion boundary? | **PASS** (2026-08-08) — all 36/36 accepted and decoded at 0.2, default 0.6 and 1.0; simple shapes sampled throughout, while the adversarial shape sampled 13–14 decisions before 129–156 hard-zone argmax decisions completed it |
| S17 | Does S16's hybrid survive product acceptance beyond its four retained shapes? | **STOP / DECODE FAILED** (2026-08-08) — the installed schema-plus-tools path produced grammar-accepted JSON that FoundationModels could not decode; a deterministic `topP(1, seed: 29)` response reproduced an unbounded integer outside Swift `Int`, firing the locked decode kill and rolling back the fork and product changes |
| S18 | Do decoder-compatible numeric grammars make S16's hybrid safe to ship? | **STOP / BUDGET FAILED** (2026-08-08) — exact signed-64-bit and finite-Double grammars passed in isolation and seed 29 decoded, but the unchanged adversarial schema exhausted 512 tokens at temperature 1.0 after 28/36 accepted matrix cases; no sampler or numeric fork ships |
| S19 | Can the installed greedy path reach a grammar-accepted numeric value that fails typed decoding? | **STOP / NOT REPRODUCED** (2026-08-08) — five hostile unbounded numeric asks completed and decoded 3/3 each, 15/15 total; neither the `Int` nor `Double` mismatch was reachable, so no Reach normalization, dependency pin or installation change ships |
| S20 | Can baseline-v0 `Ping`/`Pong` distinguish legitimate model silence from a progressively degrading active road quickly enough to enter the existing candidate race? | **PASS** (2026-08-08) — signed Simulator acceptance kept queued real-weight silence in place 3/3 and recovered seeded degradation 3/3; the natural phone walk reattached the same generation over `10.86.0.2` at sequences 1016 and 1433 and visibly completed |
| S21 | Does the installed cluster survive short, residency-scale and overnight system sleep without product wake machinery? | **PASS / DOCUMENTATION ONLY** (2026-08-10) — 2× short, 2× ten-minute and 2× eight-hour-plus trials preserved the daemon, listeners, model and mesh; the system broker recreated expired mappings four seconds after wake, so no Reach sleep code was licensed |
| S22 | Why does one installed `reachd` find MLX resources by its canonical path but not through a symlink or bare `PATH` command? | **PASS / CANONICAL RE-EXEC** (2026-08-10) — the loaded image and `dladdr` already resolve to the canonical binary, while `Bundle.main` remains beside the launch alias; one early `execv` of the resolved executable makes every invocation use the canonical adjacent bundle set |
| S23 | Which authority owns the host across lock, logout and reboot? | **PASS / LOGIN CLUSTER, ROOT ROAD** (2026-08-10) — one lock, two logout/login and two reboot/pre-login/login trials selected login-owned serving, proved late roads need no daemon restart, and isolated automatic privileged mesh activation as a separate pass |
| S24 | What least-privileged installed component can restore the host mesh without owning the cluster? | **PASS / ROOT-OWNED HEADLESS MESH OWNER** (2026-08-11) — a scriptless helper with strict data-only state survived the physical lifecycle matrix; final-byte crash recovery restored interface plus connected route, and a strict building-network cold open arrived from `10.86.0.2` and streamed to `done` |
| S25 | Can one model-neutral provider slot bound concurrent public generations without changing single-request correctness? | **PASS / ONE ACTIVE, THREE FIFO WAITERS** (2026-08-12) — fake and real-weight probes found accidental overlap but no model-path failure; the shipped lease covers one complete public generation, admits three bounded waiters and refuses overload as reachable-busy |
| S26 | What exact volatile replay capacity preserves whole-or-refuse reattachment without limiting live generation? | **PASS / FOUR PHYSICALLY EXACT MEMORY WINDOWS** (2026-08-13) — deterministic framed bytes replaced the 4 MiB estimate; one generation retains 16,777,220 bytes, the process retains four such windows, popped payloads are destroyed immediately, and live delivery continues while an unavailable replay refuses |
| S27 | Can the pinned provider restore one exact public generation across process death on every shipped route? | **EVIDENCED STOP / RAW KV IS NOT A GENERATION** (2026-08-13) — ordinary, guided, allowed-tool and required-tool execution all lack complete serializable provider state; corrupted cache files were accepted, and client-owned tool effects require acknowledgement/idempotency rather than inferred recovery |
| S28 | Would explicit structured-partial wire events add a capability beyond Foundation Models' locally derived typed snapshots? | **EVIDENCED STOP / THE TYPED VALUE WAS ALREADY ON THE CLIENT** (2026-08-13) — 21/21 real TLS/wire/daemon/guided executions plus synthetic typed probes found no structured information absent from the text-derived surface; candidate payload models added overhead and the public executor exposes no structured injection action |

## Upstream checkpoint — nested tool grammar schema test (2026-08-11; merged 2026-08-17)

The first prepared post-S19 dependency contribution was filed as
[`mlx-swift-lm` PR #527](https://github.com/ml-explore/mlx-swift-lm/pull/527).
Fresh upstream `main` was `0b47e698`; the publication commit is `634345a`,
whose stable patch ID exactly matches prepared commit `7828993`. The PR merged
on 17 August as upstream commit `ef0b0cc945896216902ccd7f8df1590eb848485f`.
It contains one commit and one changed test file (+12/-6), and changes no
library, package, public API or runtime behavior. Post-filing review found no
actionable correctness, security, performance or maintainability issue. After
the initial approval-gated run, GitHub Actions completed both `lint` and
`mac_build_and_test` successfully before merge.

The current-base `ToolCallingSchemaTests` reproduced the stale assertion at
**11/12**: only `grammarBuilderHoistsNestedDefsInBothArms()` failed at its
former direct-shape lookup. The replayed correction passed **12/12**. Paired
complete `xcodebuild test` runs produced no branch-only failure line: both hit
the same existing Foundation Models Swift Testing runner crashes and
continuation-test failures, while the baseline additionally failed
`TurboQuantIntegrationTests.testRawKeyModeBFloat16MatchesReference()`.
`pre-commit run --all-files` passed, and `scripts/verify-docs.sh` ended with
all documentation builds passed.

This is ecosystem maintenance, not a Reach product or grant-frontier change.
The project record is therefore **five merged upstream contributions and none
open**. The signed-range prototype `fd04f2f` remains unpushed and unfiled but is
now **retired**, not pending publication: it hand-edits MLX's pinned xgrammar
v0.1.30 snapshot even though its vendor marker routes patches upstream, and
upstream [xgrammar #669](https://github.com/mlc-ai/xgrammar/pull/669) already
shipped the broader number-generation repair in
[v0.2.3](https://github.com/mlc-ai/xgrammar/releases/tag/v0.2.3).
Its tests cover the full two-sided range and one-sided minimum, but not the
touched one-sided negative-maximum path. `b871cd7` remains parked and unfiled.
A future MLX xgrammar sync would be a separate dependency upgrade, not this
patch.

## S19 — the typed mismatch is architectural under the shipped greedy path (2026-08-08)

**Question and gate.** S17 proved that sampled constrained generation can
produce grammar-accepted JSON that FoundationModels cannot decode. S19 asked
the narrower product question before hardening anything: can the installed
greedy daemon at `32f93a2` reach the same class of mismatch at its real
defaults? The locked stop required no Reach product change and no fork pin if
neither `Int` nor `Double` reproduced.

The launch-environment-only instrument was a normally signed Simulator build
using the existing Example identity, `127.0.0.1`, and `gemma-4-e4b`. Every run
created a fresh `LanguageModelSession`, sent one exact prompt with a 512-token
ceiling, streamed the response, and retained the final typed value. The two
wire schemas were the framework's sorted-key encodings:

```json
{"additionalProperties":false,"properties":{"value":{"type":"number"}},"required":["value"],"type":"object"}
{"additionalProperties":false,"properties":{"value":{"type":"integer"}},"required":["value"],"type":"object"}
```

The three ordered runs for each ask were identical in value and snapshot
count. Timings below are end-to-end `streamResponse` wall time from request
construction through the final typed snapshot:

| Exact requested value | Final typed value | Snapshots | Seconds, ordered |
|---|---:|---:|---|
| `1e309` (`Double`) | `1e+30` | 5 | 0.344, 0.236, 0.233 |
| `2e-324` (`Double`) | `2e-32` | 5 | 0.223, 0.221, 0.221 |
| `9223372036854775808` (`Int`) | `922337203685477632` | 18 | 0.419, 0.421, 0.415 |
| `-9223372036854775809` (`Int`) | `-9223372036854775808` | 22 | 0.416, 0.415, 0.414 |
| 100-digit all-nines (`Int`) | `1000000000000000000` | 18 | 1.524, 1.510, 1.542 |

The model did not obey the impossible requested literals; greedy completion
closed each numeric token at a decoder-safe value. That is not evidence that
the ordinary JSON grammar is type-safe. It is the narrower evidence the gate
asked for: **0/15 typed failures, with streamed completion in every run.** The
normally signed evidence screen and exact timing ledger were retained locally;
the app was terminated after capture.

**Dependency division of labour.** Reach can deterministically annotate every
response and tool schema before encoding, but it cannot make xgrammar compile
new numeric semantics without becoming a second schema compiler. The converter
must own exact signed-64 range construction and a finite-binary64 lexical
grammar; Reach should only opt into those semantics once the dependency offers
them. Three independent fixes were therefore prepared and tested on current
upstream `c97539d`: signed-64 range generation passed 2 boundary tests plus the
7 CXGrammar tests; finite `format: "double"` passed 5 boundary/refusal tests
plus the 7 CXGrammar tests; and the stale structural-tool assertion now passes
its complete 12/12 suite. A broader guided-generation run reached an unrelated
existing test-harness failure loading MLX's default Metal library; the
converter and CXGrammar suites were then run separately and passed.

**Verdict: STOP / NOT REPRODUCED.** Both candidate product defects remained
unreachable under the shipped greedy path, and the exact mechanism requires a
dependency change. Reach therefore keeps its existing dependency, product
code, installed daemon, wire dialect v0, public API, persistence and CA
material unchanged. The three upstream fixes are clean local commits only;
at the founder's direction they are neither pushed nor filed while another
`mlx-swift-lm` PR is pending. Typed numeric completion returns to Held as
architectural hardening and as a prerequisite for any future sampled path,
not as a claimed defect fixed in the current product.

**Later status:** the structural-test commit became PR #527 on 11 August and
merged as `ef0b0cc9` on 17 August after lint and macOS build/test passed; the
signed-range prototype was retired unfiled after the upstream/vendor review;
the finite-double prototype remains parked. The paragraph above records the
S19 stop-time state rather than the current publication queue.

## S18 — typed numerics closed the overflow hole, not the completion cliff (2026-08-08)

**Question and boundary.** The founder reopened sampling for one narrower
mechanism: add decoder-compatible numeric grammar semantics, then rerun the
exact S16 matrix without widening the S14 completion bias, adding a parser, or
repairing output after generation. Any grammar, decode, or budget failure
still stopped the pass.

The isolated dependency prototype repaired the pinned converter's exact
`Int64.min` negation and generated a Reach-opt-in finite IEEE-754 `Double`
grammar. Four focused dependency tests passed in 0.722 s: both signed integer
boundaries decoded, adjacent overflows and a 100-digit integer were rejected,
ordinary decimal and scientific forms remained available, and Foundation's
underflow/overflow cases (`2e-324`, `1e309`, and a value above the finite
maximum) were rejected. Upstream xgrammar's ordinary unbounded `number`
semantics remained unchanged. Reach's scratch schema normalization and
sampling resolver then passed 7/7 and 5/5 focused tests respectively,
including nested objects, arrays, optionals, `$defs`, explicit-bound
precedence, default `0.6`, greedy precedence, top-k/top-p boundaries, and seed
forwarding.

The real-weight gate used the preserved S16 harness against cached
`gemma-4-e2b`. The exact S17 `topP(1, seed: 29)` reproducer now completed and
decoded:

```json
{"count":1234567890123456789,"name":"Alpha"}
```

The former hundreds-digit overflow was therefore closed. All 12 temperature
`0.2` cases, all 12 default-`0.6` cases, and all four first-run temperature
`1.0` cases accepted and decoded. The next case — temperature `1.0`, run 2,
the exact adversarial nested pattern/range/fixed-array schema — then returned
`the cluster could not finish the constrained response within its 512-token
limit`. The 28 accepted matrix cases took 0.51–5.23 s after prewarm. An earlier
diagnostic attempt had also ended with a typed-decode error before raw-output
instrumentation; the instrumented rerun was commissioned only to attribute
the stop and was not repeated after the independent budget failure fired it.

**Verdict: STOP.** Type-safe numeric grammars are a valid, bounded mechanism:
they solve S17's grammar-accepted `Int` overflow without a post-generation
parser or arbitrary digit cap. They do not solve S15's independent fact that
probabilistic choices can consume the budget before the grammar completes.
The required S16 matrix was 28/36, not 36/36, so neither the sampler resolver
nor the numeric dependency prototype returns to the product. The installed
greedy daemon, wire dialect v0, public interfaces, CA material, and pushed
dependency state were untouched. The sampler commits and numeric prototype
remain unpublished scratch evidence; no upstream PR was opened.

## S17 — grammar acceptance is not typed acceptance (2026-08-08)

**Question and stop.** S16 proved the hybrid policy against the exact retained
four-shape matrix. Product acceptance then exercised `.allowed`, `.required`
and schema-plus-tools through the installed release. The plan's unchanged kill
criterion still applied: any attributable grammar, decoding or budget failure
stops the pass. It did.

The first canonical installed selftest reached the default-`0.6`
schema-plus-tools arm and returned `Failed to parse generated content.` A
separate `.allowed` run once selected prose rather than a tool; that is valid
allowed-mode model routing and is not the stop. To isolate the decode failure,
the same two-field response schema was run directly with the categorical
sampler, `topP(1)` and explicit seeds. Seeds 1–28 accepted and decoded (mostly
with `count` 0; seed 28 produced 1). Seed 29 accepted this JSON shape:

```json
{"count":1000000000…<hundreds of additional digits>…,"name":""}
```

The JSON is structurally valid and the grammar accepted it, but its positive
integer is outside Swift `Int`; constructing the requested `@Generable` value
failed with `Failed to parse generated content.` This was not a Metal, model
load, Keychain, wire, cancellation, budget or harness fault. It is an
attributable decoding failure produced by the candidate sampling path while
the S14 grammar, bias table, reserve formulas and token budget remained
unchanged.

**Verdict: STOP.** S16 was a valid but insufficient matrix result. The local
dependency hook and Reach sampling resolver were removed, the upstream and
backport branches remain unpublished scratch evidence, and constrained paths
remain deliberately greedy. No wider completion bias, numeric parser or JSON
repair was added. The signed Simulator probe was canceled before install or
launch because continuing after this kill would test a design the product no
longer contains.

## S16 — sample while there is headroom, complete deterministically (2026-08-08)

**Ruling.** S15 established that probabilistic choice inside the hard zone can
legally avoid structural exits until the budget ends. The authorized follow-up
therefore changed one thing: the request sampler chooses grammar-legal tokens
in the normal and soft zones, while the existing hard-completion zone uses
argmax. S14's grammar, 512-token budget, reserve formulas, closing table and
whitespace policy remained byte-for-byte unchanged. No parser, backtracking,
buffered retraction or wider bias was added.

The isolated dependency hook counted requested-sampler decisions, hard-zone
argmax decisions, unconditional-splice selections and xgrammar fast-forward
tokens. The release harness built in **83.62 s**, prewarmed the cached
`gemma-4-e2b`, and ran the exact S15 four-shape matrix. Every row below is three
ordered runs; `chosen` is requested sampler / hard argmax / total generated
tokens, and seconds are complete accepted-and-decoded wall times.

| Temperature | Shape | Chosen tokens, runs 1/2/3 | Seconds, runs 1/2/3 |
| --- | --- | --- | --- |
| 0.2 | adversarial | `13/129/159`, `13/148/178`, `13/129/159` | `3.847`, `1.977`, `1.746` |
| 0.2 | negative integer | `28/0/30`, `28/0/30`, `29/0/31` | `0.487`, `0.370`, `0.383` |
| 0.2 | decimal + integer | `16/0/17`, `19/0/20`, `19/0/20` | `0.218`, `0.254`, `0.256` |
| 0.2 | nested numerics | `42/0/47`, `62/0/67`, `44/0/49` | `0.532`, `0.766`, `0.547` |
| default 0.6 | adversarial | `13/129/159`, `13/148/178`, `13/129/159` | `1.754`, `1.968`, `1.746` |
| default 0.6 | negative integer | `22/0/24`, `18/0/20`, `28/0/30` | `0.296`, `0.251`, `0.370` |
| default 0.6 | decimal + integer | `16/0/17`, `19/0/20`, `19/0/20` | `0.214`, `0.255`, `0.251` |
| default 0.6 | nested numerics | `44/0/49`, `44/0/49`, `39/0/44` | `0.547`, `0.549`, `0.489` |
| 1.0 | adversarial | `14/156/187`, `13/148/178`, `13/148/178` | `2.104`, `1.986`, `1.977` |
| 1.0 | negative integer | `20/0/22`, `17/0/19`, `17/0/19` | `0.275`, `0.237`, `0.240` |
| 1.0 | decimal + integer | `16/0/17`, `16/0/17`, `19/0/20` | `0.223`, `0.215`, `0.251` |
| 1.0 | nested numerics | `40/0/45`, `58/0/63`, `38/0/43` | `0.511`, `0.713`, `0.476` |

The grammar fast-forwarded 18 adversarial tokens, 3 negative-integer tokens,
2 decimal/integer tokens and 6 nested tokens in every run; unconditional
splice selections were zero. Reserves were stable by shape: soft/hard
`186/496`, `128/56`, `128/72` and `128/168`. The adversarial hard reserve
therefore begins with 16 tokens of nominal headroom, and the instrumentation
proved the policy did not disguise an all-greedy run: 13–14 actual choices used
the requested sampler before deterministic completion.

**Verdict: PASS 36/36.** All outputs reached grammar acceptance and decoded.
Every adversarial result retained two alternatives, three checkpoints per
leaf, exact count 73 and codes `AB-1234`, `CD-5678`, `EF-9012`; its free audit
note varied among `Audit Complete`, `Audit Report`, and a longer sentence.
The fixed decimal/integer result remained `5` and `0.5`. Legal sampled
variation was observable rather than inferred: negative labels varied, and at
temperature 1.0 the nested run produced alternatives including scores
`-0.75333333333333334`, `1.92`, and `-9.2` while still decoding.

This overturned only S15's proposed *full-path* sampling design, not its
evidence. It licensed a product candidate: sample where choice is generative,
then complete the already-defined hard zone deterministically. S17 subsequently
showed that the four retained shapes did not cover typed numeric range: a
grammar-accepted sampled integer overflowed Swift `Int`. S16 therefore remains
useful mechanism evidence, but no longer licenses a fork pin or product ship.

## S15 — constrained greed is measured necessity (2026-08-08)

**Question and kill.** Would S14's unchanged completion policy remain safe if
the grammar masked first and the ordinary MLX sampler then selected among legal
tokens? The pre-ruled matrix was the exact S14 adversarial, negative-integer,
decimal-plus-integer and nested-numeric shapes, three runs each at temperature
`0.2`, the unset provider default `0.6`, and `1.0`. Any attributable grammar,
decode or budget failure stopped the pass; widening the bias table or adding a
parser was forbidden.

**Prototype boundary.** Nothing in Reach's tracked tree or installed daemon was
changed. Isolated release sources based on Reach `0d5e9fc` and pinned
`mlx-swift-lm` `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8` added one
source-compatible dependency hook:

- `GuidedGenerationLoop.run` accepted a defaulted `LogitSampler`, retaining
  `ArgMaxSampler` as its old behavior;
- grammar mask and S14's exact closing/whitespace biases were applied before
  `sampler.sample(logits:)`;
- the candidate constrained path passed the request's ordinary
  `GenerateParameters.sampler()`; no completion score, reserve, schema or
  prompt changed.

That combination built successfully in release in **90.62 s** and prewarmed
cached `gemma-4-e2b`. The spike used no Keychain, wire session, phone or
Simulator, so the result isolates guided token selection.

**Verdict: STOP on attempt 5.** Temperature `0.2` run 1 passed all four shapes:

| Shape | Complete | Time | Accepted JSON |
| --- | ---: | ---: | --- |
| adversarial nested pattern/range/fixed arrays | yes | 3.601 s | primary plus two alternatives; every code matched `^[A-Z]{2}-[0-9]{4}$`, every count was 73 and every checkpoint array had three integers |
| negative bounded integer | yes | 0.360 s | `{"label":"-73","offset":-73}` |
| decimal plus following integer | yes | 0.241 s | `{"count":5,"ratio":0.500000}` |
| two nested integer/decimal objects | yes | 0.429 s | `{"first":{"count":-5,"score":0.75},"second":{"count":-12,"score":9.2}}` |

The accepted adversarial bytes were:

```json
{
  "auditNote": "This is a complete audit based on the,","payload"
  : {"alternatives" : [
    {"checkpoints" : [
      1,
      2,
      3],"code" :"AZ-0001","count" :73},
    {"checkpoints" : [
      4,
      5,
      6],"code" :"BC-0002","count" :73}],"primary" : {"checkpoints" : [
      7,
      8,
      9],"code" :"CD-0003","count" :73}}}
```

The next attempt — temperature `0.2`, adversarial run 2 — stayed within the
grammar but did not accept before the same 512-token ceiling. It returned the
exact product error:

```
the cluster could not finish the constrained response within its 512-token limit
```

This is the planned model-path failure, not an infrastructure fault. The
remaining 31 candidate runs, including default `0.6` and `1.0`, were therefore
not run: continuing after the first kill would turn a stopping rule into a
scorecard.

**What this ruled at the gate.** S14's table is sufficient under greedy argmax
but is not a general completion guarantee under sampling, even at temperature
`0.2`. The candidate sampler hook, shared resolver and fork pin therefore did
not proceed under S15's full-path design. S16 later supplied the required new
founder ruling over a different completion design — sampled normal/soft zones
and deterministic hard completion — without widening this table or adding a
parser; its separate result above supersedes the temporary all-greedy product
decision while preserving this stop as evidence.

## S13 — constrained calls have a greedy adversarial cliff (2026-08-08)

**Question and kill.** Can the pinned engine compose a model-format-neutral
strict JSON tool envelope with the existing parser, repair candidate arguments
without leaking the originals, and force `.required` across simple, nested,
enum, fixed-array, optional, multi-tool and adversarial schemas? The locked
criterion was explicit: if constrained replay itself failed, record S13 and
stop rather than ship a partial argument guarantee.

**Verdict: STOP.** Tier 1 and Tier 2 were not implemented. The ordinary
breaking shapes established the function gap and showed that replay can close
it, but the adversarial replay failed **3/3** at the existing 512-token default.
Every failure remained inside the grammar, greedily extending a legal integer
until the budget ended, and returned the exact existing product error `the
cluster could not finish the constrained response within its 512-token limit`.
No unconstrained fallback or tool execution occurred.

### Pinned source and test surface

- Revision `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8` confirms that
  `MLXLMCommon.ToolCallProcessor` streams ordinary prose incrementally but
  exposes a tool call only after its full native span has parsed. There is no
  safe incremental argument surface, so Tier 3 remains an evidenced seam.
- The pinned adapter already implements generic required calls with an
  xgrammar structural tag and a strict JSON `{name, arguments}` envelope. A
  real `mlx-community/gemma-4-e2b-it-4bit` characterization terminated its
  grammar, parsed `set_flashlight`, and completed 24 generated tokens in
  **595 ms**. Its final buffer was valid JSON and selected the offered tool.
- The dependency's own `ToolCallingSchemaTests` passed **11/12** from a clean
  `/private/tmp` scratch build. The sole failure is a stale
  builder/assertion mismatch at `ToolCallingSchemaTests.swift:280`: the test
  expects `elements[0].content.json_schema`, while the current builder makes
  `content` the per-tool `or`. The workspace build first hit attributable
  Finder/resource-fork codesigning metadata; the scratch rerun removed that
  harness fault.

### Real Reach/Gemma comparison

The pre-change Reach path ran against cached
`mlx-community/gemma-4-E2B-it-qat-4bit`. Each allowed candidate was observed
whole from today's native parser, then replayed as response JSON under the
same deterministic grammar engine and the candidate tool's schema. Prompt
schema inclusion was disabled. Times below are wall-clock ranges over three
runs; allowed "complete" is completed-call delivery because no raw argument
fragment exists.

| Shape | Unconstrained valid | Constrained replay valid | Allowed complete | Replay first accepted delta | Replay complete |
| --- | ---: | ---: | ---: | ---: | ---: |
| simple | 3/3 | 3/3 | 403–412 ms | 370–1,011 ms | 733–1,363 ms |
| nested `$defs` | **0/3** | **3/3** | 673–745 ms | 63–72 ms | 952–1,048 ms |
| enum | 3/3 | 3/3 | 346–365 ms | 59–69 ms | 330–352 ms |
| fixed array | **0/3** | **3/3** | 385–481 ms | 59–77 ms | 514–763 ms |
| optional | 3/3 | 3/3 | 336–366 ms | 363–372 ms | 594–623 ms |
| two offered tools | 3/3 | 3/3 | 403–413 ms | 361–372 ms | 715–733 ms |
| adversarial nested pattern/range/arrays | **0/3** | **0/3** | 791–848 ms | 382–408 ms | 20.43–21.06 s, then budget error |

The nested baseline encoded `destination` as a string rather than its object
**3/3**. The fixed-array baseline emitted malformed shapes such as
`{"values":"[3"}` or a spurious `properties` string **3/3**. Replay repaired
both to schema-valid JSON **3/3**, so either is a genuine future Simulator
comparison discovered in S13 rather than invented afterward.

The adversarial schema nested `$defs`, a regex-constrained code, an exact
integer range, and fixed arrays. Its deliberately conflicting candidate was
invalid **3/3**. Replay began correctly but greedy sampling entered the first
integer array and emitted one unbounded integer for the remainder of the
budget **3/3**. This is a fidelity failure within the allowed grammar, not a
schema-compile failure, and it is why legality alone cannot support the
pass's promised every-call guarantee.

### Grammar construction measurements

With the real QAT Gemma tokenizer, warm model load was **5,020 ms** and the
one-time grammar tokenizer build was **625 ms**. Bare, model-neutral structural
grammars compiled in **301 ms** simple, **6 ms** nested, **3 ms** enum,
**4 ms** fixed array, **308 ms** optional, **301 ms** second tool, and
**312 ms** adversarial. The seven-tool combined source was 3,232 bytes and
compiled in **417 ms**; a repeated fresh compile took **413 ms**.
`GrammarConstraint.clone()` failed immediately with
`forkFailed("xg_matcher_fork: Fork() not available in xgrammar v0.1.30")`, so
the repeated cost is the required isolation fallback rather than a cache hit.

**What this rules.** The model-neutral envelope and generic required path are
technically viable, and Tier 3 is unavailable on the pinned processor, but
Tier 1's universal guarantee is not viable with the present greedy guided
loop. Per the founder-approved stop condition, Reach's implementation,
`docs/wire.md`, public interfaces, installed daemon and dialect v0 remain
unchanged; `PLAN-toolargs.md` stays live for a future re-ruling rather than
retiring.

## S14 — numbers needed an exit, not a parser (2026-08-08)

**Question and bounded ruling.** S13 proved the adversarial output stayed
inside xgrammar yet never finished an integer. The founder authorized one
narrow experiment before any wider implementation: stop classifying digits as
JSON-closing tokens, classify comma as the separator that ends a scalar, and
rerun the exact failed schema plus negative, decimal and nested-number
controls. Only if that failed could the work widen to a bounded schema/state
machine; no general parsing table was authorized or built.

**Cause.** The pinned `GuidedGenerationLoop` enters a hard completion zone by
penalizing every token except the closing-bias set, then takes greedy argmax.
That set contained every single digit but not comma. Xgrammar's integer rule
was already correct — `("0" | "-"? [1-9] [0-9]*)` — so after the first digit
both another digit and the field separator were legal, but policy rewarded the
digit and suppressed the exit forever. A digit is scalar content; comma is the
structural exit.

**Result: PASS, 12/12.** Reach retained the pinned dependency and supplied the
correct model-wide completion bias locally: EOS remains tier 1; quote, right
brace, right bracket and comma are tier 2; digits receive no closing reward.
The grammar mask still forces a first digit when one is required.

| Shape | Result | Complete time over 3 runs |
| --- | ---: | ---: |
| exact S13 adversarial nested pattern/range/fixed arrays | **3/3** | 5.25–7.07 s |
| negative bounded integer | **3/3** | 0.41–0.52 s |
| decimal plus following integer | **3/3** | 0.55–0.57 s |
| two nested integer/decimal objects | **3/3** | 1.77–1.84 s |

Every output reached grammar acceptance and decoded through its requested
`@Generable` type. The adversarial outputs satisfied the exact integer 73,
regex codes and all three fixed-array counts. No fallback, schema rewrite or
state machine ran.

**Implementation confirmation.** After the S14 gate passed, the permanent
Gemma E2B self-test offered two tools and exercised the S13 breaking shape.
Private `.allowed` proposal/replay passed **3/3** in 5.37–6.49 s; generic
`.required` dispatch passed **3/3** in 5.24–5.33 s; schema-plus-tools selected
a constrained response **3/3**; and a one-token required budget returned the
legible constrained-generation error **1/1**. A separate mTLS loopback carried
two repeated calls as two whole, ordered events. Tier 3 remains out for the
unchanged S13 reason: the pinned native processor exposes only completed calls.

## S11 — the framework refused the missing capability (2026-08-08)

Measured before changing the model capability or daemon, with real
`gemma-4-e4b` weights and the same loopback spine as the tool-call spike. Six
`@Generable` shapes — two fields, nesting, enum, fixed-length array, optional,
and an adversarial prose-vs-JSON ask — each ran three times with
`includeSchemaInPrompt` both `true` and `false`.

- All **36/36** attempts stopped in FoundationModels with the exact sentence
  `The selected model does not support guided generation. Consider trying
  again with a different model.`
- The executor was never invoked. Consequently no transcript, transmitted
  schema, stream, or final decode existed to compare; prompt-schema inclusion
  made no difference.
- The cause was `ReachLanguageModel.capabilities` declaring only
  `.toolCalling`. The prior behavior was therefore a **function gap**, not a
  sampling-fidelity gap disguised by prompt coaching.

This is the retained before-state. Declaring `.guidedGeneration` is valid only
with a working constrained path behind it, which is why capability and engine
support land in the same change.

## S12 — the pinned grammar engine's real surface (2026-08-08)

Measured in release configuration against the repository's exact
`mlx-swift-lm` checkout `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8`,
using the checked-out source and executable-layout metallibs. The engine takes
JSON Schema directly, constructs its own grammar tokenizer from the model
vocabulary, computes an allowed-token mask each step, supports fast-forwarded
forced text, and accepts deltas while its matcher advances.

- Model load was **3,481.70 ms**, including a first Metal warm-up of
  **1,495.17 ms**. Vocabulary extraction was **70.16 ms** and the one-time
  grammar-tokenizer build **91.78 ms** for 262,144 tokens.
- First compilation was **14.53 ms** for two fields, **14.15 ms** nested,
  **0.34 ms** enum, **0.36 ms** fixed array and **13.83 ms** optional. The
  larger adversarial benchmark compiled in **119.98 ms**.
- `GrammarConstraint.clone()` itself returned in **0.002–0.004 ms**, but the
  pinned xgrammar then failed exactly with
  `forkFailed("xg_matcher_fork: Fork() not available in xgrammar v0.1.30")`.
  Fresh compilation is therefore the honest per-request isolation path:
  **13.3–13.6 ms** for the exact two-field FoundationModels schema and
  **120.12–134.76 ms** for the adversarial benchmark.
- The exact two-field schema reached its first accepted delta in
  **38.94 / 30.35 / 30.32 ms** over three warm runs and completed 19 tokens in
  **216–226 ms** (**84–87.7 tok/s**). The adversarial benchmark reached its
  first delta in **95.71 / 31.80 / 32.41 ms** and completed 31 tokens in
  **510.44 / 387.40 / 382.50 ms** (**60.73–81.05 tok/s**).

The warmed first-token addition is safely below the one-second re-ruling gate.
The implementation therefore keeps one model grammar tokenizer and bias set,
keys compiled templates by deterministic schema JSON, asks for a fresh clone,
and recompiles when this pinned fork is unavailable. It also retains the
adapter's completion reserve, hard reserve, closing bias and whitespace bias.
The current guided loop chooses the highest permitted token, so sampling-mode
fidelity remains a separate seam even though schema conformance is now exact.

## S10 — what an old peer actually survives (2026-08-08)

Measured before the negotiation implementation in the loopback rig, three
times per case:

- An existing frame with an unknown optional JSON key decoded successfully
  **3/3**. This is the additive-field tool.
- Unknown frame type byte 255 failed **3/3** with the exact error `frame type
  255 is not in this protocol version's vocabulary`. A new type is therefore
  never additive by itself.
- An authenticated client offering `reach/255` to a `reach/0` listener failed
  **3/3** as `could not open a connection to the cluster: stream open timeout`.
- An enrollment client offering `reach-enroll/255` to a `reach-enroll/0`
  listener failed **3/3** with the same timeout.

The last two are the retained before-state: ALPN remains the hard boundary for
an envelope change, but dialect incompatibility now reaches the stable
generation-0 envelope and returns a directional `wire-version` frame before
creating a session, consuming a device token, or parking an app request.

## S6 — the framework runs the tool and comes back (2026-08-05)

Three probes in a plain CLI process: a real `LanguageModelSession`, a real
`Tool`, a local executor, no wire and no weights.

- **The transcript loop is not a preference, it is the only shape the API
  admits.** `LanguageModelExecutorGenerationChannel` is send-only from the
  executor's side — there is no path by which one `respond` call receives tool
  output. The session runs the tool in-process and **re-invokes** the executor
  with the transcript extended by `.toolCalls` and `.toolOutput`. Observed:
  `instructions | prompt | toolCalls | toolOutput | response`.
- **`capabilities` is a framework-enforced gate.** A model declaring
  `LanguageModelCapabilities([])` handed a tool-bearing session does not
  silently ignore the tools: the framework throws
  `LanguageModelError.unsupportedCapability` and `respond` is **never called**.
  So declaring `.toolCalling` is what makes tools reachable, and it must land
  with working support rather than ahead of it.
- **`GenerationSchema` encodes to JSON Schema** — `type`, `properties`,
  `required`, `title`, `additionalProperties`, `x-order` — and survives a
  `Codable` round trip byte-identically. A tool spec is therefore one
  `JSONEncoder` away, which is exactly how Apple's own adapter builds it.
- A `toolOutput` carries the **call's** id, not the id of the `toolCalls` entry
  holding it.

## S7 — the slot model calls tools (2026-08-05)

Measured through `reachd selftest --mlx --tools`, which is where it can run:
MLX's metallib is only locatable in an executable layout, so `swift test` from
a terminal cannot load it at all.

**`gemma-4-e4b`, 5 runs: 5/5 called the tool**, every run choosing
`Europe/Vienna` for "What time is it in Vienna?", ~0.85 s per full two-turn
round trip warm. The demonstration model does not have to change.

Two facts that shaped the daemon more than the emission rate did:

- **MLX already parses the call.** `MLXLMCommon.ToolCallProcessor`, configured
  from the model's `model_type`, swallows the `<|tool_call>…<tool_call|>` span
  out of the chunk stream and yields a parsed `Generation.toolCall`. The markers
  never reach the daemon, so there is no scanning to do — the case that dropped
  it was a `default: break`.
- **Gemma's call grammar has no escape mechanism.** Its only string delimiter is
  the special token `<|"|>`, and a `}`, `,` or `<|"|>` inside a string value is
  emitted verbatim and is unrecoverable by any parser. That, not convenience, is
  why arguments cross whole.

## S4 — the provider slot is real (2026-07-21)

A third-party `LanguageModel`/`LanguageModelExecutor` conformance streams
through a real `LanguageModelSession` in a plain CLI process: the framework
instantiates the executor via `init(configuration:)`, calls
`respond(to:model:streamingInto:)`, and factory-constructed channel events
surface as `streamResponse` snapshots. No entitlements involved. An
in-process rehearsal of the whole spine — session → executor →
transcript-to-chat mapping → MLX generation (`MLXLMCommon.generate`) →
factory events — streams real tokens, multi-turn included.

Rulings this confirms or forces:

- **Channel `Event`/`Action` payloads are construct-only** on the public
  surface (verified by API grep and runtime Mirror dump: payloads live in
  private storage with no read path). The daemon therefore speaks Reach's
  own wire-event vocabulary natively and never serializes framework Events;
  only the client-side executor constructs them.
- ~~**The announced off-the-shelf `MLXLanguageModel` provider does not ship
  in tagged `mlx-swift-lm`**~~ (checked 3.31.4). **Stale as of 2026-08-05:**
  the repo pins a *revision past that tag* (`83f3ef6dc5bc`, for Gemma 4), and
  that revision carries a whole `MLXFoundationModels` library — a public
  `MLXLanguageModel` and `.Executor`, plus `TranscriptConverter`,
  `SchemaConverter`, `SamplingModeMapper` and `ToolCallingConversions`. It has
  been in the tree the daemon builds against since before the take was shot.
  Every helper is internal, so none of it can be imported, and the adapter is
  an *in-process* FM model where reachd is a wire server — so driving
  `MLXLMCommon` directly behind the slot remains the primary path. Its value is
  as a reference implementation, and it settled two questions for the tool pass.
  **This does NOT trigger the roadmap's FM-core tripwire:** FoundationModels
  itself is still a closed system framework read through a `.swiftinterface`,
  and `GenerationOptions`/`Transcript.ToolDefinition` are still not natively
  `Codable`, so `Mirrors.swift` does not retire.
- First streamed token ~2.1 s after container load (gemma-3-1b-qat-4bit on
  an M5 Pro); warm-cache model load a few seconds, cold download ~95 s.
- Build notes that will bite later if forgotten: the Metal Toolchain is a
  separate Xcode component (`xcodebuild -downloadComponent MetalToolchain`);
  `#huggingFaceLoadModelContainer` requires importing `MLXHuggingFace`,
  `HuggingFace`, and `Tokenizers` (packages: swift-huggingface,
  swift-transformers); `MLXLMCommon` declares its own `LanguageModel`
  protocol, so FoundationModels conformances must be written qualified
  (`FoundationModels.LanguageModel`); `UserInput`/`Chat.Message` are not
  Sendable and must be constructed inside `ModelContainer.perform`.

## S1a — mutual TLS over QUIC holds (2026-07-21)

QUIC between a listener and client on loopback, server identity and client
identity both issued by a throwaway CA: handshake completes, a
bidirectional stream round-trips data, and a cert-less client is refused at
the data plane (stream reset; the tunnel never serves). `ALPN` negotiated;
`sec_protocol_options_set_peer_authentication_required` is enforced.

Transport rulings for the spine:

- **Servers must accept QUIC via `newConnectionGroupHandler`** and take
  streams from `group.newConnectionHandler`; a bare
  `listener.newConnectionHandler` yields stream-connections that stall in
  `.preparing`.
- **Verify blocks need the role-correct SSL policy**: the default policy
  checks `serverAuth` EKU, which wrongly rejects client certificates on the
  server side — set `SecPolicyCreateSSL(false, nil)` when verifying
  clients, then pin anchors to the cluster CA with
  `SecTrustSetAnchorCertificates` + `SecTrustSetAnchorCertificatesOnly`.
- **TLS 1.3 clients reach `.ready` before the server's verdict lands** —
  negative tests (and any client-side "am I in?" logic) must probe the data
  plane, not trust `.ready`.

## S1b — re-attach is the transition (2026-07-21 partial, ruled 2026-07-22)

On an iPhone 17 Pro Max (iOS 27) streaming a long generation from the Mac
over the studio LAN: Wi-Fi switched off mid-stream for ~5 s, then back on.
The visible stream froze, the daemon kept generating inside its residency
window, the client's reconnect loop re-attached when the path returned,
replayed from its last received sequence, and the generation — 2,272
characters — completed intact.

**Scoping, stated rather than discovered:** the migration-vs-re-attach
question for a true Wi-Fi → cellular transition cannot be answered before
the mesh exists, by construction — on cellular there is no route to the
daemon's LAN address, so there is nothing for a QUIC connection to migrate
*to*. Constant addressing across paths is precisely what the WireGuard
mesh provides; the final S1b ruling (and any use of `.handover`
multipath) lands with S2 and the away leg, tested against the mesh IP.
Until then, session-layer re-attach is not just the guaranteed path — it
is the only well-defined one, and it is verified.

### The ruling (2026-07-22) — the away leg answered it by construction

The away leg ran in-building against a travel router we govern: the phone
streaming a generation on our own SSID, then hopping mid-stream to the
building's, so the daemon's LAN address went unroutable exactly as it does
at the door. The session froze for seconds, fell to the mesh address
through the router's WAN port map, and completed; the tunnel's counters
moved with it (47 KiB in, 78 KiB out), so the generation itself rode
WireGuard rather than merely handshaking over it.

**Migration is not the transition, and cannot be.** QUIC migration
preserves the *destination* address and changes only the client's local
path — but the walk-out is precisely the event that makes the destination
unroutable. There is nothing to migrate *to*. Re-attaching at the mesh
address **is** the transition, and it is the only form the transition can
take. The corollary is the good news: once a session rides 10.86.0.1,
WireGuard's own endpoint roaming absorbs every later path change beneath
QUIC, which never sees them — an on-mesh session is path-agnostic by
construction. `.handover` multipath is therefore off everywhere, and the
planned A/B against it is deleted rather than deferred: it would compare a
working mechanism against an inapplicable one.

What made the fall possible is a wire change, not a transport trick. The
daemon's `HelloAck` now declares every address it answers on, the mesh
address among them, over the already-authenticated control stream — so the
list is exactly as trusted as the session carrying it, and trusting it adds
nothing mutual TLS had not already granted. The client keeps those
addresses as dial candidates; on path death or path change it races all of
them and keeps whichever connects first. An `NWPathMonitor` cancels the
live stream the moment the path moves, so the re-dial starts in
milliseconds instead of at the 30 s idle timeout, and `QUICStream.open`
honors cancellation so the race's losers die promptly. A session that began
over Bonjour discovery on the LAN ends up on the mesh without the app ever
having been told either address exists.

The first attempt failed informatively and is worth recording: WireGuard
ingress was already proven — a handshake and 680 bytes arrived through the
port map — but the *session* never followed, because the client dialed the
cluster by its Bonjour service name, which resolves to nothing on a foreign
network. Reachability was never the missing piece; knowing where else to
knock was.

## S2 — the entitlement gate, refused then granted; the embedded tunnel holds (2026-07-22)

**Final verdict: PASS.** The kill fired first and honestly — see below — and
was reversed the same day when the developer account was upgraded to the
paid program. On retry the profiles minted for both bundle ids with the
packet-tunnel entitlement, the go bridge built, and the whole away-leg
data path ran end to end: WireGuardKit inside the extension, handshake
within seconds of Start, and a mutually-authenticated QUIC session
streaming a generation to the daemon's mesh address (10.86.0.1) — ~8 KiB
each way on the interface counters for one session. The official-app
fallback below remains recorded as the exercised de-risk path.

Build frictions worth remembering (all patched in a local checkout at
`~/Library/Caches/reach-vendor/wireguard-apple`; follow-up: push the
two-line fork under the studio account and repoint the project):
wireguard-apple's manifest declares platform constants its own
swift-tools-version (5.3) never had — bump to 5.9; WireGuardKitC.h uses
BSD types without `<sys/types.h>` under the 27 SDK's strict modules; the
wg-quick parser is app code, not part of WireGuardKit — two MIT-licensed
files ride along in the PacketTunnel target; and the go-bridge script
phase must point at the local package path, with Homebrew's go on PATH.

### The kill, as it first fired

The Keeper shell and its packet-tunnel extension built against WireGuardKit
hit the kill criterion at the first gate, precisely and informatively:
*"Personal development teams, including 'Cassandra Spiral', do not support
the Network Extensions capability."* The only team Xcode holds an account
for is a personal one; the packet-tunnel entitlement is not grantable on
it. (WireGuardKit's package build is unverified for the same reason —
signing blocks before compilation.)

Per the plan's pre-authorized demotion, **the official WireGuard app is
now the away-leg path**: the keys are still ours and real, the phone's
wg-quick config travels by QR, and the tunnel's consent dialog is still
the system's own. The proto-keeper app and extension remain in-tree,
buildable the day a paid team exists — the seam is the ceremony's
provisioning target (embedded adapter vs. exported config), nothing in
the wire or the daemon changes. The beat sheet's "no third-party app in
the demo's frame" is honestly weakened to "one open-source app in the
frame" until the account upgrade; the restated milestone at filing prices
the embedded path where it always was, in funded scope.

## S3 — headscale supervises cleanly (2026-07-21)

headscale v0.29.2 (official darwin_arm64 release binary) launched as a
subprocess with a generated config: socket up in under a second, user
created, **pre-auth key minted programmatically**, nodes listed — the whole
sequence scripted end to end in 0.8 s with no interaction. Config
requirements on 0.29.x: explicit `dns.override_local_dns: false` +
`nameservers.global: []` when MagicDNS is off; a non-empty DERP map even
with the embedded DERP server disabled (a STUN-only local region file
satisfies it); a short `unix_socket` path (macOS caps unix socket paths at
~104 chars — Application Support paths are too long);
`preauthkeys create --user` takes the numeric user ID.

Per the mesh ruling, S3's outcome affects only the fallback control-plane
path (official Tailscale client + pre-auth key) and the funded multi-device
ledger; the demo's primary away path is a static WireGuard peer provisioned
through the ceremony.

## S5 — a road the user already owns (2026-07-24, code side)

**The question.** Reach ships a mesh so that a civilian always has a road.
But many people already run one — a tailnet, most commonly — and the
honest test of the architecture is whether Reach can *use* theirs without
being taught about it. Concretely: with Tailscale carrying the phone (iOS
grants exactly one VPN slot, so the Reach tunnel is down) and the Mac on
the same tailnet, does a session that began on the LAN survive the hop by
falling to the Mac's 100.x address?

**Verdict: yes, by construction. No code lands.** Three existing pieces
compose into the answer, none of which were written with tailnets in mind:

- `LocalAddresses.ipv4()` enumerates every `AF_INET` interface the host
  holds and filters nothing but a duplicate loopback. Tunnel interfaces are
  interfaces: the mesh's own 10.86.0.1 appears there today, which is why
  the away leg works at all, and a tailnet's 100.x appears the same way the
  moment it is up.
- `HelloAck` carries that list, and the hub turns each address into a dial
  candidate; the race dials them all and keeps the first that connects.
  Nothing ranks or prefers — the race is the arbiter.
- The verify block pins the cluster's CA with a nil host, so *any* address
  presenting the cluster's chain **is** the cluster. A certificate issued
  for LAN addresses authenticates a mesh dial, and would authenticate a
  tailnet dial identically.

So the pre-authorized escape hatch — a trivial interface-inclusion
predicate, which would also have governed which addresses the server
certificate honestly claims — is not needed and is not written. Systematic
VPN interop stays where it was scoped: M3.

**Boundaries, stated rather than discovered.**

- Candidates are learned when a session opens. A road that appears
  *mid-session* is picked up at the next session open, not retroactively.
- A cold start away from home has no learned candidates at all: discovery
  is mDNS, which does not cross a foreign network, and nothing is persisted
  between launches. The demo's shape — a session begun at home, walked out
  of the door — never meets this, but a shipped product would; candidate
  persistence is named M3 work, not a defect discovered late.
- Loopback is declared to every peer and is meaningless to all of them
  except a client on the same host (a simulator, where it is exactly right).
  Off-box it is refused immediately and costs one failed dial in a race
  that was already parallel.

### Confirmed on hardware the same day (2026-07-24)

Tailscale was brought up on the Mac (split-tunnel, no exit node) and the
daemon restarted. It announced itself without being asked to:

    [reachd] Reach Cluster serving gemma-3-1b on :47337
             (127.0.0.1, 192.168.8.104, 10.86.0.1, 100.66.143.31)

— loopback, LAN, first-party mesh, and tailnet, in one list, from one
`getifaddrs` walk that knows nothing about any of those categories.

On the phone, enabling Tailscale takes the single iOS VPN slot and drops
the Reach tunnel, which is what makes the test honest: the first-party
mesh is *unavailable*, so only the tailnet can carry. A generation was
started on the LAN and the phone was moved to a foreign network
mid-stream. It completed.

Which road carried it, evidenced both ways. Positively: the tailnet peer
showed `active; relay "sfo", tx 299660 rx 79460` — 293 KiB pushed from the
Mac, the size of the generation. Negatively: the WireGuard peer's last
handshake was 4 m 36 s old, and WireGuard rekeys every 120 s whenever it
has anything to send, so a handshake that stale is proof the mesh sat idle
straight through the run.

The relay is worth dwelling on. The Mac sits behind a travel router,
behind a building router, behind a router-level VPN; direct traversal
failed and Tailscale fell back to its own DERP relay in San Francisco.
Reach neither knew nor cared. It dialed 100.66.143.31 because that address
had been declared over an authenticated control stream, and the road
worked out how to be a road. Reach ships no relay by design; a road that
brings its own is that road's business. **Reach always brings a road,
gladly uses yours, and the session never learns which one it took.**

## S8 — the local mapping broker has no permitted edge (2026-08-07)

**Question.** Can the product's actual macOS mapping path obtain a usable
UDP lease from the active default gateway before reachability code or live
port mappings are introduced?

**Verdict: KILL FIRED.** The active product path has no responding mapping
edge, so this pass stopped before implementation, installation, or plan
retirement.

The host's default route was `192.168.8.1` over `en0`, with the host at
`192.168.8.210`. Three sequential `dns-sd -X` probes exercised the same
system broker used by `DNSServiceNATPortMappingCreate`, each with an unused
UDP port, the same requested external port, and a 120-second requested TTL:

| Probe | Disposable UDP port | Callback delay | External address | External port | TTL | Protocol |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| 1 | 55101 | about 3.5 s | `0.0.0.0` | 0 | 0 | 16 |
| 2 | 55102 | about 3.5 s | `0.0.0.0` | 0 | 0 | 16 |
| 3 | 55103 | about 3.5 s | `0.0.0.0` | 0 | 0 | 16 |

Read-only inspection of the Slate gateway attributed the result: its
`upnpd` service is disabled (`enabled='0'`). Its stored configuration still
has NAT-PMP and UPnP enabled (`enable_natpmp='1'` and `enable_upnp='1'`), but
no `miniupnpd` process or UDP 5351 listener was active. The Proton VPN path
configured on the router is not a mapping broker exposed to the Mac's active
default-gateway product path, so it cannot satisfy this spike.

S9 did not run because S8 produced no lease whose renewal, movement,
teardown, or stale-road behavior could be measured.

The founder explicitly authorized a second attempt the same day. The Slate's
feed supplied `miniupnpd-nftables` 2.3.3-2; it was installed, restricted to
requests from `192.168.8.210/32`, enabled, and verified listening on UDP 5351.
The product broker reached it, and the daemon log showed both the request and
the matching allow rule. The result was still unusable:

- a probe on disposable UDP port 55111 returned macOS error `-65564`
  (`NATPortMappingUnsupported`); miniupnpd had selected the Proton interface
  `wgclient1` at private address `10.2.0.2` and refused to install the mapping;
- a diagnostic repeat on port 55112 returned the same error;
- after separate explicit authorization, binding the broker to the Slate's
  real Wi-Fi WAN (`wwan` / `sta1`) and declaring its private outer address
  `192.168.4.94` failed before startup with the exact broker error
  `Error: option ext_ip contains reserved / private address 192.168.4.94, not public routable`.

The failed interface declarations were reverted. The broker was stopped and
disabled, no listener or lease remained, and the package was left installed
but inert; the narrower Mac-only permission remains. Under the criterion as
then written, S8 had no accessible edge and the kill remained active.

On 8 August the plan split that single question in two. The public-edge result
above became S8a: it still fails and still forbids an end-to-end public-uplink
claim on this rig. A separate S8b asks whether the product mapping client can
be verified against a deliberate conformant instrument; only failure there
stops implementation. The founder explicitly reopened the pass on that
amended criterion.

## S8b — the macOS broker is verifiable (2026-08-07 PDT / 8 August sitting)

**Question.** Can the exact product API path create and tear down mappings,
receive the assigned address, port, and lease lifetime, and repeat reliably
against a conformant controlled edge?

**Verdict: PASS, 3/3.** A one-off miniupnpd 2.3.3 process ran on the Slate with
an ephemeral configuration: boot service still disabled, client restricted to
`192.168.8.210/32`, disposable ports restricted to 55120–55199, and the rig's
current Proton exit `159.26.99.105` used only as a synthetic public-form
callback value. It was an instrument, never a reachability claim.

Three `dns-sd -X` calls exercised `DNSServiceNATPortMappingCreate` with the
system-default TTL:

| Probe | Internal port | Assigned endpoint | Granted TTL | Active-rule check | Deallocation check |
| --- | ---: | --- | ---: | --- | --- |
| 1 | 55121 | `159.26.99.105:55121` | 7200 s | matching PCP lease + nft DNAT | lease and rules empty |
| 2 | 55122 | `159.26.99.105:55122` | 7200 s | matching PCP lease + nft DNAT | lease and rules empty |
| 3 | 55123 | `159.26.99.105:55123` | 7200 s | matching PCP lease + nft DNAT | lease and rules empty |

The system broker chose PCP, preserved each requested external port, and
explicit deallocation removed each mapping immediately. S8b therefore lifts
the verification kill. S8a remains failed: none of these addresses was tested
or claimed as a public road.

## S9 — the lease changes honestly (2026-08-07 PDT / 8 August sitting)

**Question.** What does the system broker report for renewal, movement,
expiry, refusal, and teardown, and what state does the edge actually retain?

**Verdict: PASS for the protocol mechanics; public-uplink behavior remains
unavailable under S8a.** Measurements against the same instrument:

- requesting a 12-second lease was clamped to 120 seconds;
- with the DNSService reference held open, the edge deadline advanced by
  exactly 60 seconds at renewal while the callback value stayed unchanged;
- restarting the instrument with its synthetic address moved from
  `159.26.99.105` to `159.26.99.106` produced a second callback on the same
  live reference with the replacement address, same port, and 120-second TTL;
- three raw, non-renewing NAT-PMP control leases on ports 55125–55127 were
  granted for 120 seconds and all three lease rows and nft rules disappeared
  at expiry;
- a request outside the instrument's ACL (55200) produced macOS error
  `-65564` (`NATPortMappingUnsupported`) while the broker logged the explicit
  permission rejection;
- deallocating a live DNSService reference removed its lease and both
  forwarding chains immediately.

The one-off process was stopped, its temporary files removed, both miniupnpd
chains verified empty, UDP 5351 verified absent, and the boot service left
disabled. The installed package remains inert with the Mac-only ACL. These
results license implementation of automatic mapping and its failure states;
they do not license an internet-reachability claim on the current rig.

## S20 — silence can be classified by the active road (2026-08-08)

**Question.** Can baseline-v0 `Ping`/`Pong` distinguish a real-weight model
that is legitimately silent from a progressively degrading QUIC road quickly
enough to trigger the existing candidate race, without treating silence itself
as failure?

**Instrument.** A normally signed Simulator scratch client used unused local
UDP ports in front of the installed daemon. A seeded Python proxy forwarded
both directions to `127.0.0.1:47337`. The measured profile was clean for five
seconds, then added 10 percentage points of loss and 250 ms one-way delay every
three seconds, capped at 80% and 2.00 s, while still forcing at least one packet
in each direction every two seconds. The app independently opened authenticated
control channels and tested 2, 3 and 5 second silence intervals, using that same
interval as the matching-pong deadline. Each shape ran three times.

**Before-state matrix.**

| Shape | Run 1 | Run 2 | Run 3 | Verdict |
| --- | --- | --- | --- | --- |
| queued real-weight silence | first event 6.136 s | 6.013 s | 6.046 s | all 2/3/5 s pings returned in 1–3 ms; 3/3 legitimate silence |
| progressive degradation | 2 s probe failed at 13.903 s; max event gap 12.130 s | failed at 13.997 s | failed at 14.025 s; max gap 6.781 s | matching pongs stopped in every run, within 9.025 s of degradation beginning |
| explicit clean path change | completed and reattached | completed and reattached | completed and reattached | existing trigger remained 3/3 |

The degradation runs never produced the kill shape: generation delivery did
not remain stalled while matching pongs continued to return. The 2-second
interval was the fastest candidate with 3/3 correct classification in every
shape, and detected degradation inside the required ten seconds. **Ruling: two
seconds of event silence, then one two-second matching-pong deadline. One miss
triggers re-dial only if no generation event won the race.**

**Implemented-path confirmation.** The acceptance proxy used the same seeded,
progressive shape on a faster schedule so the live generation could not finish
before degradation: clean for 1 s; every 0.5 s add 10% loss and 0.5 s one-way
delay; cap at 80% and 4 s; still forward at least one packet each way every
five seconds. A unique identity label per run forced the first generation
stream through the proxy while its authenticated hello taught the client the
healthy direct alternate.

| Run | Visible result | largest event gap | liveness notice | daemon reattach |
| --- | --- | ---: | ---: | ---: |
| 1 | complete, 2,080 snapshots | 4.091 s | 4.072 s, road epoch 1 | from seq 101 |
| 2 | complete, 1,826 snapshots | 4.271 s | 4.252 s, road epoch 1 | from seq 92 |
| 3 | complete, 2,092 snapshots | 4.048 s | 4.031 s, road epoch 1 | from seq 96 |

The complementary implemented-path control queued the same 25,000-token
prefill three times. Occupier/queued first-event gaps were 6.380/6.163 s,
6.609/6.386 s and 6.345/6.130 s. Matching 2/3/5-second pongs returned in every
run, all six generations completed, and ReachKit emitted no liveness-trigger
notice. Recovery therefore depends on evidence from the exact active road,
not on a shorter generation timeout.

**Final signed matrix after the retry-loop corrections.** The normally signed
Simulator build repeated both implemented paths from a clean install. Queued
silence completed 3/3 with occupier/queued first-event gaps of 6.832/6.611,
6.288/6.076 and 6.507/6.289 seconds. There was no liveness notice and no daemon
reattach in any slow run. Seeded degradation then completed 3/3:

| Run | Proxy | Visible result | largest gap | liveness notice | daemon reattach |
| --- | --- | --- | ---: | ---: | ---: |
| 1 | UDP 52161, seed 61 | complete, 1,524 snapshots | 4.239 s | 4.220404 s, epoch 1 | seq 113 |
| 2 | UDP 52162, seed 62 | complete, 3,390 snapshots | 4.111 s | 4.088257 s, epoch 1 | seq 99 |
| 3 | UDP 52163, seed 63 | complete, 2,208 snapshots | 4.147 s | 4.129326 s, epoch 1 | seq 72 |

Every proxy drained before teardown, all three ports were free afterward, and
the Simulator returned to Home. This final 6/6 matrix is the acceptance
measurement; the earlier matrix above records the first implemented shape that
found the remaining retry defects.

**What the phone found before it passed.** The first natural walks exposed two
client retry errors that a local proxy could not hide. A transport-ending frame
from the path watch initially escaped through the generation-stream error path
instead of re-entering the road race. After that was corrected, an attempt that
opened inside the ten-second cold budget kept using that deadline even after it
had received events; a later hop therefore had no resident-generation retry
time left. The retry decision now derives its deadline from whether an event
has actually been received: ten seconds while nothing is resident, 120 seconds
after the first event. The loopback regression delays the hop beyond the cold
budget and then proves reattach rather than double execution.

The failed walks also found rig drift rather than licensing product folklore.
The Slate's static UDP forward and its GL.iNet-specific hidden
`port_forward` table both still targeted the Mac's abandoned `.104` address;
the Slate WAN had moved from `192.168.4.94` to `192.168.4.22`; and the installed
Keeper predated its away-road control. The single UDP/51820 forward was made
consistent at `192.168.8.210`, the hidden table and stale conntrack entry were
corrected, the current Keeper was installed and re-paired, and its on-demand
away road was visibly enabled. A cold building-network preflight then showed
the phone's outer flow reaching `192.168.4.22:51820`, the reply leaving
`.210`, an assured conntrack entry, and inner `utun9` traffic.

**Hardware acceptance: PASS.** A normally launched Example began the filmed
3,000-word generation on the Slate LAN. Session
`3B135C82-1AE6-48E4-9468-1BED0CAD8E19` opened from `192.168.8.225`; during the
natural walk to the building network, generation
`9A731727-446F-4C47-B5A3-BE2172F34B64` reattached over the alternate mesh road
from `10.86.0.2` at sequences 1016 and 1433. The same response reached its
final river paragraph and the app visibly reported `done`, with no error and
no manual Wi-Fi toggle. The terminal screenshot's SHA-256 is
`60b634a5a78efe857b65a75b68de47de7a87419a4bb88210b2528e06ea063276`;
the retained daemon slice contains both reattaches and no generation refusal.
S20 therefore closes on both required halves: silent work stays put when the
road answers, and a degraded road causes an invisible, completing re-dial.

## S21 — the lid closed and the cluster woke intact (2026-08-09–10)

**Question.** What actually happens to the installed cluster across a short
lid close, a sleep beyond the generation-residency window, and an idle night?
Does launchd hide a death, do listeners or weights disappear, and do suspended
mapping timers leave stale roads after wake?

**Instrument.** The installed release ran on one MacBook Pro (`Mac17,9`, Apple
M5 Pro, 64 GB) under macOS 27.0 build `26A5388g`. A disposable,
LaunchAgent-shaped AppKit observer in `/private/tmp` listened only to
`NSWorkspace` system-sleep and system-wake notifications, recorded monotonic
elapsed time, and held no power assertion. Every notification was corroborated
against `pmset`; display-only events were excluded. `ProcessType: Interactive`
was retained unchanged: it selects launchd's resource class, not a request to
prevent sleep.

Mapping suspension was exercised independently of the live ports through the
real `ReachabilityCoordinator` on UDP `55121` and `55122`. A one-off Slate
broker listened on `br-lan`, attached rules to `sta1`, allowed only
`192.168.8.210/32` and external/internal ports `55120...55199`, and left the
persistent service disabled. Because miniupnpd correctly refuses an RFC1918
`ext_ip`, the measurement used the same public-form address instrument as S9
while the actual outer interface remained the Slate's private building lease.
It therefore proves suspension, expiry, recreation and cleanup, not public
internet reachability or a private-double-NAT callback.

**Matrix.** Two trials of every required duration completed. One additional
10-minute rehearsal is retained but excluded because the phone locked during
it.

| Duration | Trial | Confirmed system-sleep interval | Generation result | daemon / model | mapping result |
| --- | ---: | ---: | --- | --- | --- |
| short | 1 | 78.544 s | same generation reattached at seq 469 and finished, 14,276 characters | PID 38397, launchd run 1 survived | coordinator and leases survived |
| short | 2 | 72.882 s | output paused while the host slept, then the same generation reattached at seq 218 and 1154 and visibly reached `done` | same PID/run survived | coordinator and leases survived |
| 10 min | 1 | 597.806 s | remained foreground and streamed 18,559 characters to `done` while the lid was closed | no restart or model reload | live requests remained valid |
| 10 min | 2 | 599.855 s | remained foreground and streamed 15,706 characters to `done` while the lid was closed | no restart or model reload | live requests remained valid |
| overnight | 1 | 29,929.759 s (8 h 18 m 49.759 s) | cold post-wake signed usage probe passed, input 21 / output 20 | PID 38397 and 4.4 GiB model survived; launchd run 1 | two 7,200-second leases renewed |
| overnight | 2 | 28,823.484 s (8 h 00 m 23.484 s) | fresh phone session streamed exactly `awake` and visibly reached `done` | PID 12268, launchd run 2 and 4.27 GiB model survived | expired leases were recreated four seconds after wake |

The excluded rehearsal slept for 605.924 seconds and also streamed to `done`,
but the phone was locked for part of it; it is evidence about the host, not a
controlled client trial.

**The ten-minute expectation was wrong in a useful way.** The 120-second
generation residency limit never became the ending because the host did not
remain inert while work was arriving. In trial 1, inbound QUIC activity drove
roughly 55 seconds of network dark wake while the response completed, followed
by about 543 seconds of deep sleep. Trial 2 did the same for roughly 65 seconds,
then slept deeply for about 526 seconds. Both post-wake signed probes passed
(21/20 and 21/18 input/output tokens). Residency still bounds an unavailable
generation; it is not a timer that fires merely because the lid is shut while
macOS continues servicing the active flow.

**Overnight process and power evidence.** In trial 2 the observer recorded
`system-will-sleep` at `2026-08-10T10:02:57.593Z` and `system-did-wake` at
`18:03:21.077Z`. `pmset` independently recorded clamshell sleep at 03:03:02
PDT, maintenance and SleepService dark wakes throughout the night, and a lid
wake at 11:03:21 PDT. The battery charged from 21% to 100%. The daemon,
observer, and mapping coordinator retained PIDs `12268`, `12056`, and `12086`
and launchd run counts 2, 1, and 2. Both UDP listeners remained owned by the
same daemon; `10.86.0.1` remained up; `reachd.log` did not change between the
pre-sleep baseline and the post-wake client; and the model RSS remained
4,474,448 KiB. There was no hidden supervisor restart or model reload.

The second trial's scratch leases initially expired at 04:55:56 PDT while the
host was asleep. The system broker recreated both at 11:03:25—four seconds
after wake—with new expirations at 13:03:25. `reachability.json` did not change
because address, port and TTL were identical, which is correct: it records
endpoint evidence, not every renewal transaction. The edge lease and nft rules
proved the refresh. A product wake observer would duplicate behavior the
system broker already provides.

**Installed acceptance.** Trial 1's cold `doctor --dial` opened a session in
37 ms with 13 pass / 3 warning / 0 failure. Trial 2's doctor was 11 pass / 4
warning / 0 failure and hit only the established diagnostic-identity
`SecPKCS12Import` `-25291` fault; a normally signed phone then opened session
`17C9E6C2-6934-42E8-B68E-BE79EBEEB8B4` from `192.168.8.225:51263`, streamed
exactly `awake`, and visibly reported `done`. Across both overnights all four
CA/server SHA-256 values were unchanged and `cluster CA created` remained zero.
At closeout, the same installed binary passed the scripted spine, the MLX
spine, unconstrained sampling 3/3 and guided schemas 15/15. A normal-keychain
`doctor --dial` then cleared the diagnostic warning and opened an authenticated
session in 33 ms: 13 pass / 3 expected mapping and pinned-endpoint warnings /
0 waiting / 0 failure. The complete ReachKit suite passed 79/79 in 8/8 runs,
the complete reachd suite passed 171/171 in 8/8 runs, and normally signed
generic-Simulator Example and generic-iOS Keeper builds both succeeded. No
source or installed binary changed during this documentation-only pass.

**A reboot between the overnights exposed a different boundary.** `/private/tmp`
was correctly cleared; the Reach LaunchAgent returned after login, but
WireGuard did not rise with it. `sudo wg-quick up reach0` and one supervised
daemon restart were required before the second baseline advertised the mesh
road. That is broader host lifecycle—boot/login, logout, updates and key
availability—not a sleep failure, and remains a separate follow-on rather than
being smuggled into this pass.

**Verdict: PASS, documentation-only branch.** Healthy sleeps need no Reach
sleep assertion, wake subscription, listener reconstruction, persisted
generation, `ProcessType` change, or client path prod. The temporary agents
were unloaded; the coordinator deallocated both mappings; the one-off Slate
broker and its files were removed; UDP 5351/1900/5000 were absent; all three
UPnP chains were empty; and persistent UPnP remained disabled. This result is
measured on one Mac across six controlled trials, not a claim about every
laptop or macOS release.

## S22 — one executable image, two bundle identities (2026-08-10)

**Question.** The accepted installed binary and its seven SwiftPM resource
bundles are one layout under `~/.local/libexec/reach`. Why does
`selftest --mlx` pass when that binary is named directly but fail with
`Failed to load the default metallib` when the same inode is reached through
`~/.local/bin/reachd`?

**Instrument.** A disposable Swift executable and staged install tree under a
`/private/tmp` directory containing spaces printed the process identity under
four launches: canonical absolute path, absolute symlink, relative nested
symlink, and bare `reachd` found through a temporary `PATH`. It retained
`CommandLine.arguments[0]`, `ProcessInfo.arguments[0]`, `_NSGetExecutablePath`
before and after `realpath`, dyld image zero, `dladdr` for a symbol in the
executable, and `Bundle.main`'s bundle, executable and resource URLs. The
pinned MLX sources were then traced at the exact checked-out revision.

| launch | `argv[0]` | `_NSGetExecutablePath` | `realpath` / `dladdr` | `Bundle.main` |
| --- | --- | --- | --- | --- |
| canonical | canonical absolute path | canonical | canonical | canonical resource directory |
| absolute symlink | absolute alias | absolute alias | canonical | alias directory |
| nested symlink | nested alias | nested alias | canonical | nested alias directory |
| bare `PATH` | `reachd` | absolute alias selected by `PATH` | canonical | alias directory |

The split is exact. MLX's `current_binary_dir()` uses `dladdr`, so its first
colocated search is already canonical; Reach deliberately ships no colocated
`mlx.metallib`. The SwiftPM fallback that can find
`mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib` starts at
`NS::Bundle::mainBundle()->bundleURL()`, which is the alias directory in the
three failing shapes. The remaining loaded-bundle search has no second main
bundle rooted beside the canonical executable. The installed hash remained
`bdaf33611eda8e5eadab1e56f788b7af09eb7a2cc3849990b0a69b87b2f61108`,
so the 8 August canonical-pass/symlink-fail A/B still describes these bytes.

**Prototype.** The same disposable executable performed one idempotent
`execv` of `_NSGetExecutablePath` after `realpath`. On the replacement image,
all four launches reported the canonical executable and canonical
`Bundle.main`; the direct launch did not replace itself. A value containing
spaces in the environment, the working directory, an argument containing
spaces and an empty argument all survived. Replacing `argv[0]` with the
canonical target also gives child-process code one spelling rather than
requiring each child to rediscover the alias.

**Verdict: PASS / EARLY CANONICAL RE-EXEC.** The fault is process bundle
identity at Reach's executable boundary, not a missing resource, service
installer defect or MLX model behavior. Normalize once before ArgumentParser
or MLX access. Do not add a launcher shell, copy resources beside aliases,
change the working directory, export a private resource path, or fork the
dependency.

**Implementation and acceptance.** A package-internal resolver now reads
`_NSGetExecutablePath`, applies `realpath`, and returns either continue or one
canonical replacement. The new executable bootstrap runs before
ArgumentParser and MLX. It passes the canonical target directly to `execv`,
sets `argv[0]` to that target, retains the kernel's raw `argv[1...]` pointers,
and logs then continues if replacement fails. Seven focused tests hold direct,
absolute, nested, `PATH`, spaced, missing and failure shapes, including a
spaced argument, an empty argument, the null terminator and injected
`EACCES`.

One fresh warnings-as-errors release, SHA-256
`c0c4e08072d1e6fa0db1aaca702912c66b42d431eb7e72195f7351d0348d46af`,
passed the scripted spine 4/4 and the real-weight MLX spine 4/4 through the
canonical path, installed-style symlink, nested symlink and bare `PATH`.
Every MLX run also passed explicit unconstrained sampling 3/3 and guided
schemas 15/15. Direct and nested-alias subprocesses produced byte-identical
`status`; empty and spaced extra arguments produced identical exit 64;
`REACH_STATE_DIR` containing spaces resolved from the unchanged working
directory; `ps` observed canonical `argv[0]`; and SIGTERM remained status 143.
The nested alias's restart rig killed its child after two snapshots, received
the existing legible restart ending in 4.10 seconds, relaunched after one
second, and completed a fresh ask. ReachKit passed 79/79 in 8/8 complete runs;
reachd passed 178/178 in 8/8; the normally signed generic-Simulator Example
linkage build succeeded.

**Installed guard.** The prior accepted binary plus seven bundles were saved
as one eight-item unit before replacement. The first final-binary copy exposed
a deployment detail: overwriting the existing executable inode made launchd
report `OS_REASON_CODESIGNING` even though the embedded linker signature
verified. Copying to a fresh sibling inode, verifying it, and atomically
renaming it into place cleared the rejection. The accepted agent runs the hash
above from the canonical plist path with exactly seven adjacent bundles and no
alias bundles. Both listeners are held, the model prewarmed, all four CA/server
fingerprints are unchanged, CA creation remains zero, authenticated
`doctor --dial` is 13 pass / 3 expected warnings / 0 waiting / 0 fail, and
installed canonical, symlink and bare-`PATH` MLX selftests all pass.

## S23 — login brings the process back; privilege must bring the mesh (2026-08-10)

**Question.** Which authority actually owns each part of the cluster across
lock, logout and reboot, and can WireGuard rise after `reachd` without
restarting the daemon? The old operator explanation attributed login ownership
to a listener identity in the login keychain. The current source does not:
`IdentityMaterializer` imports the disk-backed leaf with
`kSecImportToMemoryOnly`.

**Authority trace.** The serving system is six independent authorities, not
one thing called launchd or the keychain:

| surface | measured/current owner | contract established here |
| --- | --- | --- |
| daemon process | `systems.reach.reachd` in `gui/501` | login-owned; absent before login, automatically supervised after login |
| cluster state and CA | UID 501, `~/Library/Application Support/Reach` | the generated agent pins this exact path through `REACH_STATE_DIR` |
| listener identity | disk leaf → memory-only PKCS#12 import | not a login-keychain reason for the service boundary |
| model runtime | the user's interactive MLX/Metal process | starts and prewarms after login; pre-login serving is unsupported rather than inferred |
| mesh interface | root-applied WireGuard configuration | absent after both reboots; automatic privileged bootstrap needs a separate trust design |
| client roads | each paired client's authenticated calling card | every hello recomputes current host addresses; a client already away cannot learn an address that appeared after its last hello |

The local trust boundary rules out an unattended root shortcut.
`/opt/homebrew/bin/wg-quick`, its Homebrew tree, and
`/opt/homebrew/etc/wireguard/reach0.conf` are user-owned; the config is mode
`0600`. The script parses and evaluates `PreUp`, `PostUp`, `PreDown`, and
`PostDown` hook fields. A root job consuming that mutable file would therefore
turn a user edit into persistent root command execution. No LaunchDaemon,
`NOPASSWD` rule, wrapper script, or privileged helper was installed in this
pass.

**Physical matrix.** The accepted installed hash was
`c0c4e08072d1e6fa0db1aaca702912c66b42d431eb7e72195f7351d0348d46af`.
The pre-change daemon began as PID 66242/run 1 with both listeners, the model,
and `10.86.0.1`. Each phone run was a normally launched, already-paired
Example; Keeper and its PacketTunnel were left untouched.

| transition | process and roads | authenticated result |
| --- | --- | --- |
| lock → unlock | same PID 66242/run 1, listeners/model/mesh retained | Slate session completed 11,701 characters |
| logout/login 1 | new PID 82109/run 1 in the new `gui/501` instance; mesh retained | cold Slate session completed 13,595 characters |
| logout/login 2 | new PID 83911/run 1; mesh retained | cold Slate session completed 14,547 characters |
| reboot 1, pre-login | no GUI LaunchAgent and no daemon | phone refused boundedly: no answer on its four known roads |
| reboot 1, post-login untouched | PID 961/run 1, both listeners/model present; no `10.86.0.1` | LAN session `34C4B0F4-…` opened from `192.168.8.225`; doctor exposed the missing mesh |
| reboot 1, late mesh | `sudo wg-quick up reach0` produced `utun4 10.86.0.1`; PID stayed 961/run 1 | after one Slate hello refreshed roads, away session `FC216C98-…` opened from `10.86.0.2` and streamed to `done` |
| reboot 2, pre-login | final controlled reboot again had no GUI LaunchAgent or daemon | phone refused boundedly against three learned roads |
| reboot 2, post-login untouched | PID 951/run 1 and both listeners returned; no mesh. The Mac first auto-joined `192.168.4.50`, then ordinary Wi-Fi selection returned it to Slate without restarting the daemon | local `doctor --dial` passed; Slate session `AFFAF33E-…` from `192.168.8.225` completed 10,644 characters |
| reboot 2, late mesh | `utun4 10.86.0.1` rose; PID stayed 951/run 1; doctor returned 13 pass / 3 expected warnings / 0 fail | Slate refresh `14CA40B0-…` completed 10,062 characters; cold away session `2063672E-…` opened from `10.86.0.2`, reattached at seq 381, 744, 925, 1235, 1491 and 3468, and visibly reached `done` |

The first attempt in reboot trial 1 taught an important ordering fact. A LAN
hello while mesh was absent correctly replaced the phone's calling card with
two then-current roads. Raising WireGuard after the phone had already left
could not teach it the new address, so that attempt refused without reaching
the daemon. Returning to Slate for one authenticated hello populated
`10.86.0.1`; the next cold away launch passed. The daemon listener itself had
already been capable of accepting on the late interface. No restart or re-pair
was required.

One accidental login/reboot before the second controlled pre-login attempt is
retained as an unmeasured extra boot, not counted as a trial. The final reboot
then followed the exact pre-login sequence and is the recorded trial. Fast
user switching remained unmeasured because no suitable second account was
evidenced or authorized; no account was created. No safe OS update naturally
occurred, so update survival remains unmeasured.

All four CA/server SHA-256 values remained byte-identical, `cluster CA
created` remained zero, the enrolled device stayed `iPhone (10.86.0.2)`, the
WireGuard public identity remained `zBiw+nU3TWFz…`, and the phone never
re-paired. The initial rollback copy under `/private/tmp` was correctly erased
by reboot; before implementation work the accepted eight-item artifact, state,
plist, and WireGuard config were re-backed up under user-owned Application
Support so the actual rollback unit survives the transition it protects.

**Verdict: LOGIN-OWNED PASS / PRIVILEGED FOLLOW-ON REQUIRED.** Lock and
logout recover within the chosen login boundary. Pre-login serving is
unsupported. Both reboots reproduce one missing authority: root-owned mesh
activation. A late interface is immediately usable by the unchanged wildcard
listener, and the next authenticated hello advertises it, so restarting
`reachd` is both unnecessary and harmful to the distinction being measured.
The bounded product change is an explicit login-owned launch definition,
root preflight guards, readiness-aware status, current-address hello tests,
and corrected operational truth. Automatic mesh bootstrap requires a trusted
installer and sanitized structured configuration and is a separate pass.

### Installed-release repeat

The implementation release was built warnings-as-errors at
`fb4864642e9cd3590d7caffb6ad6dc3ca4e79d7b0b882156b8ad5f57ad7ef324`,
installed as one executable plus seven adjacent bundles, and exercised again
through the complete physical matrix. ReachKit passed 79/79 and reachd passed
182/182 in each of eight complete runs; the normally signed generic-Simulator
Example and generic-iOS Keeper linkage builds also passed. Keeper source and
behavior were unchanged.

| installed transition | process and roads | authenticated result |
| --- | --- | --- |
| lock → unlock | PID 37579/run 1 remained; listeners and mesh stayed present | normally launched Example completed 10,934 characters; session `80963E3F-…` opened from `192.168.8.225` |
| logout/login 1 | exactly one new PID 40245/run 1; both listeners and model returned; mesh was absent | visible Slate completion; session `44A69E32-…` opened from `192.168.8.225` and its generation reattached at seq 797 |
| logout/login 2 | exactly one new PID 41564/run 1; both listeners and model returned; mesh was absent | 15,832-character Slate completion; session `8450B517-…` opened from `192.168.8.225` |
| reboot 1, pre-login | no login-owned daemon | screenshot retained the bounded no-road refusal against two then-known roads |
| reboot 1, post-login untouched | exactly one PID 860/run 1; both listeners/model returned; mesh was absent | session `D11FDF23-…` opened from `192.168.8.225` and the phone visibly completed |
| reboot 1, late mesh | `utun6` acquired `10.86.0.1`; PID stayed 860/run 1 | a 12,628-character Slate refresh opened session `7B866659-…`; cold away session `61EA960B-…` opened from `10.86.0.2` and streamed to `done` |
| reboot 2, pre-login | no login-owned daemon | screenshot retained the bounded no-road refusal against three then-known roads |
| reboot 2, post-login untouched | exactly one PID 989/run 1; both listeners/model returned; mesh was absent | 10,508-character Slate completion; session `EED3F4F6-…` opened from `192.168.8.225` |
| reboot 2, late mesh | `utun4` acquired `10.86.0.1`; PID stayed 989/run 1 | a 14,882-character Slate refresh opened session `887817B1-…`; cold away session `585F8035-…` opened from `10.86.0.2`, reattached at seq 143, 231, 486 and 1112, and streamed to `done` |

The installed repeat strengthens the privilege finding. The pre-change
logout observations happened to retain the user-space WireGuard interface;
both installed logout trials did not. Interface survival across logout is not
a contract and must not be inferred from one run. Automatic mesh bootstrap
must cover every supported login transition, while service status must keep
reporting a running daemon with no mesh as incomplete away readiness.

The four CA/server fingerprints remained byte-identical throughout, the
device registry and WireGuard host public identity were unchanged, no phone
re-paired, and `cluster CA created` remained zero. The final installed
`doctor --dial` reported 11 pass, four expected warnings, zero waiting and
zero fail; its diagnostic identity hit the attributed intermittent
`SecPKCS12Import` `-25291` seam, while the normally signed Example completed
authenticated LAN and mesh sessions in the same installed state. An earlier
installed diagnostic dial had completed successfully before the disruptive
matrix.

### Canonical service-state repair

Review after S23 found two bounded authority defects before the privileged
mesh-bootstrap pass could safely consume the login contract. An ambient
`REACH_STATE_DIR` could be serialized into the persistent LaunchAgent, and
service status treated any four-octet `10.86.x.x` address as mesh-ready while
the rest of Reach required `10.86.0.0/24`. The roadmap and mesh-bootstrap plan
were already based on synchronized `e1372b5`; no stale-state correction was
fabricated.

The repair separates canonical login state from the existing foreground and
scratch runtime override. Service installation now refuses divergent state
before executable or filesystem access, while status and doctor strictly
parse and validate the installed plist. Endpoint derivation, doctor and status
share one exact four-octet `10.86.0.x` predicate. No wire, dependency, public
API, Keeper, WireGuard or privileged behavior changed.

Focused state/status/mesh and late-hello coverage passed 34/34 three times.
ReachKit passed 79/79 in eight complete runs. reachd passed 189/189 in eight
accepted complete runs. One additional full-suite attempt reproduced the
named cold-ask timing sentinel at 41.3437 seconds; the unchanged test then
passed alone in 10.486, 11.019 and 10.511 seconds, and the replacement full
run passed 189/189. No timing threshold or unrelated test was weakened.

The fresh warnings-as-errors release has SHA-256
`127081878c0aa014e39b07aea1f125c8c040dd05a5db51131e4a872e28e498d4`.
Its seven bundles were byte-identical to the accepted installed bundle set.
Before the authorized swap, the executable, seven bundles, plist, complete
state, WireGuard configuration and the 655-line / 63,093-byte log checkpoint
were copied byte-for-byte under
`~/Library/Application Support/Reach Backups/host-lifecycle-fixes-2026-08-11-0337Z`.
The stopped binary was replaced through a verified fresh sibling inode, then
`service install` ran with `REACH_STATE_DIR` absent.

The installed result is PID 42756/run 1 in `gui/501`, serving both UDP ports
from the canonical executable with exactly seven adjacent bundles. The plist,
status and doctor all name
`~/Library/Application Support/Reach`; status reports exact mesh address
`10.86.0.1`. Authenticated `doctor --dial` opened over
`127.0.0.1:47337` in 34 ms and finished 13 pass / 3 expected mapping and
pinned-endpoint warnings / 0 waiting / 0 fail. Installed canonical and alias
launches each passed the MLX spine, unconstrained sampling 3/3 and guided
schemas 15/15. The four CA/server hashes, device registry, WireGuard host
public key and WireGuard configuration remained byte-identical, and no
`cluster CA created` line appeared. No phone, logout, reboot, re-pair or
privileged mutation was needed for this correctness repair.

## S24 — privilege owns only the WireGuard road (2026-08-10)

**Question.** What supported boundary can raise the host WireGuard peer after
logout or reboot without moving `reachd`, cluster authority or model execution
into root, and without executing a user-writable Homebrew program or
hook-capable configuration as root?

**Candidate trace.** Three boundaries were compared before tracked product
work:

| candidate | measured/documented requirement | verdict |
| --- | --- | --- |
| `SMAppService` privileged helper | current SDK requires an app-bundle service and a notarized containing app; Reach ships a CLI and this rig has no suitable distribution identity | reject for this release shape |
| packet-tunnel provider | Apple says a packet-tunnel provider is not a general host network-listener mechanism; it would also entangle the phone-side Keeper boundary | reject |
| root LaunchDaemon with embedded `wireguard-go` | scriptless component package can protect one executable and fixed plist as root; compile-only prototype linked only system libraries and needed no Homebrew, `wg`, shell or user runtime | select |

The embedded dependency is annotated tag `0.0.20250522`, commit
`f333402bd9cbe0f3eeb02507bd14e23d7d639280`. The boundary is a root-owned
`systems.reach.meshd` process that owns only a dynamic `utun`, while the
existing `systems.reach.reachd` LaunchAgent, CA, registry, sessions, model and
serving remain login-owned.

**Disposable privileged proof.** Before tracked edits, a temporary helper and
scriptless component package used the isolated label
`systems.reach.meshd.s24`, address `10.86.254.1/24`, and unused UDP `55182`.
The helper SHA-256 was
`fc0fc1e5a3e7cd43c2d86a8698609a7dc748acaa0afd37ab37bef5ef3520e78f`;
the unsigned local package SHA-256 was
`e8b2475e46952a75628fb64ef243d9c50501d71a6f2cfe46f65a2b50df05193c`;
and its bounded configuration SHA-256 was
`d121a53b7efa2285af8b722f6f3b1bd54aa688d5f4a17fe7667f5e432019ad6e`.
The package payload listed only the helper and LaunchDaemon plist beneath the
required system directories and contained no installer scripts.

The founder-authorized operation installed the package and bootstrapped its
fixed plist:

```
/usr/sbin/installer -pkg /private/tmp/reach-mesh-s24.toIdBh/systems.reach.meshd.s24.clean.pkg -target /
/bin/launchctl bootstrap system /Library/LaunchDaemons/systems.reach.meshd.s24.plist
```

The job started root-owned, created one `utun` with `10.86.254.1/24`, held UDP
`55182`, and exposed its expected process and launchd identity. Killing the
helper reproduced unconditional launchd recovery. Teardown booted out the
fixed system label, removed the two payload files and bounded prototype state,
forgot receipt `systems.reach.meshd.s24`, and verified the absence of job,
process, interface address, UDP listener, socket, log, receipt and
configuration. No live Reach port, key, registry, CA, daemon or service was
changed.

**Verdict: PASS / ROOT-OWNED HEADLESS MESH OWNER.** The prototype needs root
only for installation, lifecycle and interface ownership. It does not need a
user-writable executable, package script, broader authorization, signing
identity, shell or cluster-state access. Product work may therefore embed the
pinned MIT implementation in one ad-hoc-signed local helper, define a strict
version-1 data contract and leave Developer ID signing/notarized distribution
as the later release frontier.

**Product contract.** Login-owned `mesh-intent.json` carries deterministic
public intent without the private host key. One-time migration strictly reads
the existing hook-free `reach0.conf` and leaves those bytes untouched as
rollback evidence. `reachd mesh stage` cross-checks intent, registry and host
public key before writing one user-owned mode-`0600` specification inside a
mode-`0700` directory. `reachd mesh apply` names and invokes only
`/Library/PrivilegedHelperTools/systems.reach.meshd` through `/usr/bin/sudo`.
The helper independently requires root, a valid `SUDO_UID`, its canonical
root-owned executable, an unchanged regular user-owned input, strict schema
validation and a root-only control peer. It consumes the input and promotes a
validated pending generation only after the live backend accepts it; failure
restores the active last-known-good generation.

The root state is split into a public privacy-safe `status.json` and a
mode-`0700` private directory containing mode-`0600` active/pending data. The
public record is bounded to helper version, PID, generation, public digest,
interface name, readiness, peer count, update time and a fixed error
vocabulary. `doctor` and `service status` require package ownership and launch
policy, helper/status PID agreement, desired generation/digest agreement, and
the actual exact `10.86.0.1` address. Missing/unconfigured is waiting; a
manually raised legacy road is usable but unmanaged; malformed or divergent
authority is failure.

**Pre-installation product checkpoint.** The helper's rootless backend,
manager, strict decoder, secure-file, control-socket and status tests passed
three times under Go's race detector; `go vet ./...` also passed. The focused
Swift intent/owner/enrollment/diagnostic suite passed 63/63 three times.
ReachKit passed 79/79 in all eight complete runs. reachd passed 200/200 in
seven of eight required complete runs. One issue-bearing run completed in
62.462 seconds; its duration matches the existing serialized cold-open timing
sentinel rather than any mesh test. Both named cold-open guards then passed
alone 3/3: the no-resident-generation case in 9.658–9.765 seconds and the
30-second-connect-timeout case in 10.546–10.725 seconds. The five subsequent
complete runs all passed in 48.278–49.651 seconds. No timing threshold was
changed.

The fresh warnings-as-errors `reachd` release has SHA-256
`104ae97363ebc628cff85462b954d31dcafc48c40800826c7c3334802f6fce03`
and exactly seven adjacent bundles. Canonical, installed-style absolute
symlink (including a path containing spaces), and nested-symlink launches each
passed the MLX spine, unconstrained sampling 3/3 and guided schemas 15/15;
there were no bundles beside either alias. The normally signed generic
Simulator Example and unsigned generic-iOS Keeper linkage guards both built.

The scriptless local component package contains exactly
`/Library/PrivilegedHelperTools/systems.reach.meshd` and
`/Library/LaunchDaemons/systems.reach.meshd.plist`. The ad-hoc-signed helper
has SHA-256
`956ec948d490fce02305afaea4f49a0abc9e4853f950403db5ef52dd36bf8193`
and CDHash `1bc0816e3993ab302db2618a73d30dc9dd786e78`; the plist has SHA-256
`9c5d7d2b789ff984418119b56e332f98b53adde7c042f2e0083d6cbed5ff8b0b`;
and the package has SHA-256
`4d66905cce5acb8a927a9729c5415770c57221d23d2619e88142b3857bd38d0c`.
The helper is a thin arm64 executable linked only to Apple system libraries,
and its build metadata records the pinned `wireguard-go` revision above.

No live privileged product has been installed at this checkpoint. No
`NOPASSWD` rule is created. The bounded local installation, bootstrap, first
apply and immediate privileged acceptance operations are arranged behind one
native `sudo -v` administrator authorization, followed only by fixed Apple
executables and the installed root-owned helper; no user-writable script is
executed as root. The installed physical matrix is recorded below only after
its separate founder authorization and completion.

The recoverable pre-install backup is
`~/Library/Application Support/Reach Backups/mesh-bootstrap-2026-08-11-0700Z`.
Its 35 files / 58 MiB include the complete installed eight-item artifact,
canonical state, LaunchAgent plist, 679-line log checkpoint, and untouched
legacy `reach0.conf`. Source-versus-backup `diff`/`cmp` checks were empty. Its
privacy-safe `MANIFEST.txt` records the four CA/server hashes, registry, host
key, old/new executable and package hashes, and the pre-install PID/run count.

### Installed S24 acceptance — 11 August 2026

The authorized installation preserved the login/root split. One login-owned
`reachd` continued to own the CA, registry, model, sessions and listeners; one
root-owned `systems.reach.meshd` owned only its strict specification, dynamic
`utun`, UDP `51820`, and mesh route. No `sudoers` entry, `NOPASSWD` rule,
stored credential, package script, Homebrew runtime or root execution of the
legacy file was introduced.

The immediate privileged matrix passed an idempotent generation-1 apply, a
controlled helper kill and launchd restart, generic malformed-update refusal,
a registry-consistent temporary second-peer generation, and rollback to the
canonical one-peer generation 3. Malformed and consumed staging data did not
replace the active generation; the login daemon PID did not move. Two bounded
implementation defects found by that matrix were closed before acceptance:
the helper now explicitly applies the declared mode to a directory it has just
created despite launchd's `Umask 077`, and it validates and removes only its
own stale root-owned Unix socket after an unclean death.

The physical lifecycle matrix passed one lock, two logout/login trials and two
reboot/pre-login/login trials. Each pre-login phase had the root mesh helper
but no serving daemon, and the phone got the bounded no-road refusal. Each
login automatically produced exactly one login-owned daemon and an
authenticated phone generation streamed to `done`; no Terminal command was
needed to raise the helper. The helper remained PID 52231 across both logout
trials, returned as PID 531 and PID 573 after the two reboots, and the daemon
returned as PID 55070, PID 56518, PID 876 and PID 922 in the four supported
post-login phases. These trials used the first installed helper build and
prove its launchd ownership and lifecycle contract.

The first strict building-network cold open then found a separate data-plane
defect: the helper had assigned `10.86.0.1/24`, but had not installed the
connected `10.86.0.0/24` route. `/sbin/route -n get 10.86.0.2` selected the
default path through `en0`, and no daemon session arrived. The accepted helper
now installs the exact route on its created `utun`, removes it on orderly
teardown, and cleans it after a partial setup failure. Focused route command,
failure and removal tests passed 3/3; the complete Go race suite passed 3/3
and `go vet ./...` passed.

The route-corrected scriptless package contains the same two payloads and no
scripts. Its helper SHA-256 is
`9f56170e54e0e4e96aefb732e0df42d5bb878a340b6e905596743e2fa545909b`,
its plist SHA-256 is
`9c5d7d2b789ff984418119b56e332f98b53adde7c042f2e0083d6cbed5ff8b0b`,
and its package SHA-256 is
`d91612140bb746215d3ba2676586842608c50bf3d6d3f70e42abc635de99ccdd`.
The helper's ad-hoc CDHash is
`448468b72738de4f718baa891a960ab925584b2a`. Replacement retained a complete
rollback copy of the preceding helper. A later controlled kill changed the
helper from PID 22263 to PID 22840, restored generation 3, `utun0`,
`10.86.0.1/24`, and the connected route, while `reachd` remained PID 922.

The final cold-open baseline had Example process-absent and the unchanged
Keeper packet tunnel alive. From the building network, the daemon opened
session `4EBDAA17-3740-4085-8A8D-E92CC78C8E19` from
`10.86.0.2:57849`; the phone streamed and visibly reached `done`. This is the
end-to-end proof for the corrected helper bytes. CoreDevice became unavailable
across the network boundary, so process provenance comes from the immediately
preceding profile-validated read-only inventory and the terminal result is the
founder's visible report; the authenticated mesh source is daemon evidence.

A final controlled reboot then exercised those exact corrected bytes. Before
login, the phone was still on the building network and got the expected bounded
no-road refusal: the root helper existed, but the deliberately login-owned
serving daemon did not. After login, launchd had automatically started final
helper SHA `9f56170e…5909b` as PID 525 and final `reachd` SHA
`104ae973…ce03` as PID 957. `service status` reported generation 3, one peer,
and `utun0`; `/sbin/route -n get 10.86.0.2` selected the connected
`10.86.0.0/24` route on `utun0` with MTU 1280. A new strict cold open then
authenticated daemon session `83886836-9931-46C9-84C0-C2ECAA1754B2` from
`10.86.0.2:52996` and streamed visibly to `done`. No mesh or daemon command was
run after reboot. Doctor's disposable identity hit the established
`SecPKCS12Import -25291` fault on three bounded post-reboot attempts; all other
findings passed, the same installed bytes had already completed authenticated
doctor dials, and this normally signed real-client session supplies the direct
post-reboot authentication proof.

Installed canonical MLX, unconstrained sampling 3/3 and guided schemas 15/15
all passed. Authenticated `doctor --dial` completed over loopback in 38 ms and
the final closeout recheck in 41 ms, both with 15 pass, three expected mapping
warnings, zero waiting and zero fail. The
sandbox-only `SecPKCS12Import -25291` remained attributable because the same
installed command passed outside the sandbox. The four CA/server hashes,
device registry and WireGuard private/public identities remained
byte-identical, no `cluster CA created` line appeared, and no re-pair occurred.

**Verdict: PASS.** Automatic root-owned mesh bootstrap is installed baseline.
The first two logout/reboot trials establish the selected ownership boundary;
final-byte crash recovery and the added post-correction reboot establish route
restoration for the exact accepted helper; and both building-network cold
opens prove its corrected data plane. Developer ID signing, notarization,
trusted distribution/update and broader VPN interoperability remain future
work.

### Post-S24 rollback/status audit — 11 August 2026

A bounded review of accepted commit `f92159d` found that one internal helper
transition represented both “the road is unavailable” and “the update failed
but the old road survived.” That made a rejected generation, malformed pending
file, or restored candidate failure clear readiness in the public status even
when the active backend remained live. The durable-promotion branch also
ignored whether reapplying the active backend succeeded, and an immediate
control request could race the startup status read. The Swift diagnosis could
then omit the bounded update outcome. These were status and transaction defects
inside the accepted ownership boundary; the installed helper remained ready
and the S24 lifecycle and data-plane evidence above remained valid.

The correction separates ready, last-outcome and unavailable transitions. A
pre-mutation refusal leaves the ready active generation untouched and adds a
bounded outcome. Candidate or rename failure reapplies the active
specification exactly once, reports `rollback restored` only after that apply
succeeds, and otherwise reports non-ready `interface unavailable` while
retaining recovery evidence. A non-durable candidate is never published as
active. Startup prints the manager status before the control server begins
accepting, and the Swift verdict now evaluates artifact/PID authority,
configured non-readiness, generation/digest authority and bounded outcome in
that order. The superseded permissive `WireGuardConf` diagnostic parser and
its unreachable checks were deleted; strict legacy import remains the only
reader of the preserved rollback file.

Rootless deterministic verification passed the focused manager matrix, the
complete Go race suite three times in 2.517 seconds, and `go vet`. The focused
Swift status/intent/doctor matrix passed 51 tests across five suites three
times. ReachKit passed all 79 tests in 8/8 fresh runs. A warnings-as-errors
release hashes to `6d6ce6add00ee395ea927fdb434b4594ef11c5257156c0f2723163ecc751c1dd`
with CDHash `24d8462e518997aeba184c1e09b47c6443f9c0b1` and exactly seven adjacent
resource bundles. The normally signed universal Simulator Example and signed
generic-iOS Keeper linkage builds succeeded without a Keeper source change.

The staged scriptless package still has exactly the helper and LaunchDaemon
plist and no scripts. The helper hashes to
`8ac3705b3eeac878693eb921c946b24c9ce6a6a97b90371debef2519611420d3`
(CDHash `ecb4fb7e62adef0f9dc3653d2741c17064280b2e`), the source plist to
`6a8ee41852db26e7b41c3f2d976fdabba06cd6e6a3e77d8838470f07a38761df`,
and the package to
`8f0a77a6181cdee4dbad7df6d1421da5650086e25567be5350cf352e3f4ffc77`.
The one-byte plist difference from the installed hash is only the installed
copy's extra trailing blank line; parsed policy, payload ownership and modes
are unchanged. Helper/config/status versions and JSON field sets are unchanged.
No installed binary, process, route, root state or login service was changed by
this rootless checkpoint.

The accepted reachd matrix passed 198 tests in 29 suites in 8/8 fresh scratch
runs. One additional attempt while the macOS console was locked failed before
the assertions because complete file protection denied two temporary-state
writes; after unlock, those exact two guards passed together 3/3 and the
replacement full run passed 198/198. The staged release then passed the real-
weight MLX spine both at its canonical path and through an installed-style
symlink with no resources beside the alias. Each invocation passed
unconstrained sampling 3/3 and guided schemas 15/15 and reported positive
usage. Metal compiler `32023.921` remained available, `git diff --check` was
clean, and no superseded `WireGuardConf` or unreachable diagnostic symbol
remained. These results complete rootless acceptance; installed replacement,
restart, apply, identity and diagnosis checks remain separately authorized.

Founder-authorized installation then replaced the two accepted units under one
complete rollback guard at
`/private/tmp/reach-mesh-fixes-installed-backup-20260811`. The installed helper
hashes to
`8ac3705b3eeac878693eb921c946b24c9ce6a6a97b90371debef2519611420d3`
and the canonical daemon to
`6d6ce6add00ee395ea927fdb434b4594ef11c5257156c0f2723163ecc751c1dd`.
The scriptless package retained its two payload files and no scripts. An
idempotent generation-3 apply preserved public digest `540d0724…f03`, and one
controlled helper termination changed its PID to 88852 while restoring one
peer, `utun0`, `10.86.0.1/24`, the connected `/24` route, MTU 1280 and UDP
51820. The login daemon independently restarted as PID 89336 and retained UDP
47337. The superseded mode-0600 staging specification was removed after apply;
durable intent and active state were unchanged.

Installed `service status` and doctor agreed on mesh-owner PASS. Authenticated
`doctor --dial` opened a session over loopback in 53 ms with 15 pass, three
expected mapping/pin warnings, zero waiting and zero fail; the earlier
`SecPKCS12Import -25291` fault did not recur. Canonical and `~/.local/bin`
alias invocations each passed the MLX spine, sampling 3/3 and guided schemas
15/15 with positive usage. The four CA/server files, device registry, host
WireGuard keypair and mesh intent remained byte-identical, the CA-creation
count remained zero, and no re-pair occurred. No logout, reboot or phone matrix
was repeated because this correction changed no launch policy, route/backend,
wire or Keeper behavior. **Verdict for those bytes: PASS.** That predecessor
rollback/status contract remains the usable installed baseline.

A post-install review then found three bounded gaps in that candidate: rollback
could still swallow pending-removal or status-publication failure, four strict
diagnostic mismatch returns omitted the retained update outcome, and the direct
orphan-peer warning lacked its own test. The current source delta closes all
three. Go race passes 3/3 plus vet; the focused Swift matrix passes 52/52 once
and full reachd passes 199/199 once.

Founder-authorized exact-byte replacement then installed the reviewed delta
under the complete rollback unit at
`/private/tmp/reach-mesh-review-installed-backup.3jWDXJ`. The installed helper
hashes to
`61d04eebb17b063ac77f0beab7beecc1417af8cc2ca495284e98e49aaf094542`
and the canonical daemon to
`4d2a6f693c74f13904599a02166c10cac9d956b7c8cd520336d84f10fe319ad2`.
The scriptless two-item package hashes to
`589cd9b5f14f142d5e2412bceac4513fcd3d464672e4e87ce2e34b795ecb2625`.
Launchd runs the helper as PID 4622 and the login daemon as PID 4725; generation
3, digest `540d0724…f03`, one peer, ready `utun0`, the connected `10.86.0.0/24`
route and UDP 47337 all survived replacement. Service status reports the mesh
owner PASS.

Three sandboxed doctor attempts reproduced the attributed
`SecPKCS12Import -25291` diagnostic-mint fault; the required unsandboxed
authenticated `doctor --dial` then opened over loopback in 43 ms with 15 pass,
three expected pin/mapping warnings, zero waiting and zero fail. Installed
canonical and `~/.local/bin` alias launches each passed the MLX spine,
unconstrained sampling 3/3 and guided schemas 15/15 with positive usage. The
four CA/server files, device registry, host WireGuard keypair and mesh intent
remained byte-identical, `cluster CA created` remained zero, seven resource
bundles remained adjacent only to the canonical binary, and no re-pair
occurred. No logout, reboot or phone matrix was repeated because this review
delta changes no launch policy, backend/route behavior, wire or Keeper
behavior. **Verdict for the reviewed bytes: PASS.**

## Controlled VPN interoperability matrix — 11 August 2026

This was a measurement pass over the accepted `9bfdd8d` daemon/helper baseline,
not a VPN-product certification. Router-level Proton remained enabled
throughout. Host-local Proton cells were founder-excluded; no router, VPN
profile, Reach wire, Keeper behavior, cluster identity, helper or daemon was
changed. The iPhone's already-authenticated Tailscale profile made the tailnet
arm executable without installation or login.

The fixed cold prompt and long transition prompt were hashed once before the
matrix. Fresh explicit-scratch verification passed ReachKit **79/79** and
`reachd` **199/199 in 29 suites**. The installed control opened an authenticated
loopback session in 38 ms before the matrix and 36 ms after restoration, each
with **15 pass, three expected pin/mapping warnings, zero waiting and zero
fail**.

| cell | measured result | independent road evidence | verdict |
|---|---|---|---|
| C0 | login daemon and root mesh owner retained their accepted PIDs, run counts, generation and one-peer state | physical default remained Slate; exact Reach `/24` remained connected | **PASS** |
| C1 | cold session opened from the phone's Slate-LAN address and reached visible `done` | physical-interface traffic moved while Reach-mesh bytes stayed flat | **PASS — direct LAN** |
| C2 | building-network cold session opened from `10.86.0.2` and reached visible `done` | Reach `utun` gained 62 packets / 15,936 inbound bytes; helper identity did not move | **PASS — first-party mesh** |
| C3 | cellular cold open produced the declared bounded all-roads refusal; no daemon session or generation appeared | private mapped/pinned edge was unreachable; background counters alone were rejected as evidence | **PASS — expected private-edge boundary** |
| C4 | a known-good Slate session completed while the Mac tailnet address was present in authenticated roads | Reach mesh stayed flat and the phone still ran Keeper rather than Tailscale | **PASS — tailnet road learned** |
| C5 | the first attempt was rejected as ambiguous because it was actually another Slate session. After closing Example and proving the phone tailnet peer 3/3, the single clean rerun cold-opened from a `100.x` phone address and reached visible `done` | Mac Tailscale bytes moved materially; Reach mesh stayed exactly flat | **PASS on the permitted rerun — user tailnet** |
| C6 | one long generation began from `10.86.0.2`, held through the iOS provider gap, then the **same generation** reattached from the phone tailnet at sequence **601** and caught up to visible `done` | Reach bytes rose before the switch and froze afterward; Tailscale bytes then rose and its peer answered | **PASS — Keeper to Tailscale** |
| C7 | a fresh long generation began on the tailnet, then the **same generation** reattached from `10.86.0.2` at sequence **563** and reached visible `done` | tailnet peer became unreachable; Reach peer answered and mesh bytes rose materially | **PASS — Tailscale to Keeper** |
| C8–C9 | host-local commercial VPN was deliberately not enabled because Proton already remained the router baseline | no host-profile policy was changed to manufacture another cell | **OUT OF SCOPE BY FOUNDER RULING** |
| C10 | Keeper truth was correct when it showed itself displaced, but iOS selected Tailscale unexpectedly before C2. Later Keeper's in-app Start failed while selecting the same Keeper profile in Settings succeeded. During C6, Tailscale initially remained disconnected after displacing Keeper, adding about 40 seconds before reattach | Settings, provider processes, daemon source, peer reachability and tunnel counters agreed on the eventual active profile | **FOLLOW-UP — profile authority and handoff truth** |

The final restoration returned the phone to Slate with Keeper connected and
on-demand enabled, phone Tailscale disconnected, and Mac Tailscale active in
split-tunnel/no-exit-node mode. The accepted daemon and helper hashes, PIDs,
routes, generation and peer count were unchanged. Example was terminated after
the final cell; no re-pair or CA creation occurred.

At the founder's explicit request during the matrix, Example alone gained a
test convenience: the one-sentence cold prompt is now its default and a compact
menu selects the unchanged long transition prompt. Normal generic Simulator
and generic-device builds passed, and both presets were visually verified on
the signed physical build without changing VPN state. A warnings-as-errors
build isolated an existing Swift 6 implicit/weak-capture warning in the prior
generation code; this measurement pass did not widen into that unrelated
refactor. ReachKit, daemon, wire and Keeper behavior remain unchanged.

**Behavior verdict: PASS for the combinations actually exercised.** Direct LAN,
first-party mesh and an existing user tailnet coexist; cold tailnet sessions
work; and active generations resume in both directions across the iPhone's
single VPN slot. The matrix does not claim host-local commercial-VPN coverage,
cellular ingress, relay behavior or universal VPN-product compatibility. The
observed profile-selection/start/handoff behavior is retained as a focused
Keeper-held follow-up rather than repaired here.

**Acceptance verdict: STOP for a bounded observability gap.** The approved
ledger required a generation ID and initial/final event sequence for every
successful cell. Production logging names a generation only on reattach and
names only that cursor. Cold C1/C2/C4/C5 therefore retain attributable
session/source/counter/visible-done proof but no generation ID or terminal
sequence; C6/C7 retain generation and reattach sequence but no terminal
sequence. Those facts cannot be recovered honestly after completion. A narrow
`PLAN-vpn-interop-evidence.md` follow-up adds privacy-safe begin/terminal
receipts and repeats only C1, C2, C4, C5, C6 and C7. Until that closes, the matrix
is measured behavior rather than a fully retired acceptance record.

## VPN interoperability receipt closure — 11 August 2026

The bounded follow-up closed that stop without changing the wire, roads,
generation behavior, VPN profiles, Keeper, model or public API. `SessionRegistry`
now emits one package-internal accepted receipt only when it creates a new
generation and one terminal receipt only after it stamps the actual
`.finished` event. The stable copy contains random session/generation cursors,
the accepted sequence `0`, terminal sequence, ending category, and one of six
source categories. It contains no address, port, prompt, output, identity,
certificate, token count or raw error text. Duplicate begin, replay-only
attachment, detach/reattach and post-terminal cleanup do not produce another
receipt; an expiry with no wire terminal still produces none.

Five focused receipt tests extended the existing registry matrix across exact
rendering/classification, order, ordinary completion, cancellation, filling
error, duplicate begin, replay, detach/reattach and cleanup. The 18-test focused
suite passed three consecutive runs. Fresh explicit-scratch ReachKit passed
**79/79** and reachd passed **204/204 in 29 suites**. The warnings-as-errors
release hashes to
`b5952c42078dfa6c2eb13e36c943b64fe3125e303b548e87e6938bd0c21912d6`;
generic-Simulator Example and generic-iOS Keeper linkage builds passed. The
staged real-weight spine also passed MLX, unconstrained sampling **3/3**, and
guided schemas **15/15**.

The first installation command exposed a bounded operator fact: the
`--executable` option names the path launchd should execute; it is not a copy
source. That attempt wrote a valid temporary-path plist, launchd refused it,
and the accepted installed inode remained unchanged. The service was then
replaced through the documented verified fresh-directory swap. The accepted
installed executable has the release hash above, exactly seven adjacent
bundles, PID 51546/run 1, both listeners and unchanged cluster state. The four
CA/server files, device registry, mesh intent, identity and WireGuard host key
remained byte-identical to the backup; CA creation stayed zero. Final
authenticated `doctor --dial` opened over loopback in 36 ms with **15 pass,
three expected warnings, zero waiting and zero fail**. The root helper remained
PID 4622, generation 3, one peer and ready on the same Reach `/24`.

The repeated six-cell matrix retained only receipt categories and counter
deltas in the repository; raw endpoints and screenshots remain in the
mode-private ledger. Every accepted receipt precedes exactly one terminal
receipt with the same IDs:

| cell | receipt cursor | route and independent evidence | terminal | verdict |
|---|---|---|---|---|
| C1 — direct Slate cold | session `55A05A32…`, generation `E63ED472…`, `private-lan` at seq 0 | Reach mesh exactly flat; phone Tailscale absent; signed Example screenshot showed the fixed answer | seq 32, complete, visible `done` | **PASS** |
| C2 — Reach-mesh cold | session `A34C65B7…`, generation `639303B9…`, `reach-mesh` at seq 0 | Reach tunnel +54 packets / 17,736 bytes in and +44 / 11,499 out; tailnet phone peer offline | seq 29, complete, founder-witnessed `done` | **PASS** |
| C4 — tailnet-learning control | session `38424DAB…`, generation `04897D6C…`, `private-lan` at seq 0 | Reach mesh flat; Mac tailnet address present in authenticated roads; C5 independently cold-used it | seq 30, complete, founder-witnessed `done`; the retained CoreDevice frame is horizontally displaced and is not accepted as independent UI proof | **PASS** |
| C5 — tailnet cold | session `338801DD…`, generation `2C3CB359…`, `shared-address-space` at seq 0 | tailnet +45 packets / 10,016 bytes in and +67 / 11,357 out; peer active; Reach mesh flat | seq 30, complete, founder-witnessed `done` | **PASS** |
| C6 — Keeper to Tailscale | session `7EA60524…`, generation `8394324C…`, `reach-mesh` at seq 0 | the same generation reattached from tailnet at seq 2223, 2572 and 2944; post-switch tailnet +347 packets / 48,269 bytes in and +1,044 / 231,376 out | seq 3659, complete, founder-witnessed `done` | **PASS** |
| C7 — Tailscale to Keeper | session `2FFC3C2E…`, generation `B2954130…`, `shared-address-space` at seq 0 | the same generation reattached from Reach mesh at seq 908; post-switch Reach tunnel +966 packets / 88,006 bytes in and +1,129 / 161,565 out | seq 2030, complete, founder-witnessed `done` | **PASS** |

CoreDevice becomes unavailable on the building network, so C2/C5/C6/C7 use
the founder's visible terminal report joined to daemon receipts and independent
tunnel evidence; no remote screenshot is claimed for those cells. C1 retains a
fully framed signed-device screenshot. CoreDevice remained available for C4,
but its retained frame is horizontally displaced and does not expose the prompt
or `done`; its hash is preserved as a rejected capture, while the
founder-witnessed terminal UI remains joined to the exact daemon terminal and
counter evidence. This limitation no longer hides a protocol cursor or terminal
sequence.

The exact initial state was restored: Example absent, Keeper's packet tunnel
active with founder-confirmed on-demand intent, phone Tailscale inactive, phone
back on the initial Slate SSID, and Mac Tailscale active without an exit node.
A read-only phone capture corroborated every provider/process fact; it could
not display the Keeper toggle without foregrounding Keeper. Installed parity
and the final authenticated control passed. The original evidenced stop is
therefore **resolved**. Direct LAN, Reach mesh, user tailnet cold-open and both
same-generation VPN-slot transitions now have the complete approved receipt.
The Keeper profile-authority finding remains Held; slot admission is the sole
Now pass.

## S25 — concurrent provider-slot admission, 12 August 2026

S25 first measured the unmodified `acb723b` runtime through a disposable fake
registry and the cached Gemma 4 E4B weights. Four begins entered both the
separate-session and same-session fake filling simultaneously (`peak=4`). The
real filling did not have one concurrency shape: short ordinary decoding
overlapped after serialized preparation, while guided and tool work advanced
in staggered, effectively serialized passes. Four 25,000-word prefills ended at
8.460, 15.070, 21.392 and 27.669 seconds. Nothing crashed, corrupted output or
failed typed decoding, so the selected model-neutral one-generation contract
remained admissible.

| warmed shape | before wall | admitted wall | outcome |
|---|---:|---:|---|
| ordinary ×1 | 0.144 s | 0.164 s | complete; within run-to-run noise |
| ordinary ×4 | 0.359 s | 0.489 s | four complete; one filling call at a time |
| guided ×4 | 1.542 s | 4.811 s | four typed completions |
| allowed tool ×4 | 2.428 s | 6.654 s | four constrained calls complete |
| required tool ×4 | 1.286 s | 4.629 s | four required calls complete |
| 25,000-word prefill ×4 | 27.669 s | 29.336 s | four complete; preparation was already serial |

The admitted run prewarmed in 3.778 seconds. Its process RSS was 4.65 GiB after
prewarm and 4.69 GiB at the end. MLX reported 4.044 GiB active after prewarm,
a 5.349 GiB peak, and 4.046 GiB active at the end; the recorded cache high-water
was 21.016 GiB. The passing test required the built `default.metallib` beside
the scratch executable, directly exercising the Metal backend. A first test-
bundle launch without that adjacency failed before model work and was
attributed to the scratch layout, not admission.

After implementation, every four-request batch observed exactly one public
filling call with one active reservation and three FIFO waiters. Cancelling the
active real-weight generation promoted the oldest waiter, which completed;
the counters ended with two admitted and one cancelled. Deterministic actor,
registry and QUIC tests separately proved FIFO order, a fifth immediate
`cluster-busy`, one waiter per session, a 120-second timeout without filling
execution, duplicate-begin idempotency, active and queued re-attach, replay-
only release, and reuse of the same authenticated session after overload.

**Verdict: PASS, with the serial-capacity tradeoff deliberate.** Single-request
latency remains unchanged within measurement noise, while concurrent guided
and tool requests now exchange accidental overlap for bounded FIFO latency.
One lease covers the complete public generation and all of its internal model
passes; no dialect, frame, persisted queue or public client queue API was
added.

Focused admission, registry and loopback coverage passed three complete runs
at 14 tests in four suites. Fresh full products then passed ReachKit **79/79
eight of eight** and reachd **218/218 in 33 suites eight of eight**. A known
cold-open timing sentinel crossed its bound once while eight full products
were competing for the host, then passed three isolated repetitions without a
threshold change; two rejected back-to-back attempts also exposed fixed-port
contention and a terminal-receipt observation race. The latter was a real
ordering defect: the registry now commits the terminal state and receipt before
yielding the terminal event, and its focused reproducer passed 3/3.

The final tree adds one explicitly gated installed-host test, so its default
inventory is 219 tests in 34 suites. A fresh audit passed every admission suite
and found only the same cold-open timing sentinel at 40.341 seconds under the
full concurrent runner. With that already-attributed sentinel selected out,
the other **218/218 in 34 suites passed in 49.290 seconds**; the sentinel then
passed immediately in isolation **3/3 at 11.131, 10.978 and 10.776 seconds**.
Its 10-second budget and 2x failure bound remain unchanged. Full-suite load
also showed that an end-to-end QUIC promotion can arrive after 1.5 seconds even
when the admission actor has already promoted it correctly (observed at 3.955
seconds), so only that integration test's observation allowance became ten
seconds. The deterministic actor deadlines stayed unchanged, and the focused
wire suite passed 3/3 after the calibration.

The warnings-as-errors release had SHA-256
`19462f3e4069aac8fe698a8f778cbf5165b419d95046c03e57436f9c0b65798b`
and retained exactly seven adjacent resource bundles. Generic-Simulator
Example and generic-iOS Keeper linkage builds passed. Installed acceptance
used five simultaneous, separately authenticated loopback clients against the
supervised exact release: four completed and the fifth received the exact
`cluster-busy` refusal. The daemon recorded one active lease, FIFO positions
one through three, one refusal without a generation receipt, promotions after
7.240, 13.349 and 19.143 seconds, and complete terminal sequences 577, 496,
472 and 475. It ended at active zero and waiting zero without restarting.

Installation preserved all four CA/server fingerprints, the device registry,
the WireGuard host keypair, mesh intent and zero CA creation. The canonical
agent remained healthy as PID 82151/run 1, both listeners were present, and an
authenticated installed `doctor --dial` opened a loopback session in 41 ms
with **15 pass, 3 expected mapping/pin warnings, 0 waiting and 0 fail**. The
complete previous eight-item installation remains recoverable from the guarded
pre-replacement backup. A later read-only closeout spot-check reproduced the
known host `SecPKCS12Import -25291` diagnostic-identity fault on four bounded
attempts after that successful dial. No installed byte, daemon, listener or
identity moved; the accepted gate is the actual 41 ms authenticated session,
not the later warning, whose recurrence remains an attributed machine fault.

### S25 post-review correction

Two review rounds found three bounded defects in the otherwise accepted
admission pass.
The end-to-end QUIC test had assumed that sequential sends on separate streams
established daemon admission order; one clean run admitted `1,0,2,3`, proving
that assumption false. The test now sends and observes the active generation
before it admits each waiter, so it tests the FIFO actor rather than
Network.framework scheduling. Review also found that queued cancellation
could publish `.cancelled` before an unawaited task removed its reservation.
The daemon now awaits queued-reservation removal before making the terminal
visible, and a regression immediately begins a replacement generation from
the same session with no yield or retry. The second review then forced the
remaining actor-reentry edge: cancellation removed a queued reservation while
reattach bumped the generation epoch. A committed queue removal now finishes
the current streaming record across that epoch change; an active or otherwise
uncommitted cancellation still requires the original epoch. A deterministic
barrier test proves the reattached stream receives `.cancelled`, the registry
does not remain streaming, and the filling never executes the removed work.

The corrected admission/registry/QUIC set is **17 tests in five suites** and
passed three complete focused runs. A fresh full-suite attempt reached every
admission test but was blocked by 11 unrelated CA fixtures: Foundation refused
every `.completeFileProtection` write with `NSCocoaErrorDomain 513` / POSIX
`EPERM`. A standalone probe reproduced the same failure in both the Darwin
user temporary directory and `/private/tmp`, establishing a host protection
or keybag fault rather than an admission regression. The prior 79/79 ReachKit
and 218/218 reachd repetitions remain the last complete-suite baseline; this
follow-up does not pretend the blocked audit passed.

The fresh warnings-as-errors release is arm64, ad-hoc linker-signed, retains
exactly seven adjacent bundles, and has SHA-256
`b3db694d8069bd81357fa41d2cc2558c22d97457cb5900ec28a95e93a4f69cd5`.
Founder-authorized guarded replacement installed those exact bytes with the
prior eight-item unit recoverable at
`/private/tmp/reach-slot-followup-install-backup.v0XdaT`. The supervised daemon
returned as PID 29122/run 1 with both UDP listeners. The gated five-client
acceptance then completed four generations and refused one full-room request
in 25.669 seconds. An unsandboxed authenticated `doctor --dial` opened over
loopback in 38 ms with **15 pass, 3 expected mapping/pin warnings, 0 waiting
and 0 fail**. Two preceding sandboxed attempts reproduced
`SecPKCS12Import -25291`; the immediate unsandboxed success identifies that
instance as the diagnostic process boundary rather than an installed-daemon
failure. All four CA/server hashes, the device registry, mesh intent and
WireGuard host keypair remained byte-identical to the pre-install manifest;
the CA-creation count remained zero.

The closeout remains deliberately phone-free. First- and middle-waiter
cancellation under real weights, active and queued reattachment over every
physical road, and repeated cold-load trials were proposals in the exploratory
draft, not acceptance work that was performed. The founder ruled the measured
fake/real provider matrix plus deterministic transport-independent lease tests
sufficient; this record claims exactly that boundary and no larger matrix.

## S26 — exact volatile replay capacity, 13 August 2026

**Before.** The old store estimated payloads and advertised a 4 MiB
per-generation bound. Disposable encoding probes showed why that was not a
storage contract: an empty text event encoded to 87 bytes, 1 KiB text to
1,111, a 1 MiB structured delta to 1,048,664, a 1 MiB tool-argument event to
1,048,699, usage to 86 and terminal events to 77–181 bytes. Crossing the old
bound discarded sequences 0–3 and retained only a later suffix; re-attach from
inside that hole correctly refused. Four old-style resident windows raised RSS
by approximately 4.90, 10.11, 15.30 and 20.50 MiB. Replay lookup itself was
about 0.1 ms. Nothing crashed or corrupted typed output, so S26 licensed a
memory-only capacity correction rather than persistence or a wire change.

**Selected contract.** `ReplayStore` retains the deterministic complete
encoded `Ev` frame plus a sequence index. One generation may retain exactly
one maximum v0 frame including its four-byte prefix: **16,777,220 bytes**.
The process budget is exactly four windows: **67,108,880 bytes**. Cumulative
acks release exact bytes. Per-generation or process pressure may reclaim only
the appending generation's prefix; no generation can evict another. Live
delivery continues after pressure, while a re-attach that asks inside a lost
prefix receives the existing refusal. Stored frames are decoded and checked
against their indexed sequence before serving; corruption clears and refuses
that window. Queued work has emitted nothing and consumes zero replay.

The store is deliberately volatile. It writes no prompt, output or tool
argument to disk; shutdown clears all windows, and daemon restart retains the
existing legible lost-generation behavior. Detached residency remains 120
seconds and completed replay remains 600 seconds. An individual event larger
than the wire's 16 MiB envelope limit is replaced at the same sequence by a
small terminal error, never reported as successful incomplete output.

**After.** Real Gemma 4 E4B runs detached, completed, and replayed ordinary,
guided, allowed-tool and required-tool generations whole. Prewarm was 3.397 s
at 4,646,174,720 bytes RSS. Their exact retained replay totals were:

| route | elapsed | events | exact replay bytes | outcome |
|---|---:|---:|---:|---|
| ordinary | 0.755 s | 33 | 2,381 | complete and whole |
| guided response | 1.661 s | 22 | 1,543 | typed, complete and whole |
| allowed tool | 1.541 s | 3 | 356 | constrained call, complete and whole |
| required tool | 1.108 s | 3 | 354 | required call, complete and whole |

Every registry returned to zero replay bytes on shutdown. Repeating S25 on
the new store preserved one filling call, three FIFO waiters, immediate fifth
refusal and cancellation promotion across ordinary, guided, allowed, required
and long-prefill shapes. Process RSS moved from about 4.63 to 4.67 GiB and MLX
peaked at 5.351 GiB; single-generation performance remained within the
measured run-to-run range.

Final exact store coverage is **16/16 at 3/3**. The replay/registry/QUIC matrix
passed 34 tests at 3/3 before the final counter-reporting correction; the
correction added a simultaneous per-generation/process crossing test and the
complete exact-tree suite exercised it. ReachKit passed **80/80 at 8/8**.
The final exact reachd tree passed **238/238 in 36 suites at 7/8**. The eighth
run's only issue was the existing cold-open timing sentinel at 41.36 s; in
isolation it then passed at 10.85 and 11.07 s and reproduced at 42.63 s. Its
10-second budget and 20-second defect threshold were not weakened. No replay,
registry, admission, framing or MLX test failed.

Warnings-as-errors release, generic-Simulator Example and generic-iOS Keeper
builds passed. The installed release SHA-256 is
`89080e0168262ec7e3e831d9ce897022716b06ccd03a47aa113ba21610ed1b2d`
with exactly seven adjacent bundles. Guarded replacement preserved all four
CA/server hashes, the registry, mesh intent, WireGuard host keypair, helper
hash and zero CA creation. Launchd returned as PID 72852/run 1. Five installed
clients completed four generations and refused one full room in 25.506 s.
The canonical installed self-test passed ordinary MLX, unconstrained sampling
3/3 and guided schemas 15/15. Authenticated `doctor --dial` opened in 43 ms
with **15 pass, 3 expected mapping/pin warnings, 0 waiting and 0 fail**. The
complete prior eight-item unit and state remain recoverable at
`/private/tmp/reach-replay-install-backup.MnEnnN`.

### S26 post-review correction

Post-install review found that the exact counter was not yet an exact physical
bound. `Window.popFirst()` advanced an array head but left each removed
frame's `Data` owned by the backing array until metadata compaction after at
least 256 removals. A matching probe could therefore retain 64 MiB while the
counter reported 1 MiB; maximum frames made the gap much larger. Popping now
replaces the frame payload with empty `Data` before advancing the head. A
backing-storage invariant test turns over 64 approximately-1-MiB frames below
the compaction threshold and compares physically owned payload bytes with
`currentBytes` after every capacity drop and acknowledgement.

The same review found a release-classification mismatch: an admitted event
larger than the wire limit was replaced by `.finished(.error)`, but admission
still derived its outcome from the original event. `ingest` now returns the
ending of the event it actually stamped and published. The admitted oversized
regression observes both the client error terminal and the privacy-safe
`released ... after error` transition, with no completion transition.

The corrected ReplayStore suite passed **18/18 at 3/3**. Fresh complete suites
then passed ReachKit **80/80** and reachd **240/240 in 36 suites**. The first
post-review artifact, SHA-256 `6f01b9fb…d85c`, passed behavioral checks but was
rejected as a release: its Xcode request synthesized
`CLANG_COVERAGE_MAPPING=YES`, its Mach-O carried `__llvm_*` profiling and
coverage sections, and running it wrote a 7,527,000-byte `default.profraw`.
That generated file was removed and is not part of the repository.

A fresh-DerivedData Release rebuild disabled coverage mapping, test coverage
files and flow-arc instrumentation explicitly. The accepted warnings-as-errors
binary has SHA-256
`da7f3cf93b398e51192b23cd68eae7533cee65c364e46d43399b5388b84f3fd8`,
no `__llvm_*` or coverage sections, and exactly seven adjacent resource
bundles. Direct execution and the installed checks created no `.profraw`.
Founder-authorized guarded replacement installed those exact bytes. The
rejected artifact, state and guard material are recoverable at
`/private/tmp/reach-replay-clean-install-backup-20260813`; the pre-replay
complete unit remains recoverable at
`/private/tmp/reach-replay-install-backup.MnEnnN`. Launchd returned as PID
6118/run 1 with both listeners and a prewarmed model. The first five-client
run completed all four admitted generations daemon-side but one client lost
its generation stream during transport reattachment; one clean rerun completed
four and refused one full waiting room in 25.393 seconds. Authenticated
`doctor --dial` opened over loopback in 38 ms with **15 pass, 3 expected
warnings, 0 waiting and 0 fail**. The four CA/server hashes, device registry,
mesh intent, WireGuard host keypair, helper and plist remained byte-identical;
CA creation remained zero.

**Verdict: PASS.** Exact bounded replay is now baseline M3 capacity; it is not
generation durability. A resident generation still dies with the daemon, so
process durability is the next separate design pass.

## S27 — exact public-generation durability, 13 August 2026

**Question and stop rule.** S27 asked whether the pinned MLX stack could
restore one public generation exactly across process death on all four shipped
routes: ordinary, guided response, allowed-tool proposal/replay, and required
tool call. A raw KV cache, completed replay alone, or recovery of only the
ordinary route did not qualify. The required state was the same generation
identity and committed event prefix, the same sampler and usage trajectory,
the same grammar or tool-call identity, and no repeated visible output or tool
effect. The source and installed baseline was clean `16e47df`; the installed
coverage-clean daemon remained SHA-256 `da7f3cf9…3fd8`, and the dependency was
the pinned `mlx-swift-lm` revision `83f3ef6…`.

**Provider-state inventory.** The dependency can save and load the model's
`[KVCache]`, but that is only part of an executing generation:

| route | serializable part | state that is not a restorable public checkpoint |
|---|---|---|
| ordinary | caller-owned raw KV tensors | Reach uses the convenience iterator without owning a checkpoint; iterator token, sampler/RNG, logit processor, detokenizer, `LMOutput.State`, usage and event cursor are not one serializable unit |
| guided | raw model KV could be saved separately | opaque grammar matcher position, model state, detokenizer, accepted-token count, closing/whitespace policy and usage remain local to `GuidedGenerationLoop` |
| `.allowed` | no exact multipass checkpoint | incremental proposal parser, buffered prose, selected calls, candidate arguments, generated call IDs, replay grammar state and accumulated probe/replay usage are separate local values |
| `.required` | no exact structural checkpoint | all-tools structural matcher, sampler state, accepted envelope, generated call identity, detokenizer and usage are local and non-Codable |

An external compile probe confirmed that `TokenIterator.cache` is not public;
`LMOutput.State` contains private heterogeneous state and is not Codable;
`GrammarConstraint` exposes an in-process clone, not an encoded matcher; and
`ToolCallProcessor` owns private parser buffers and completed-call queues.
These gaps exist before the first event, after visible output, around a tool
call, and after terminal publication before acknowledgement. The selected stop
therefore fired for every route without attempting to invent a second Reach
schema compiler, persistent transcript, worker, or wire protocol.

**Raw-cache measurement.** A disposable real Gemma cache probe produced 24
cache layers and a 2,930,234-byte safetensors file after 64 tokens. The retained
raw rerun loaded the model in 2.710 seconds. Three save plus `F_FULLFSYNC`
trials were 8.978, 6.267 and 7.008 ms; three loads were 0.961, 0.856 and
0.854 ms. The saved metadata was
empty, so the file did not bind itself to the model revision. More importantly,
both a half-truncated file and a middle-bit-flipped file were accepted by the
loader and each produced a further token. That is useful cache machinery, not
a durable execution or integrity contract. Stale writers, revision mismatch,
rollback, duplicate begin, cancellation and expiry consequently have no
provider-owned transaction authority to reconcile.

**Synthetic encrypted-storage envelope.** Private synthetic bytes and an
ephemeral AES-GCM key measured storage cost only; all payload files were
deleted after the run. Values below are three trials in milliseconds:

| plaintext | encrypted bytes | seal | exclusive write + `F_FULLFSYNC` | read + decrypt |
|---|---:|---|---|---|
| 65,536-byte request | 65,564 | 2.042 / 0.017 / 0.024 | 4.798 / 5.081 / 4.664 | 0.171 / 0.120 / 0.080 |
| 16,777,220-byte replay window | 16,777,248 | 3.850 / 2.775 / 2.937 | 10.871 / 11.684 / 11.207 | 6.571 / 6.942 / 7.482 |
| 67,108,864-byte synthetic checkpoint | 67,108,892 | 14.986 / 11.843 / 11.891 | 34.946 / 32.262 / 32.072 | 28.136 / 30.417 / 31.886 |

Storage latency is not the blocking fact. The missing boundary is a complete,
versioned, integrity-checked provider state plus an explicit privacy and
retention contract for content that Reach intentionally does not persist.

**Tool-effect probe.** A harmless synthetic client-owned tool used a
`flock`-serialized private counter. Synthetic loss before delivery left it at
0; executing the delivered call before returning synthetic generation loss made
it 1; explicitly asking again executed the effect again and made it 2. The
daemon cannot infer whether an already delivered call ran, and call identity is
generated inside the lost process. Exactly-once tool effects would need a
client acknowledgement/idempotency contract, not a KV-cache file.

**Installed launchd crash.** Four authenticated clients first established the
required one-active/three-waiter state. While the explicit kill checkpoint was
being confirmed, the original active generation completed at sequence 1558
and the oldest waiter was promoted. The single authorized `SIGKILL` therefore
actually struck one active plus two queued generations; this timing is retained
rather than rewritten as the intended shape. Launchd replaced PID 6118/run 1
with PID 29485/run 2. The promoted active generation ended with the existing
legible lost-answer sentence. The two clients that had seen no generation
event resent their unchanged IDs after opening fresh sessions; the empty new
daemon accepted each at sequence 0 and re-executed them to sequences 2225 and
2320. The already completed generation remained complete. Admission and replay
state restarted empty, proving that launchd service recovery is not public-
generation durability.

A fresh authenticated generation then completed against the restarted daemon.
The CLI diagnostic reproduced the known `SecPKCS12Import -25291` process fault
three times across this pass, with no other doctor failure; the private scratch
client supplied the actual authenticated-session proof. Installed bytes, CA
and server certificates, device registry, and WireGuard host public key remained
byte-identical, and the CA-creation count remained zero.

**Verification.** The restart/admission/replay/tool/error focused set ran 49
tests in seven suites. Its one immediate fake-execution assertion was a real
test race, not a product failure: it now waits for the asynchronously scheduled
execution exactly as the subsequent assertions already did. The repaired exact
test passed **3/3** in 24, 24 and 22–23 ms. After that repair, the complete
reachd tree passed **240/240 in 36 suites**; the pre-repair complete ReachKit
tree remains **80/80** because no ReachKit source changed. The private evidence
pack retains the raw cache/storage/tool transcripts, probe and test source
snapshots, a self-contained patch-record reconstruction of the overwritten
executed crash harness, the immutable crash-log slice, launchctl state,
installed/identity hashes, and both verification transcripts. The client and
daemon records independently prove the four-client crash behavior; the
reconstruction is not described as a contemporaneous snapshot. No product,
dependency, persistence, wire, service, Example, Keeper, or installed byte
changed.

**Verdict: EVIDENCED STOP.** The pinned provider cannot serialize the exact
execution state of any shipped route, and the client-owned tool boundary makes
partial durability actively misleading. Reach retains the existing sentence:
“the answer stopped partway and cannot be picked up again … Asking again
starts a new one.” Future durability is Held behind a resumable-provider and
at-rest privacy ruling; volatile transport replay and launchd recovery remain
the honest shipped mechanisms.

## S28 — locally derived structured snapshots, 13 August 2026

**Question and boundary.** S28 asked whether an explicit structured-partial
wire event would add a current product capability beyond the typed snapshots
Foundation Models already derives from streamed grammar-constrained JSON. The
selected boundary prohibited a second parser, side API, persistence, frame or
dialect change. Source began synchronized at `8135c93`; installed reachd stayed
at SHA-256 `da7f3cf9…3fd8` and the root helper at `61d04eeb…4542` throughout.

**Public SDK surface.** The retained Swift-interface excerpts show that a
response snapshot already exposes both typed `content` and `rawContent`, while
`GeneratedContent(json:)` accepts incomplete JSON. The executor channel can
append/replace text, emit custom segments, attachments, metadata, usage and
tool-call actions. It has no public action that accepts a server-authored
`GeneratedContent`. A wire partial would therefore coexist with the text stream
and introduce a second cadence and authority rather than replace an unavailable
local surface.

**Synthetic matrix.** A disposable executor streamed every Unicode scalar of
deterministic two-field, nested, enum, fixed-array, optional-present,
optional-omitted and adversarial JSON, three times each. Every fragment and
typed/raw snapshot retained field visibility, completion, generation id,
ordering and duplicate/coalescing behavior. Snapshot counts varied for
equivalent final values: two-field 10/10/11, nested 11/11/12, enum 5/5/5,
fixed-array 8/8/7, optional-present 18/14/14, optional-omitted 10/11/12, and
adversarial 29/33/34. The framework's snapshot cadence is useful application
state, not a stable protocol clock.

**Real-weight matrix.** Cached `gemma-4-e2b`, ephemeral identities and the
shipped TLS/QUIC/wire/daemon/guided path completed **21/21
TLS/wire/daemon/guided executions** in 24.487 seconds. This describes the
transport and guided execution, not semantic success of every named arm. All
three original optional-present prompts omitted the optional property. The
real adversarial output described a closing brace and quote without emitting
the literal characters. Synthetic typed evidence covers both missing local
surfaces; no unavailable structured information was revealed.

A separate correction made the optional property required through a custom
schema, streamed `GeneratedContent`, observed `"optional":"later"`, and
decoded the final value into the optional type **3/3** in 7.103 seconds. This is
the narrower claim: it does not demonstrate real-weight
`OptionalValue.PartiallyGenerated` streaming under the original optional
schema.

**Candidate payload lower bounds.** The authoritative population is 18 primary
semantic runs plus the three corrected optional runs; the original three
optional omissions are explicitly excluded. Whole-value and JSON-Pointer
set/remove candidates replaced arrays whole where identity was unavailable.
The values below are **candidate structured payload bytes at observed snapshot
cadence**, compared with 690 bytes of compact canonical final JSON:

| candidate | bytes | ratio |
|---|---:|---:|
| whole value at every observed snapshot | 7,398 | 10.722x |
| duplicate-suppressed whole values | 3,426 | 4.965x |
| JSON-Pointer set/remove patches | 4,437 | 6.430x |
| duplicate-suppressed patches | 4,251 | 6.161x |

These are modeled payload lower bounds, **not measured wire traffic**. They
exclude envelope framing, event and generation ids, sequence metadata and all
other protocol overhead. Patch operations and byte counts were modeled but not
implemented, reapplied or verified; S28 makes no replay-codec correctness
claim. Old peers already retain the exact text-only behavior.

**Verification and retained authority.** Response guidance passed **5/5 at
3/3**. Fresh complete suites passed ReachKit **80/80** and reachd **240/240 in
36 suites**. A first full reachd attempt inside the managed sandbox reproduced
the known keychain `SecPKCS12Import -25291` fault; the same already-built suite
passed with normal keychain access. Installed and identity hashes remained
unchanged, CA creation remained zero, and launchd remained PID 29485/run 2.
Final authenticated `doctor --dial` opened over loopback in 36 ms with **15
pass, 3 expected mapping/pin warnings, 0 waiting and 0 fail**.

The private pack `/private/tmp/reach-s28.5FB49W` was reduced from approximately
3.9 GiB to 908 KiB by removing reproducible builds, checkouts, module caches,
duplicate metallibs and the interrupted focused product. It retains exact
sources, successful transcripts, SDK excerpts, authoritative analysis,
explicitly labeled failures/exclusions, runtime hashes, a README and a verified
manifest. `SHA256SUMS` has SHA-256
`01c8076fb372588e6214346c57af549a963dfd4d344a6ef9e18b7a491369363f`.

**Verdict: EVIDENCED STOP.** Foundation Models' locally derived snapshots are
the current authoritative structured surface. Explicit wire partials remain
Held until either a real non-Foundation-Models consumer needs them or the
framework exposes a public structured executor action. No product or installed
byte changed, and nothing is promoted to Now without a separate founder ruling.

## S29 — portable reference-hub forwarding core, 13 August 2026

**Question and boundary.** S29 asked whether the selected single-cluster relay
hub could enforce host/device ownership and forward actual WireGuard-encrypted
traffic entirely in userspace, without root, a host TUN, a VM, a Linux runner,
Reach credentials, product integration or an external endpoint. Source began
synchronized at `50ae87e`; installed reachd remained SHA-256
`da7f3cf9…3fd8` and the root mesh helper remained `61d04eeb…4542` throughout.

**Offline graph ruling.** The new module uses Go 1.23.1 and the mesh helper's
existing `wireguard-go` revision `f333402bd9cb`. Isolated caches began with the
already verified graph. Four exact missing transitive objects—`wintun`,
`google/btree`, `x/time`, and gVisor—were downloaded to scratch only after
founder authorization; every returned module and `go.mod` checksum matched the
existing `mesh-helper/go.sum`. Full `go list -m all` would have required a large
unused Kubernetes/container tooling closure declared by gVisor. The founder
therefore narrowed the gate to the actual imported build/test graph. With
`GOPROXY=off` and `GOSUMDB=off`, `go list -deps -test ./...`, `go mod verify`,
all tests, vet and both builds then completed wholly offline.

**Encrypted proof.** A disposable topology created independent synthetic host,
hub and device WireGuard instances. The hub used the proposed custom bounded
TUN router; standard `wireguard-go` bound wildcard UDP sockets on unused high
ports. Three runs completed device-to-host delivery and the host reply, observed
handshakes and directional counters, found neither inner payload in captured
outer datagrams, rejected spoofed, device-to-device, unknown, fragmented,
over-MTU and over-capacity packets, and returned from one goroutine to one with
all sockets and queued payloads released. One retained timed 3-run execution
completed in **1.59 s real / 0.09 s user / 0.20 s system**. This was synthetic
private traffic, not a Reach session or public relay.

**Implemented core.** The isolated `relay-hub/` module now contains:

- strict version-1 configuration, exact key agreement, canonical ordinal
  ownership, route-overlap checks, generation ordering and frozen hub instance
  fields;
- a 256-packet/256-KiB router with exact IPv4 ownership, independent count and
  byte bounds, immediate payload release, quiescence and an in-flight
  barrier;
- one standard-bind WireGuard backend whose complete desired manifest becomes
  an exact peer diff: unchanged peers are untouched, while an address-changing
  peer is removed, verified absent and re-added so staged traffic cannot cross
  ownership;
- a serialized last-known-good manager that closes forwarding through peer
  mutation, verification, active-file promotion and router-snapshot install;
  only the durably promoted active specification survives a crash, while
  crash-left pending bytes are discarded, and a same-generation readiness
  retry revalidates the complete peer manifest plus matching open router gate;
- privacy-safe status with role/ordinal handshake age and byte counters but no
  keys, addresses, endpoints, identities or packet content; and
- a scriptless systemd/sysusers/tmpfiles/payload definition that remains
  uninstalled and unproved on Linux.

The real-backend update test additionally preserved an unchanged peer's live
endpoint/handshake/counter trajectory, changed another peer's `/32`, proved a
pre-change staged packet did not escape after remove/re-add, and then forwarded
fresh traffic under the new ownership. Transaction hooks injected packets at
every manager stage; only pre-quiescence and post-reopen snapshots admitted
them. Rollback restored configuration authority while explicitly not claiming
lost runtime state for recreated peers.

**Verification.** The complete hub suite, including the real encrypted backend
test, passed **3/3**. A review-found same-generation readiness gap was repaired:
focused manager/router tests passed 3/3 while directly drifting and restoring
the backend manifest, closed router gate and mismatched ownership snapshot.
The final package timings for the complete three repetitions were command
0.091 s, backend 1.655 s, config 0.166 s, manager 2.897 s, router 0.406 s,
status 0.157 s and package-manifest checks 0.093 s. The final
race-detector run passed every package; `go vet` was clean and `go mod verify`
reported every module verified. Fresh
Reach regressions passed ReachKit **80/80** and reachd **240/240 in 36 suites**;
the initial sandboxed ReachKit keychain failures were attributed to denied
Keychain access and the already-built suite passed with normal access. Final
authenticated `doctor --dial` opened over loopback in 59 ms with **15 pass, 3
expected mapping/pin warnings, 0 waiting and 0 fail**; installed hashes, PIDs,
run counts and the direct mesh remained unchanged.

Two clean static cross-builds per architecture were byte-identical. The final
Linux amd64 SHA-256 is
`fe99fa7585c07c10084c219880adc607c476014e026868987bf41223e8600571`;
the final Linux arm64 SHA-256 is
`cbd0cdd1fa0d29340234893bdd53e377f2bfdb3a18f928c131ea63e7800d76c4`.
Both are static ELF executables and contain no local `/Users` path. These hashes
describe cross-build artifacts, not an installed Linux service.

**Verdict: PASS FOR THE PORTABLE CORE.** The hub can forward encrypted traffic
and own only its bounded relay role. No operational relay, Reach road, dialect,
host state, Keeper provisioning, Linux installation, firewall, namespace,
restart, update, teardown, external service or public-uplink claim follows from
that result. The next slice remains gated on an existing Linux runner or
separate founder authority; absent either, the roadmap has no active Now item.

## S30 — the unprivileged hub forwarded on native Linux arm64, 13–14 August 2026

**Question and boundary.** S30 asked whether the committed portable hub could
become a truthful Linux service without becoming a privileged network
appliance. Source began synchronized at `912a4f0`; ReachKit, reachd, the macOS
mesh helper, Keeper, the phone, router, wire and installed runtime were outside
the pass. The founder authorized one disposable VM, not a public endpoint.

**Pinned runner.** Lima 2.2.0 ran one native-VZ `aarch64` Ubuntu Server 26.04
LTS guest from release image `20260731`, SHA-256
`3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba`.
The plain VM had two CPUs, 4 GiB RAM and a 30 GiB disk, with no mounts,
containerd, Rosetta, GUI, dynamic forwarding or host-home exposure. It used
only the declared networking, WireGuard, nftables, JSON and package tools;
accepted builds and runtime cells ran after guest egress was blocked.

**Pre-edit gate.** The exact committed arm64 binary
`cbd0cdd1…76c4` passed S30.0 **3/3** under real systemd as the dedicated
unprivileged account. In each run Linux kernel WireGuard peers established
handshakes and exchanged traffic in both directions through the userspace hub;
the service held zero effective or ambient capabilities, used the wildcard
IPv4/IPv6 bind, and cleaned up completely. The original pre-edit transcripts
were lost with a later guest reboot, so the same exact committed hash was run
3/3 again after teardown solely to retain raw transcripts. That retention run
does not substitute a different implementation for the pre-edit gate.

**Linux additions.** The candidate adds:

- strict root/`reach-relay` ownership and mode-`0640` checks for both operator
  files, including no-follow, regular-file, single-link and exact GID rules;
- a versioned route inventory unioned with read-only netlink routes from every
  IPv4 table, with kernel-sender, socket-port, sequence, multipart-completion,
  truncation, interruption and overrun validation, plus privileged-port refusal
  before backend mutation;
- a package-internal decode policy applied at startup and every reload;
- serialized `SIGHUP`, `SIGUSR1`, TERM and INT handling, bounded refusal that
  preserves a healthy generation, live-authority status refresh, and removal
  of the historical state-directory status file;
- volatile mode-`0600` status at `/run/reach-relay-hub/status.json`;
- a hardened systemd unit for the dedicated account with shell-free
  `ExecReload`, exact mode-`0700` state/runtime directories, zero capabilities,
  fixed memory/task/FD/core bounds and the syscall filter proved by the real
  matrix; and
- a deterministic maintainer-script-free Debian package containing only the
  binary, unit, sysusers/tmpfiles declarations, licenses/notices and route
  documentation. Its actual data/control archives are checked against the
  manifest, including a mode-`0755` archive root and mandatory route document.
  It installs inertly and authors no configuration, key, firewall, fixture or
  state.

**Accepted L0–L12 matrix.** The final linear run produced these outcomes:

| cells | result |
|---|---|
| L0–L3 | pinned native runner and offline provenance; byte-reproducible A/B packages; inert install; unsafe owner, group, mode, hard-link, symlink, malformed/oversized data, privileged port and route conflicts all refused; hardened non-root start was ready with PID 3009 and zero capabilities; `systemctl reload` and exact state/runtime modes were verified |
| L4 | host↔device forwarding completed **3/3**, with matching Linux-kernel handshakes/counters and privacy-safe per-peer hub counters |
| L5 | device isolation, spoofed source and unknown destination were refused; the unconditional wildcard-port drop advanced independently for a denied source on allowed ingress, a genuinely separate interface, loopback IPv4, loopback IPv6 and injected real-`eth0` ingress while every hub peer counter remained byte-identical; valid forwarding remained available |
| L6 | generation 2 moved device 3 from relay ordinal/address 3 to 4 without changing PID; unchanged-peer runtime stayed monotonic, the recreated peer re-established, the old route stopped and status named the exact promoted generation/digest |
| L7 | seven invalid reload classes reported `update refused`, retained PID and forwarding, restored both operator files, and survived a controlled restart from the restored disk authority |
| L8–L9 | three `SIGKILL` recoveries and two distinct guest reboots returned only the promoted generation, firewall and both forwarding directions under systemd |
| L10 | B→A→B ran the exact intended executable/unit hashes, preserved compatible active authority, re-established forwarding after each controlled restart and finished on B |
| L11–L12 | service/package, operator state, firewall, namespaces, account, listener and payload were removed; the VM and mutable disk were deleted |

**Maximum-capacity addendum.** Review found that L3 had recorded the fixed
resource policy without starting the real service at the schema maximum. A
bounded addendum therefore recreated the same pinned VM, rebuilt the exact B
package twice at `252c490a…3775`, and started the installed hardened unit with
253 devices plus the host. Status reported generation 1 ready with **254/254**
peers. At the accepted snapshot the unit used 12,070,912 of 268,435,456 cgroup
memory bytes, 8 of 128 tasks and 10 of 1,024 file descriptors;
`LimitCORE=0`, every capability set was empty, `NoNewPrivileges=1`, and
seccomp mode 2 was active. The service identity was refused when it attempted
link, route, network-namespace and nftables mutation; none of the four objects
appeared and readiness remained true.

The same PID then applied generation 2's host-plus-two-device manifest. The
real Linux-kernel peers re-established handshakes and forwarded in both
directions **3/3**, with every per-peer receive/transmit counter increasing.
Package, unit, listener, fixtures, firewall, offline policy, account and
operator/runtime state were again absent before VM deletion. Lima's graceful
host-agent stop later hung on its own UDP-proxy cleanup; because guest teardown
and extraction had already passed, a targeted forced deletion removed only the
disposable VM and mutable disk. This was infrastructure teardown, not a service
or forwarding failure.

The accepted B arm64 executable is
`e5060d14…06a6`; two B package builds matched at
`252c490a…3775`. The compatibility A packages matched at
`3abbafdb…cf89`. A static amd64 binary reproduced twice at
`4b10c7d4…e8cc`, but it did not execute on an amd64 kernel and is not runtime
acceptance.

**Correction and evidence honesty.** Review invalidated the first pack's
firewall, unit, netlink and package-manifest claims, so it is superseded rather
than reused. The corrected attempt ledger retains six bounded harness failures:
an overlong interface name, an over-strict netlink-header sender assumption, a
frame that Linux classified `PACKET_OTHERHOST`, one stale peer-counter baseline,
and a reboot that removed the disposable `/tmp` runner before the host began
restoring and hash-checking it. Only run 7 is authoritative. No failed run was
rewritten into the accepted matrix.

The corrected private pack
`/private/tmp/reach-relay-linux-evidence-authoritative` contains **188 files**
and 22.9 MB; its complete manifest validates. Its artifacts are exactly five
unique byte sets retained once each: A arm64 binary/package and B arm64
binary/package plus the cross-build-only B amd64 binary. The exact corrected B
package is present. It retains sanitized manifests, command records, hashes,
bounded logs, status/counters, excluded-attempt labels, capacity receipts and
exact source snapshots. It contains no raw operator configuration, generated
key, UAPI key output, packet capture/payload, Reach identity, prompt, generated
content or external endpoint. Earlier material is classified beneath the one
top-level superseded pack; no stale third evidence authority remains.

**Post-teardown verification.** Focused Linux packages passed **3/3**; the
complete hub suite passed **3/3**; race, vet and offline module verification
passed. Linux arm64 and amd64 static cross-builds reproduced twice. Fresh
complete regressions passed ReachKit **80/80** and reachd **240/240 in 36
suites** after attributing one sandbox-only Keychain refusal. Installed reachd
remained `da7f3cf9…3fd8` at PID 29485/run 2 and the root helper remained
`61d04eeb…4542` at PID 4622/run 3. Final authenticated `doctor --dial`
reported **15 pass, 3 expected mapping warnings, 0 waiting and 0 fail** in
32 ms. No installed Reach byte or identity changed.

**Verdict: PASS FOR LINUX ARM64 RUNTIME/PACKAGING.** The private reference
substrate now has measured systemd, ownership, routing, firewall, reload,
recovery, rollback and teardown truth. No operational relay ships: a host relay
intent/helper integration, negotiated relay roads, Keeper-held device
provisioning, endpoint refresh, public operations and physical multi-NAT
acceptance all remain ahead. Lima and the exact pinned image cache remain only
as declared developer tooling; the VM does not.

## S31 — one Darwin WireGuard interface retained direct traffic while relay authority changed (14, 19, and 20 August 2026)

S31 began from synchronized `a251da8`; the installed daemon and helper remained
the accepted pre-pass bytes `da7f3cf9…3fd8` and `61d04eeb…4542`. Launchd
reported one login daemon at PID 1033/run 1 and one root helper at PID 530/run
1. Intent and helper status were direct-only generation 3 with one peer on
`utun0`; the interface retained `10.86.0.1/24`, MTU 1280 and no relay block.
The CA creation count remained zero. A real authenticated loopback session
passed before tracked implementation.

The disposable root harness used synthetic keys, unused ports and a scratch
interface only. Two initial 3/3 attempts timed out because the harness first
recreated its backend and then changed its relay route set without forcing the
hub peer to re-handshake. Those were harness defects, not accepted product
evidence. The corrected source hashes to `56b02410…239d`; its test binary hashes
to `95144703…4bae`; and the authoritative transcript hashes to
`426525fc…b05`.

The final founder-run matrix passed **3/3** in 10.25, 10.52 and 10.48 seconds.
Every trial proved, on the same `utun8` interface:

| stage | measured result |
|---|---|
| direct baseline | encrypted direct traffic passed and the direct peer's runtime state was retained |
| relay add | relay alias, exact route set, hub peer handshake and traffic passed |
| endpoint-only update | hub endpoint changed in place; direct peer remained unchanged |
| route-set update | hub peer was recreated, re-handshook and carried only the new `/32` ownership |
| injected failure | prior full authority was restored; direct traffic remained available |
| relay removal | alias, relay routes and hub peer were absent; direct state still passed |

The implementation keeps intent/specification version 1 byte-compatible and
adds strict optional relay version 2. Login-owned relay commands change intent
only; the existing apply command remains the visible administrator boundary.
The helper computes an exact peer diff, quiesces only relay paths, verifies
complete peer/address/route state, durably promotes before ready, and reports
separate direct/relay components. The daemon quarantines relay and other
same-interface IPv4 addresses from every v0 calling card while continuing to
use all local addresses for listener certificates and diagnostics.

Focused Swift relay tests passed **23/23 in two suites, 3/3**. Fresh complete
products then passed ReachKit **80/80** and reachd **249/249 in 36 suites**.
The complete helper suite, race detector, `go vet`, and isolated offline module
verification passed. Warnings-as-errors generic-Simulator Example and
generic-iOS Keeper builds also passed after two semantics-preserving current-
compiler capture spellings: `[weak self = self]` in Example and the vendored
WireGuard adapter. These are linkage/compiler corrections, not Keeper behavior.

The final warnings-as-errors daemon release is exactly eight adjacent items.
Its executable hashes to `f948301a…ca10`, passes strict signature verification,
and contains no LLVM profiling sections. The final scriptless helper package
contains only the ad-hoc-signed helper and unchanged LaunchDaemon plist: helper
`c494ad01…2de0`, plist `6a8ee418…61df`, package `1027ae12…b1`. The earlier
pre-install daemon/package hashes were superseded by these fresh verified
artifacts and were never the accepted installed authority.

**Guarded installation and local acceptance.** The founder re-earned the exact
real-backend transaction **3/3** on `utun7` in 10.45, 10.61, and 10.35 seconds;
the retained transcript hashes to `961a9d9f…302`. One coherent backup captured
the prior eight-item daemon layout, helper package/state, canonical intent,
registry, host key, logs, and four identity hashes before mutation. The daemon
was replaced first and the scriptless helper second. The installed acceptance
then passed every stage without restarting reachd:

| installed stage | result |
|---|---|
| direct authority baseline | same helper-owned interface, direct digest/count, address and route verified |
| relay add and idempotent reapply | alias, exact routes and hub peer carried attributable synthetic traffic; repeated apply made no authority change |
| endpoint-only update | hub endpoint changed in place while direct authority remained exact |
| prefix / AllowedIPs update | relay path quiesced; hub peer was recreated, re-handshook and carried only the new ownership |
| overlap refusal | unsafe candidate was refused and direct authority remained ready |
| helper crash | launchd restarted only the helper and recovered the promoted authority |
| complete removal | final generation 7 became canonical v1 direct-only; relay alias, route and hub peer were absent |

The installed transcript hashes to `fe28e06f…94c9`. Scripted selftest passed;
real MLX passed; unconstrained sampling passed **3/3**; guided schemas passed
**15/15**. The required unsandboxed `doctor --dial` passed on its first attempt,
opening an authenticated loopback session in 40 ms with **15 pass, 3 expected
mapping warnings, 0 waiting and 0 fail**.

Several bounded installer attempts remain attributed rather than rewritten as
success: a pseudo-terminal did not inherit the sudo timestamp; compact v1 JSON
defeated a whitespace-sensitive harness check; a scratch peer incorrectly
cloned the live phone key and lost to WireGuard's newer timestamp authority;
raw JSON key order defeated a final direct-authority comparison; and one final
diagnostic wrapper called nonexistent `/bin/print`. Each mutated attempt restored
the complete prior authority. The last two product matrices had already passed
every relay stage; only their closeout harnesses failed. The final harness uses
structural intent comparison and fixed-path `printf`, with direct unit coverage.

Final installed reachd is `f948301a…ca10` at PID 44462/run 19. The helper began
at PID 44498, was deliberately killed by acceptance, and launchd recovered it
at PID 44630/run 3 on `utun0`. Helper status v2 reports generation 7, direct
ready with one peer, and relay configured false/ready true (verified absent)
with zero address, routes, or hub peers. Registry `75d9dbf9…0def`, host public key
`99526d11…a1d`, CA `03a08c64…c737`, and server certificate
`15302bb6…d5af` are unchanged; the post-backup daemon-log segment contains no
CA-creation event. The accepted evidence and recoverable prior authority remain
under `/private/tmp/reach-s31-authorized-install-20260819` and
`/private/tmp/reach-s31-installed-backup-20260819`.

**Post-review exact-byte repair, 20 August.** Review found three places where
the accepted design was not yet the durable/fail-closed implementation. The
Keeper compiler spelling lived only as dirty vendored bytes; exact helper-v2
diagnosis discarded route-inspection failure; and Darwin relay removal named
only a destination, so drift could let it delete another interface's route.
The vendored capture correction is now commit `6dfd5389…f6797b` on the
submodule's `origin/reach` branch and the parent gitlink names that commit. A
fresh recursive candidate checkout built generic-iOS Keeper with warnings as
errors. Exact v2 diagnosis now fails closed when path evidence is unavailable,
while the old address-only fallback remains only for helper-status v1. Relay
teardown takes one ownership snapshot, refuses a route that moved to another
interface before mutation, deletes with the helper interface named explicitly,
and verifies absence from a final snapshot.

The apply acknowledgement received the adjacent bounded repair: the five-
second budget now covers request delivery, not an arbitrarily large completed
transaction. Once the helper accepts `apply`, the client waits for its
authoritative terminal response; an explicit `error` is a refusal, whereas a
lost transport reports unknown outcome and tells the operator to inspect
status. Per-command Darwin subprocesses remain bounded. A synthetic maximum
253-route update passed 3/3 in more than the former five-second budget with
constant route-table inspections, and a moved-route regression proved zero
mutation. The v2 fail-closed diagnostic regression also passed 3/3. Fresh
complete products passed ReachKit **80/80** and reachd **249/249 in 36
suites**; the complete helper suite, race detector, `go vet`, offline module
verification, generic-Simulator Example WAE build, and the recursive-clean
Keeper WAE build passed. The submodule working tree is clean.

The first follow-up release is coverage-clean reachd `266e29ec…148e2`, still one
executable plus seven adjacent bundles. The scriptless helper is
`90032ba4…35fc7`; its unchanged plist is `6a8ee418…61df`, and package
`e9c95d57…96206a` contains only those declared two payload files. Guarded
installation reran the local add/update/refusal/crash/removal matrix on those
exact bytes and passed every stage, ending at canonical v1 generation 11 with
all direct fields and the one direct peer byte-for-byte equal to the generation
7 baseline. One closeout guard initially compared unordered JSON dictionary
bytes and stopped after that valid matrix. Field-by-field comparison proved
generation was the sole change; the remaining nonprivileged gates then ran in
the login context rather than treating key order as authority.

Final installed reachd is `266e29ec…148e2` at PID 86352/run 21. The helper is
`90032ba4…35fc7` at PID 86534/run 5 after its deliberate acceptance crash.
Status v2 reports generation 11 on `utun0`, one direct peer, direct ready, and
relay configured false/ready true with zero address, routes, or hub peers.
Scripted selftest passed, real MLX passed, guided schemas passed **15/15**, and
the authenticated dial passed on its first login-context attempt in 36 ms with
**15 pass, 3 expected mapping warnings, 0 waiting and 0 fail**. Registry, host
public key, CA and server certificate remain unchanged; the post-backup log
segment contains zero CA-creation events. The 14-entry follow-up evidence
manifest hashes to `5c650cf5…0fd8`; evidence and the complete prior authority
remain under `/private/tmp/reach-s31-followup-installed-evidence-20260819` and
`/private/tmp/reach-s31-followup-installed-backup-20260819`. A separate
17-entry source-verification manifest hashes to `38e6db57…1503` and retains
the fresh focused/full test transcripts, warnings-as-errors linkage builds,
coverage-clean release receipt, and helper package receipt without caches or
failed-attempt noise. The top-level manifest-of-manifests, including the
attributed installer/resume transcripts, hashes to `dfc726d1…92d8`.

**Final claimed-authority and route-owner correction, 20 August.** The last
review found that the applying client—not the long-lived owner—held
`apply.lock`. If that client disappeared while a backend transaction was
blocked, a later client could replace `pending.json`; promotion or rollback
could then operate on bytes other than the candidate already in memory. The
owner now atomically renames pending authority to a distinct mode-0600
`applying.json`, syncs the private directory, and performs every read,
promotion, rollback and cleanup against only that claimed artifact. Startup
resumes a claimed generation before considering a newer pending generation.
The adjacent Darwin teardown correction now refuses any final route owner,
including a foreign interface that appears after the interface-qualified
delete; it neither reports absence nor drops its bookkeeping in that case.

Four focused authority/route regressions passed **3/3**: a blocked generation
with an interrupted client and newer pending generation, rollback isolation,
claimed-before-pending startup order, and foreign ownership appearing after
delete. The complete helper suite and race suite passed, as did `go vet` and
offline module verification. The corrected ad-hoc-signed helper is
`1963f1d3…233d`; its plist remains `6a8ee418…61df`; and scriptless two-payload
package `eb6f0f8b…0a33` contains those exact bytes.

The installed interruption test then proved the authority order directly.
Generation 12 was claimed, its client was killed, generation 13 was staged as
a separate pending artifact, and the root owner was killed. Launchd recovery
promoted generation 12—not 13—while preserving 13 for the subsequent apply;
cleanup returned to canonical v1 direct-only generation 14. The same exact
helper bytes then repeated the complete add/idempotent/endpoint/route-set/
refusal/crash/removal matrix and ended at canonical v1 generation 18. Both
pending and claimed artifacts were proven absent before and after acceptance.

At that review checkpoint, installed reachd remained `266e29ec…148e2` at
unchanged PID 86352/run 21. The claimed-authority helper was
`1963f1d3…233d` at PID 7746/run 8 after the two deliberate crash recoveries.
Status v2 reported generation 18 on `utun0`, one
direct peer, direct ready, relay configured false/ready true, and zero relay
address, routes or hub peers. Registry, host public key, CA and server
certificate remain byte-identical; CA creation remained zero. Authenticated
`doctor --dial` passed on attempt 1 in 35 ms with **15 pass, 3 attributed
mapping warnings, 0 waiting and 0 fail**.

The 23-file private evidence pack is
`/private/tmp/reach-s31-authority-fix-evidence-20260820`; its manifest hashes
to `5848c851…150f`. It includes exact private harness sources, immutable
installed transcripts, pre/final runtime evidence and hashes, but no keys,
identities, prompts or output. The complete prior accepted authority is
recoverable at `/private/tmp/reach-s31-authority-fix-backup-20260820` and is
deliberately excluded from the evidence manifest because it contains secrets.

**Final request-bound acknowledgement correction, 20 August.** The last review
found that the local control request said only `apply`, while startup correctly
processed a surviving older claim before a newer pending specification. A
newer invocation could therefore receive `ok` for the older transaction and
print that its own generation was accepted while its bytes remained pending.
The request now carries the exact expected generation and public digest. The
owner may finish one older surviving claim, but returns success only after the
requested authority itself is active; otherwise that generation remains staged
and the client reports a bounded non-success. The operator executable exposes
only that closed set of privacy-safe apply outcomes. Backend, filesystem, key,
address, endpoint and raw internal errors remain opaque.

Focused protocol/authority tests passed **3/3**, followed by the complete
helper and race suites, `go vet`, and offline module verification. Three fresh,
coverage-clean builds reproduced ad-hoc-signed helper
`a784f257…b28ca8`; CDHash `45797020…529e`. The clean scriptless package
`b206d993…60d2a` reproduced twice and contains only that helper plus unchanged
plist `6a8ee418…61df`, with no LLVM profiling sections or installer scripts.
One first exact-byte installed attempt correctly withheld success for the
newer generation but revealed that the executable still collapsed the safe
staged outcome to generic `operation failed`; it rolled the complete authority
back to generation 18. A later nonprivileged preflight stopped before password
entry or mutation because `pkgutil` listed the two valid payload directories in
the opposite literal order. Both are retained as attributed harness/copy-
boundary evidence rather than product acceptance.

The final installed acknowledgement regression forced generation 19 to remain
claimed after a pre-backend status-publication failure, staged generation 20,
and proved the second invocation acknowledged generation 20 only after 20 was
active; cleanup returned to canonical direct-only generation 21. The same
exact helper then repeated the full add/idempotent/endpoint/route-set/refusal/
crash/removal matrix and ended at canonical v1 direct-only generation 25.
Reachd remained `266e29ec…148e2` at PID 86352/run 21 throughout. Launchd
recovered the deliberately killed helper as PID 26821/run 3. Status v2 is ready
on `utun0` with direct digest `10187412…4fa5`, one direct peer, relay configured
false/ready true, and zero relay address, routes, hub peers, pending or claimed
artifacts. Registry, host public key, CA and server certificate remain exact;
CA creation remained zero. Authenticated `doctor --dial` passed on attempt 1
in 35 ms with **15 pass, 3 attributed mapping warnings, 0 waiting and 0 fail**.

The final private 22-entry top-level evidence manifest hashes to
`ab7e4f08…ce0f1` under
`/private/tmp/reach-s31-ack-fix-v3-evidence-20260820`; its `install.log` entry
was resealed after the script appended its final four success lines, and every
entry verifies. The complete accepted generation-18 authority remains
recoverable at `/private/tmp/reach-s31-ack-fix-v3-backup-20260820`; it is
excluded from the evidence manifest because it contains secrets.

**Verdict: PASS FOR HOST RELAY OWNERSHIP.** Login intent and the root helper can
now own optional host relay state on the existing interface without turning it
into a v0 road or disturbing direct ownership. No client can yet learn or dial
that relay; negotiated relay vocabulary, persistence and hedging remain the
next bounded pass. Keeper, a public hub, external service, router and phone
remain outside S31.

## S32 — negotiated relay roads and the corrected direct grace (20 August 2026)

**Baseline and measurement gate.** S32 began from synchronized `8a29d02` with
installed reachd `266e29ec…148e2`, unchanged helper `a784f257…b28ca8`, helper
status v2 generation 25 direct-ready/relay-verified-absent, and unchanged four
identity/registry hashes. A genuine authenticated baseline dial passed in
109 ms with **15 pass, 3 expected mapping warnings, 0 waiting and 0 fail**;
sandboxed `SecPKCS12Import -25291` attempts were diagnostic-only and did not
substitute for it.

The first private scratch gate used ephemeral identities, unused ports, one
disposable daemon and deterministic impairment proxies. Each delay ran three
times through healthy-direct/healthy-relay, stalled-direct/healthy-relay,
failed-relay/healthy-direct, all-failed, and same-generation reattachment:

| configured relay hedge | healthy direct preferred | stalled direct reached relay | failed relay preserved direct | all failed under one deadline | maximum observed relay start |
|---:|---:|---:|---:|---:|---:|
| 0 ms | 3/3 | 3/3 | 3/3 | 3/3 | 0.031 ms |
| 100 ms | 3/3 | 3/3 | 3/3 | 3/3 | 106.757 ms |
| 250 ms | 3/3 | 3/3 | 3/3 | 3/3 | 266.760 ms |
| 500 ms | 3/3 | 3/3 | 3/3 | 3/3 | 527.072 ms |

That fixture called 0 ms the first qualifying value, but its relay path carried
an artificial 40 ms delay. Post-install review reran the exact scheduler with a
healthy 20 ms direct and an immediate relay; 0 ms selected relay, proving that
task-admission order is not deterministic direct preference. The earlier
compatibility, persistence, failure, removal and reattachment results remain
valid, but the 0 ms selection and exact-byte closeout are superseded.

The bounded correction compiled the exact `TieredRoadRace.swift` with a
disposable synthetic timing harness and repeated all candidates three times:

| configured relay hedge | healthy 20 ms direct beat immediate relay | stalled direct reached relay | failed relay preserved direct | all failed under one deadline | invalidated proven direct reached relay | maximum observed relay start |
|---:|---:|---:|---:|---:|---:|---:|
| 0 ms | 0/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0.076 ms |
| 100 ms | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 106.829 ms |
| 250 ms | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 264.416 ms |
| 500 ms | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 518.181 ms |

The first qualifying positive value is therefore **100 ms**. Zero is honestly
fastest-authenticated-road behavior; 500 ms misses the declared start bound.
The production scheduler now uses 100 ms, and an authenticated cached dialer is
eligible only while its session remains reusable. The correction pack is
`/private/tmp/reach-s32-direct-grace-evidence-20260820`; its raw matrix hashes
to `554d50c0…b0dead`.

**Implementation boundary.** The JSON dialect set is now `[1, 0]` over the
unchanged envelope ALPN `reach/0`; no frame or framing changed. Selected v1
adds optional `HelloAck.relayRoads`: omission preserves the separate relay
Keychain record, `[]` clears it, and nonempty replaces it. Selected v0 ignores
the field and leaves relay persistence untouched. Direct `roads`, legacy
`addrs`, pairing addresses, and certificates retain their existing direct
semantics. Relay candidates use the same tiered race for cold dialing and
reattachment, declarations are committed only by the current authenticated
road epoch, and `relay-overlay` attribution is derived from configured host
intent rather than a hardcoded prefix. Keeper, helper, enrollment, router and
public-infrastructure behavior are unchanged.

One separately attributed build-graph correction is included in the exact S32
daemon bytes: reachd passes `traits: []` to the pinned `mlx-swift-lm`
dependency so its unused default Foundation Models adapter is neither compiled
nor linked. Reach still links the container loader, LLM, guided-generation and
MLX products it names directly. This is SDK-build-surface hardening, not relay
behavior; warnings-as-errors release and Example/Keeper linkage builds are its
acceptance gate.

Focused wire/store/race/daemon suites passed ReachKit **39/39** and reachd
**38/38**, three fresh runs each. Complete ReachKit passed **94/94** eight
times; reachd passed **250/250 in 36 suites** eight times. The warnings-as-
errors release, generic-Simulator Example and generic-iOS Keeper linkage guard
passed. The complete eight-item candidate is coverage-clean reachd
`66836721…1d398`, CDHash `8c1a8186…898a8`; Keeper source and helper bytes did
not change.

**Attributed bridge correction.** The first guarded installed attempt stopped
and restored the complete prior authority because the scratch bridge emitted a
synthetic inner IPv4 packet without its header checksum. After that was fixed,
the host received the request but a wildcard reply selected a direct source;
the relay router correctly refused it. Binding the reply to the relay alias
proved bidirectional encrypted request/response **3/3** in 0.03, 0.02 and
0.02 seconds without changing installed Reach. The corrected proof transcript
hashes to `117b3a35…6360`. The corrected retry remained bound to the exact
candidate and harness; no failed attempt was relabeled as product success.

**Installed compatibility matrix.** The corrected guarded retry replaced only
the complete eight-item daemon layout, used the unchanged local helper plus a
disposable relay/device, and passed seven cells in 30.516 seconds:

| cell | authenticated source / transition | session | generation | sequence evidence |
|---|---|---|---|---|
| exact v0 client | loopback | `5F3B4F30…BE45` | `56EEBE97…0953` | 0 → 32 complete |
| v1 replace / direct-first | loopback | `039E812E…642F` | `2B2D66DD…C917` | 0 → 32 complete |
| helper mismatch / preserve | loopback | `CD720A48…1684` | `36EF9369…12BC` | 0 → 32 complete |
| relay-only cold open | `10.87.41.2`, `relay-overlay` | `FDFE28C4…0466` | `4F09EA7A…FB17` | 0 → 32 complete |
| direct → relay | loopback → `relay-overlay` | `E5CD71C1…F59D` | `62ED9AE6…DE6E` | accepted 0; reattached after cursor 0; terminal 1025 |
| relay → direct | `relay-overlay` → loopback | `9C3F6C6B…1BAB` | `A28BA65D…2D55` | accepted 0; reattached after cursor 0; terminal 1025 |
| explicit clear | loopback | `0398BE6D…668B` | `DCF5C1F0…5264` | 0 → 32 complete |

The transitions were deliberately cut immediately after the first event, so
their cumulative reattach cursor is exactly 0; each resumed strictly after
that cursor and reached terminal sequence 1025 under the same generation ID.
The immutable daemon segment contains exactly one accepted and terminal receipt
per generation plus both matching reattachment categories. Independent
controller counters corroborated every leg: direct bytes stayed flat during
relay-only, relay bytes advanced there, both moved on their respective
transition legs, and the clear cell ended at generation 31 with relay verified
absent. The exact backed-up v0 binary authenticated against the v1 daemon on
attempt 1.

Final installed reachd is `66836721…1d398` at PID 26798. Helper
`a784f257…b28ca8`, its plist, Keeper, registry `75d9dbf9…0def`, host key
`99526d11…a1d`, CA `03a08c64…c737`, and server certificate
`15302bb6…d5af` are unchanged; CA creation remained zero. Helper status v2 is
generation 31 on `utun0`, direct ready with one peer, relay configured false
and ready true with zero address/routes/hub peers. Scripted and MLX selftests
passed. Final authenticated `doctor --dial` passed on attempt 1 in 34 ms with
**15 pass, 3 expected mapping warnings, 0 waiting and 0 fail**.

The accepted installed evidence is
`/private/tmp/reach-s32-authorized-retry-20260820`; its four-file immutable
matrix manifest hashes to `f92a02e7…adf5`, and all entries verify. The complete
prior authority remains recoverable at
`/private/tmp/reach-s32-installed-retry-backup-20260820` and is excluded from
the evidence manifest because it contains secrets.

**Post-install review verdict (superseded): REOPENED FOR CORRECTED EXACT-BYTE
ACCEPTANCE.** The first installed matrix remained authoritative for
negotiation, persistence, attribution and transitions, but not for the claimed
0 ms direct preference or the invalidated-session fast path. It therefore did
not retire S32.

**Post-review direct-preference correction checkpoint.** The exact scheduler
rerun above selected 100 ms and focused race coverage passed **7/7** in three
fresh products. Complete ReachKit passed **95/95** in 8/8 fresh products;
reachd passed **250/250 in 36 suites** in 8/8. A fresh warnings-as-errors arm64
release is coverage/profile clean, produces no `.profraw`, stages exactly one
executable plus seven bundles, and hashes to `a9660a83…6b790` with CDHash
`69b54c8c…a1f9f`. Generic-Simulator Example and unchanged generic-iOS Keeper
linkage builds passed with coverage disabled. The release build contains
`MLXLLM`, `MLXLMCommon`, `MLXHuggingFace`, and `MLXGuidedGeneration` targets,
but no `MLXFoundationModels` adapter target. Scripted selftest, unconstrained
sampling 3/3, guided schemas 15/15, and the MLX spine passed from the staged
eight-item layout.

The corrected disposable controller hashes to `2ec3de4d…f42af`; the client
test binary rebuilt from the exact current ReachKit source plus its explicitly
sealed nonshipping impairment seam hashes to `1fc0a7ea…c6749`. Source,
candidate, and harness manifests verify.

**Corrected exact-byte installed acceptance.** The first authorized invocation
stopped before any product replacement because the sealed and regenerated
source manifests contained the same 29 path/hash pairs in different line
orders. The failed preflight and empty backup were retained with an explicit
`preflight-order-mismatch` suffix. The guard was corrected to compare sorted
manifests; it was not bypassed and no source or candidate byte changed.

The guarded retry installed only the complete eight-item daemon layout and
passed the same seven cells in **30.383 seconds**:

| cell | authenticated source / transition | session | generation | sequence evidence |
|---|---|---|---|---|
| exact v0 client | loopback | `1D58BE23…8B1E` | `A7870FB9…6BFD` | 0 → 32 complete |
| v1 replace / 100 ms direct-first | loopback | `490F6095…C7DB` | `4DF3A37A…FADA` | 0 → 32 complete |
| helper mismatch / preserve | loopback | `AC80D8BB…B7D3` | `9EE87910…5DB9` | 0 → 32 complete |
| relay-only cold open | `10.87.41.2`, `relay-overlay` | `E5892555…4B50` | `2AD2A7EA…4B50` | 0 → 32 complete |
| direct → relay | loopback → `relay-overlay` | `E40B526B…9417` | `4DDA80E7…975C` | accepted 0; reattached after cursor 0; terminal 1025 |
| relay → direct | `relay-overlay` → loopback | `27455CB5…9C69` | `DC5D8471…EE07` | accepted 0; reattached after cursor 0; terminal 1025 |
| explicit clear | loopback | `27E4BFC4…C7D1` | `F8820BC3…127B` | 0 → 32 complete |

The immutable daemon segment contains exactly one accepted and terminal
receipt for every generation and the exact raw/category evidence for both
reattachments. Independent controller counters kept relay bytes flat for the
direct cells, direct bytes flat for relay-only, advanced the selected lens on
each transition, and ended at helper generation **37** with relay configured
false/ready true and zero relay address, routes or hub peers. The exact backed-
up v0 binary authenticated on attempt 1. Scripted and MLX selftests passed.

Final installed reachd is coverage-clean `a9660a83…6b790`, CDHash
`69b54c8c…a1f9f`, at PID 21242 beside the canonical seven bundles. Helper
`a784f257…b28ca8`, its plist, Keeper, registry `75d9dbf9…0def`, host key
`99526d11…a1d`, CA `03a08c64…c737`, and server certificate
`15302bb6…d5af` are unchanged; CA creation remained zero. Final authenticated
`doctor --dial` passed on attempt 1 in **36 ms** with **15 pass, 3 expected
mapping warnings, 0 waiting and 0 fail**.

Three immediate post-closeout diagnostic repeats then reproduced the known
`SecPKCS12Import -25291` identity-mint warning. They did not move runtime state
and do not replace or weaken the retained genuine 36 ms authenticated pass.

The corrected installed evidence is
`/private/tmp/reach-s32-correction-authorized-install-20260820`; its four-file
immutable manifest hashes to `432b9123…73fdd`, and every entry verifies. The
complete prior authority remains recoverable at
`/private/tmp/reach-s32-correction-installed-backup-20260820` and is excluded
from that manifest because it contains secrets. Its pre-install source manifest
necessarily predates this closeout: the four documentation entries now differ,
while all 23 package, product, and test source entries remain exact.

**Verdict: PASS — S32 RETIRED.** ReachKit and reachd now use authenticated,
separately persisted relay calling cards as a measured 100 ms direct-first
fallback while exact v0 peers remain compatible. This is still not an
operational relay: no public endpoint or provisioned device exists, and Keeper
remains Held. No new Now item is promoted without a separate founder ruling.

## S33 — Mac release distribution kept cluster state out of the package (20 August 2026)

S33 was an architecture/evidence pass. It changed no product, package script,
installed byte, certificate, receipt, service, state, Keeper target or public
artifact. Source, `main` and `origin/main` were synchronized at `7c05914`; the
existing PR #527 merge correction above and unrelated `tasks/` were preserved.

### Baseline and current distribution gap

Installed reachd remained `a9660a83…6b790` at PID 21242/run 29 beside its seven
canonical bundles. Root meshd remained `a784f257…b28ca8` at PID 20190/run 1,
generation 37 on `utun0`, one direct peer and relay verified absent. The helper
receipt remained `systems.reach.meshd` version 1.0.0; that identifier/version
is therefore consumed and cannot name the first new helper package. CA creation
remained zero. Identity and registry parity was checked; the corrected sealed
pack retains counts and outcomes only, not raw identity, state, address or
endpoint material.

Both installed executables are arm64 and ad-hoc signed with no Team ID. The
current keychain exposed **zero** valid Developer ID Application identities and
**zero** valid Developer ID Installer identities. S33 neither requested nor
used one. Four current `doctor --dial` attempts reproduced only the known
diagnostic-side `SecPKCS12Import -25291`; the exact unchanged daemon is joined
to the retained genuine 36 ms authenticated result with **15 pass, 3 expected
warnings, 0 waiting and 0 fail**.

A clean exported-HEAD arm64 release staged exactly reachd plus seven adjacent
bundles. Reachd hashes to `4ab18b72…3dc4`; the complete staged file payload is
61,348,677 bytes. Swift and C warnings-as-errors and coverage/profile exclusion
passed. Four upstream MLX Metal C++17-extension diagnostics remain explicitly
attributed rather than called zero warnings. The clean exported helper is
`c82b425e…dee4`; it differs from the installed Git-checkout build because
ambient Go VCS stamping is not normalized. The package implementation pass
must disable that ambient input or replace it with explicit manifest
provenance and prove two clean builds identical.

Apple's current direct-distribution contract was rechecked against local tools
and primary documentation. A signed installer is the natural container for
multiple components or fixed paths; executable code and installer containers
use distinct Developer ID identity classes; normal notarization requires
Developer ID signing, hardened runtime and secure timestamps, and a supported
ticket can be stapled. None of those credentialed gates was claimed here.

### Selected architecture

S33 selected **one arm64 flat product installer with two mandatory,
separately versioned, scriptless components**:

| component | immutable payload | selected authority |
|---|---|---|
| `systems.reach.host` | `/Library/Application Support/Reach/Host/reachd`, its seven adjacent bundles, release license/notices/non-self-referential payload manifest and `/usr/local/bin/reachd` as one symlink | Installer places root-owned bytes; a named login user later binds the LaunchAgent |
| `systems.reach.meshd` | `/Library/PrivilegedHelperTools/systems.reach.meshd` and `/Library/LaunchDaemons/systems.reach.meshd.plist` | Installer places root-owned bytes; mesh application remains a separate administrator action even if launchd starts the unconfigured KeepAlive process |

The Distribution declares arm64, hides/selects/UI-disables both components,
sets both top-level package references active, disallows customization and has
no scripts. Read-only choice inspection showed that UI disablement alone is not
authority against an explicit choice-change file; later clean-VM acceptance
must prove both payloads and receipts. Host executable mode is 0755;
bundle directories/files are 0755/0644; release metadata is 0644; helper and
plist remain 0555/0644. Numeric BOM inspection proved the intended root:wheel
owners and modes. No login-owned path, cluster state, CA, registry, model,
secret, log, mesh intent, helper active/pending state, Keeper artifact, Linux
relay artifact, build cache or evidence is payload.

The successful nonprivileged probe produced host component
`0e28713d…2ce` and unchanged helper component `466862fe…5b6c`. A corrected
two-build probe produced different unsigned Apple-container hashes
`9e5a1e00…c25b` and `6cbc783c…0939`, while normalized expanded semantics were
byte-identical at `13062790…c7ad`; XAR creation time accounted for the outer
difference. These are synthetic probe bytes, not a release and not hashes
expected to survive later signing.
Expansion found no Scripts or AppleDouble entries. A synthetic alternate-root
A→B→A sequence restored the whole A executable while an independent state
sentinel remained byte-identical. Changed executable, missing bundle and wrong
mode all refused. No Installer was invoked and no live receipt changed.

One combined package wins over split host/helper artifacts because it preserves
the same scriptless user/root boundary while adding a single compatibility and
provenance root. Split artifacts add two public trust chains and a larger
mixed-version window. A containing app/`SMAppService` shell was not materially
superior enough to justify a new product/lifecycle ruling. Package-manager or
source installation may remain an expert convenience but is not the
first-class trust path.

### Authority, provenance and transactions

Installer may place immutable root-owned release data. It never selects the
cluster owner, reads login state, starts reachd as root, creates a CA or applies
mesh intent. After installation, the explicitly chosen login user binds the
same GUI-domain LaunchAgent. The installed KeepAlive plist may start an
unconfigured helper process at reboot; mesh application remains the separate
visible administrator action, and no interface, route or active state may
appear before it.

The manifest authority is acyclic. Embedded `payload-manifest.json` has no
self-entry—its path, type, owner, group, mode, size and hash are all omitted—
and excludes every component/BOM/container/signing/notary/staple hash. An
external `release-provenance.json` records the completed manifest's path, size
and hash plus each later stage: P0 clean source; P1 payload; U1 unsigned-
container semantics; P2
separately Developer-ID-signed executables; P3 Installer-signed container; P4
notarized container plus log; P5 stapled public candidate. Unearned fields are
absent, and no hash is claimed to survive signing or stapling.

The first package must also migrate present reality: inventory and preserve the
unmanaged login-owned eight-item host, refuse `/usr/local/bin`/PATH collisions,
stop only its exact GUI job, install and verify both package components, rebind
that same LaunchAgent to the packaged canonical path, authenticate, and only
then retire the old unit. A second-login clean-guest cell must prove or reject
system-wide one-owner enforcement; any competing authority stops for a product
ruling rather than inventing root-owned owner state.

Updates stop the exact login agent before replacement, verify one complete
compatible host/helper product, reload the helper separately if its bytes
changed, then restart the same user service and reprove identities, zero CA
creation, supervision, selftests and authenticated dialing. A failure keeps the
service stopped until a complete compatible A or B is authoritative. Rollback
restores immutable software only, never state. Downgrade refuses by default.
Uninstall removes package-owned bytes/receipts and separately unloads jobs;
user/root operator state is retained unless its exact targets are separately
authorized for destruction.

The deterministic notice input includes Reach/Apache-2.0, the Reach-authored
helper's file-scoped MIT license, all pinned SwiftPM root and embedded MLX/
xgrammar licenses/notices, Swift Crypto/BoringSSL notice material, the pinned
WireGuard/wireguard-go/Go graph, and the statically linked Go runtime/standard
library. The corrected helper notice identifies both Reach helper code and
wireguard-go as separately attributable MIT code. Keeper, Example,
Linux relay-hub and model weights remain excluded because they are not this Mac
payload. Counsel review of the generated notice presentation and export/
cryptography classification remain explicit open questions, not legal
conclusions or silent release blockers.

### Later acceptance and closeout

The later acceptance rig is a disposable native-arm64 macOS VM created from
one pinned Apple restore image with no host-home share or host keychain/state.
Its matrix covers static provenance, nested signatures, package/notary/staple/
Gatekeeper, fresh install, reboot-before-mesh-application (allowing only the
unconfigured state directories, privacy-safe status and root control socket),
first unmanaged-host
migration, alias/PATH collision, second-user contention, explicit user binding,
mesh application, retained state, A→B/interruption/rollback, component
refusal/downgrade, lifecycle, tamper, uninstall and reinstall. S33 did not
download an image, create a VM, sign, notarize, install or publish anything.

The private 0700/0600 evidence root is
`/private/tmp/reach-s33-release-scope-20260820`; its corrected 31-entry manifest
verifies and `SHA256SUMS` hashes to `d0634bcf…68c6`. It includes the public
installed map, counts-only identity record, redacted runtime/dial result,
shipping/exclusion/notice ledgers, Apple contract, decision matrix, threat and
transaction models, payload-manifest/external-provenance contract, corrected
package-choice/normalization probe, acceptance rig/matrix, follow-on ledger and
privacy-scanned successful build transcripts. Raw diagnostics, user paths,
private state, labels, endpoints, identity material and superseded failures are
not retained.

**Verdict: S33 COMPLETE — ARCHITECTURE BASELINE ONLY.** The selected contract
is unreimbursed M4 baseline. `PLAN-release-package.md` is sole Now for
deterministic unsigned package/notices only. Developer ID signing/notarization
remains credential/network gated; install/update acceptance remains admin and
clean-Mac gated; adoption remains September-gated; the consortium audit remains
external. Keeper and its profile-authority rider remain Held.

## S34 / 8A — the unsigned package knew every byte it owned (20–21 August 2026)

S34 implemented only the deterministic unsigned Mac package selected by S33.
Source authority was synchronized at `175184b`; the build used a clean export
with submodule `6dfd538`, while the release tool and its strict configuration
were captured separately as uncommitted implementation inputs. The installed
daemon, helper, receipt, state, identities, service jobs and Keeper did not
change. No Installer, `sudo`, VM, Developer ID operation, Apple upload or
public artifact was used.

### Frozen authority and offline build

`release/release.json` freezes product/host **0.0.1**, helper **1.0.1**,
identifiers `systems.reach.host` and `systems.reach.meshd`, arm64/macOS 27.0,
wire `[1,0]`, helper status/specification `[1,2]`, the seven exact host bundles,
and consumed helper version 1.0.0. `release/notices.json` freezes every expected
dependency and notice family. `Tools/ReleasePackage` provides three
dependency-free operations: snapshot already-cached dependencies, build from
clean authority, and independently verify a completed candidate.

The private sealed depot hashes to
`a6a1cc0b…e3e6b` and contains 17 Swift pins, two Swift submodules, ten external
Go modules, and 49 exact notice inputs. All build work after that snapshot ran
offline. Source export rejects divergent refs, tracked dirt, unapproved
untracked entries, dirty/wrong submodules, pin drift and reused/nonmonotonic
versions. Process execution uses fixed executable paths and argument arrays,
a dedicated process group created at spawn, one monotonic clock for execution
and TERM/KILL deadlines, bounded group cleanup after timeout or normal leader
exit, descendant-leak refusal, private exclusive logs and a sanitized environment;
the inherited environment is never written to evidence. Shared filesystem
enumeration is fail-closed: any traversal error rejects source, copy, payload,
time-normalization and manifest operations instead of silently omitting entries.

Two isolated clean exports produced byte-identical reachd
`d41040ad…837e7`, helper `c66e5386…71d15`, host tree
`0823c0d7…c829a`, helper tree `aecd725b…7279`, notices
`d8c6c113…05354` and non-self-referential embedded manifest
`434315e7…9523`. Swift/C warnings-as-errors, deterministic Swift hashing,
serial compilation, reproducible linker ordering, default/fast Objective-C
stubs and source-prefix normalization,
coverage/profile exclusion, `strip -x`, deterministic ad-hoc identities,
offline Go `-trimpath -buildvcs=false -buildid=`, arm64-only inspection and
system-library-only linkage all passed. The older
`mesh-helper/build-package.sh` now identifies itself as development-only; the
release path independently rebuilds and assembles meshd.

The original S34 candidate used `-objc_stubs_small` to eliminate an
object-graph-dependent linker choice. Review correctly identified that as
Apple's size-first dispatch mode rather than a neutral reproducibility flag.
The final build restores the default/fast path and applies a narrow fail-closed
Mach-O normalization before ad-hoc signing. It requires exactly two adjacent
authenticated GOT bindings for the same `libobjc/_objc_msgSend`, the exact
ordinary and 32-byte Objective-C fast-stub instruction shapes, and the expected
thin arm64 sections; any different layout or symbol refuses the build. Build A
used GOT ordinal 0 for all 164 fast stubs and ordinal 1 for its one ordinary
message-send stub; build B exercised the inverse ordering. Both normalized to
UUID `552BEE70-22CE-89DF-ADE4-84EBA2741CAF` and identical bytes while retaining
2,200 ordinary 12-byte stubs and 164 32-byte fast stubs (`__objc_stubs` size
0x1480, alignment 32). The repair therefore fixes equivalent binding order
without selecting a new runtime-performance tradeoff.

### Payload, provenance and notices

One canonical entry table drives both the numeric BOM and a repository-owned
old-portable-ASCII cpio writer. Stable path ordering, inode/link counts,
commit-derived timestamps, numeric root:wheel ownership, exact modes and
`gzip -9 -n` make payload semantics independent of the building filesystem.
Independent verification joined **50 host records** and **6 helper records**
entry-for-entry across allowlist, BOM and cpio. It proved the absolute
`/usr/local/bin/reachd` symlink, exact seven bundles and MLX metallib, no hard
links or special files, no xattrs/ACLs/AppleDouble, no cluster/operator/secret
state, no Scripts or Resources, and ad-hoc executable identities `reachd` and
`systems.reach.meshd` with no Team ID.

The embedded schema-v1 manifest has no self-entry of any kind. External
`release-provenance.json` records its completed size/hash and only the earned
P0 source, P1 payload and U1 unsigned-container stages; signing, notary and
staple fields are absent. Thirty-seven exact notice families generate
`THIRD-PARTY-NOTICES.md` and a machine-readable notice manifest. Unknown
dependencies, changed or missing license/NOTICE inputs, payload-excluded
families and fabricated legal conclusions refuse the build. Independent
verification reconstructs and requires complete canonical equality for the
notice authority and all P0/P1/U1 provenance fields—including artifact paths,
sizes and hashes—rather than accepting summary digests or a subset.

The selected private outer package is
`Reach-0.0.1-unsigned.pkg`, 13,715,807 bytes, SHA-256
`c8d7896e…fcfc`, and has **no package signature**. A second productbuild call
is `db893934…96cc`; recursively normalized components, PackageInfo, BOM, cpio,
Distribution, member order and payload are identical at
`a969fef4…8f22`. Only XAR creation time differs. The two host component hashes
are `c7f6594f…e0669` and `937e4f30…b177`; the helper components are
`e7623c9d…dea7` and `bd68bed4…5f75e`. Their actual hashes remain provenance;
S34 does not pretend Apple-container bytes are reproducible when Apple writes
time-varying metadata.

### Refusal, transaction and verification matrix

Static alternate-root cells passed fresh install, torn A→B detection, complete
A rollback, B application, uninstall and retained-state reinstall while one
independent state sentinel stayed exact. Unmanaged migration, downgrade,
alias collision and second-login ownership were refused. Candidate-backed
release-tool tests also refused tampered Distribution and payload bytes,
missing helper, extra Scripts and stale provenance. Read-only Installer choice
inspection showed both choices hidden, disabled and initially selected; an
explicit choice-change file nevertheless deselected the helper while leaving
the host selected. Therefore two mandatory payloads/receipts remain a clean-
Mac acceptance requirement rather than an S34 claim.

The candidate-backed release-tool suite passed **31/31 three complete times**.
Each provenance variant first copied the complete authority tree, then reached
and asserted its exact P0, P1-path, P1-size, stale-U1 or U1-hash refusal. The
suite also proves monotonic timeout/cleanup bounds, process-group cleanup after
timeout, refusal and cleanup when a successful leader leaves a descendant, full
notice mutation refusal and unreadable-descendant traversal refusal. The three
added tests prove inverse equivalent GOT orders normalize identically without
changing default-fast dispatch shape, and reject size-first/unknown stubs or a
nonexact authenticated binding set.
Fresh ReachKit passed **95/95** and reachd **250/250 across 36 suites**. The
mesh-helper offline module check, complete suite, race detector and vet passed.
Independent Apple-tool inspection used `pkgutil`, `lsbom`, `xar`, `codesign`,
`otool`, `file`, `xmllint`, `plutil` and exact privacy/license/path allowlists.
Superseded probe failures are retained separately and attributed; they are not
in the authoritative evidence pack.

Installed parity remained exact: reachd `a9660a83…6b790` at PID 21242/run 29,
helper `a784f257…b28ca8` at PID 20190/run 1, receipt version 1.0.0, helper
generation 37 on `utun0`, one direct peer and relay configured false/ready true.
Registry, host public key, CA and server certificate remain
`75d9dbf9…0def`, `99526d11…a1d`, `03a08c64…c737` and
`15302bb6…d5af`; the current log still records zero CA creation. Three bounded
S34 dial retries reproduced only the known diagnostic-side
`SecPKCS12Import -25291`. Installed bytes and identities are unchanged and join
to the retained genuine 36 ms authenticated pass from those exact bytes with
15 pass, 3 expected warnings and 0 fail.

The privacy-minimized 0700/0600 evidence root is
`/private/tmp/reach-s34-evidence-authoritative-fast-final-20260821`; it retains only the
authoritative package manifests and reports, successful test/inspection
transcripts, narrowly scoped release-tool/config sources, a privacy-safe
runtime-parity summary and a verified **55-entry** manifest. Its final
`SHA256SUMS` hashes to `a3559ff5…eb4c`; all 56 retained files including the
seal itself are mode 0600. It excludes the 13 MB package
duplicate, caches, raw diagnostic transcripts, broad project documents, user
state, endpoints, identities, secrets and generated content. The earlier
size-first, overbroad and failed/partial correction packs are explicitly
superseded rather than treated as closeout authority. The candidate remains
private at
`/private/tmp/reach-s34-build-output-fast-normalized-final-20260821`.

**Verdict: S34 / 8A COMPLETE — PRIVATE UNSIGNED SUBSTRATE ONLY.** Deterministic
package/licensing implementation is unreimbursed M4 baseline. It is not signed,
notarized, stapled, Gatekeeper-accepted, installed or public. With zero
Developer ID Application and Installer identities available, no signing plan
is promoted and the roadmap has no active Now item. Clean-Mac install/update
acceptance, September adoption, accessibility and consortium audit remain
separately gated. Keeper and its profile-authority rider remain Held.

### S34 correction gate — compiler-visible path-length authority (21 August 2026)

S35's clean-U1 preflight correctly stopped before credentials. Rebuilding the
same historical P0 with the same release-tool, depot and toolchain from a new
absolute root produced reachd `4122823b…` instead of the retained
`d41040ad…`. Of 273 changed bytes, UUID/signature derivation explained all but
34. The remainder was 17 arm64 `mov w2, #filenameLength` operands immediately
before `_swift_isEscapingClosureAtFileLocation`, with the three observed values
tracking the absolute paths to `Memory.swift`, `Cache.swift` and
`PreTokenizer.swift`. This was compiler-generated diagnostic behavior, not a
third equivalent-link-order class. The narrow `_objc_msgSend` normalizer stays
unchanged.

The correction candidate gives build A and build B disjoint private storage
whose compiler-visible roots are each exactly 240 UTF-8 bytes. Prefix maps
continue to remove path contents; the fixed length removes the remaining
diagnostic immediate. Unknown pass names and caller paths too long to retain a
safe padding component fail before compilation. Every raw CLI path now also
rejects empty, dot or dot-dot components and any existing symlink ancestor.
The deepest existing prefix must byte-match `realpath(3)` before either mutable
root is created; the core independently repeats that validation. Every such
comparison now uses `utf8.elementsEqual`, not Swift's Unicode-canonical
`String` equality. This closes case-folded and APFS composed/decomposed aliases
and prevents the 240-byte calculation from using any caller spelling that
differs from the physical bytes SwiftPM compiles through. The external
comparison record is schema 2 and names the unaliased canonical fixed-length
authority and its exact length. Candidate-backed release-tool tests passed
**37/37 three complete times** from separate scratch products, including the
full copied-authority P0/P1/U1 mutation paths plus dot-segment, nested-symlink,
case-alias and Unicode-normalization refusal.

The final preliminary cross-root gate ran three independent tool processes
from physical, byte-exact caller work roots of 44, 72 and 94 UTF-8 bytes. Each
process performed its own A/B build, giving six full reachd builds. All six
executables are exactly `fecb7da1…254b`; all three independently verified U1
semantic digests are exactly `cdd91ae2…da1f`; each verifier joined 50 host and
6 helper files with no Scripts or Resources. The embedded manifest is
`392e4bc0…4187` and all three selected unsigned containers are exactly
`59900976…9473`. This proves the Unicode-byte-closed correction from tool source
`7b215b2b…7c8a`, but it is not the final signing parent.

The privacy-minimized preliminary pack is
`/private/tmp/reach-s34-compile-path-unicode-byte-correction-proof-20260821`;
its 26-entry manifest hashes to `4f56bb89…f989` and verifies every retained
source, candidate-backed test transcript, sanitized build-command record,
comparison, provenance, manifest and independent report. All 27 files including
the seal are 0600 below 0700 directories. The three earlier path-correction
packs remain valid only for their recorded ASCII/case boundaries and are
superseded by this Unicode-byte proof.

Read-only live parity remained exact after the proof: installed reachd is
`a9660a83…6b790` at PID 21242/run 29; helper is `a784f257…b28ca8` at PID
20190/run 1; helper generation 37 is ready on `utun0` with one direct peer and
relay configured false/ready true. No installed byte, receipt, state, service,
identity, Keeper target or network configuration moved. The retained genuine
authenticated result remains joined to those exact installed bytes; this
compile-tool correction did not substitute a new diagnostic retry for it.

**Authority ruling.** The original `d41040ad…` executable,
`a969fef4…` semantic digest, `c8d7896e…` candidate and `a3559ff5…` evidence
remain valid historical S34 evidence but are superseded as P2 signing
authority. S35 stays stopped. After this correction is separately committed
and `HEAD == main == origin/main`, the same three-process/six-build gate must
run from that synchronized correction commit and seal one new U1 authority
before any identity resolution, signing, timestamp or Apple submission.

### S34 synchronized final-U1 authority (22 August 2026)

The correction landed and refs synchronized at
`92b233e9c8c0ebfee57d0aceb182130d0bd7fa0b`. Before any credential action, a
fresh committed release tool ran the final gate from three physical,
unaliased, byte-exact caller work roots of 54, 74 and 91 UTF-8 bytes. Each
process performed its own A/B build with isolated mutable roots and the sealed
offline depot `a6a1cc0b…c3e6b`; all six comparison records name the fixed
canonical compiler-visible authority at 240 UTF-8 bytes.

All six reachd executables are exactly `fecb7da1…254b`; all six helper
executables are `c66e5386…71d15`; all three embedded manifests are
`e92463b7…07957`; and all three normalized U1 semantic digests are
`3b7324a9…305d`. The three actual selected outer packages are
`a8ff82e0…14a88`, `f671015b…16dec` and `ff9dec80…27fed`; independent recursive
normalization attributes their difference only to XAR creation time. Every
selected package independently joined exactly 50 host and 6 helper records and
contained neither Scripts nor Resources. No historical or preliminary S34
semantic digest appears in the final authority.

Invocation 1 build A is the unambiguous S35 parent:
`/private/tmp/reach-s34-final-u1-sync-one-20260822-output/Reach-0.0.1-unsigned.pkg`,
13,715,801 bytes, SHA-256 `a8ff82e0…14a88`, normalized semantics
`3b7324a9…305d`. Candidate-backed release-tool tests passed **37/37 three
complete times** from separate scratch products. They include independent
candidate verification, complete P0/P1/U1 mutation refusals, process cleanup,
and the dot-segment, nested-symlink, case-folded and Unicode-normalized
path-authority regressions.

The privacy-minimized final authority pack is
`/private/tmp/reach-s34-final-u1-authority-20260822`. Its **39-entry** manifest
verifies; all 40 retained files including the seal are 0600 below 0700
directories, and `SHA256SUMS` hashes to `556db65d…5612`. Exact source
snapshots, complete source hashes, schema-v2 comparisons, provenance,
manifests, independent reports, sanitized build-command records and three
successful test transcripts are retained. Packages, caches, raw diagnostics,
credentials, identities, endpoints, prompts, model output, Keeper and `tasks/`
are excluded. An earlier interrupted partial invocation is explicitly outside
this authority; the final gate restarted only after two unexpected exact-copy
untracked files were founder-authorized into a recoverable `/private/tmp`
quarantine and the repository again contained only `tasks/`.

Read-only live parity remained exact: installed reachd is
`a9660a83…6b790` at PID 21242/run 29; helper is `a784f257…b28ca8` at PID
20190/run 1 with receipt 1.0.0; helper generation 37 is direct-ready with one
peer and relay configured false/ready true. Four cluster identity artifact
classes and one device record remain present, and the retained log has zero CA
creation events. No fresh diagnostic replaced the retained exact-byte 36 ms
authenticated result with 15 pass, 3 expected warnings and 0 fail.

**Verdict: the bounded S34 correction is complete and final U1 is earned.**
The old equal-root and preliminary correction hashes remain history, not
fallback authority. No Developer ID identity was resolved or used; no profile
was created or validated; and nothing was signed, timestamped, submitted,
notarized, stapled, installed, published, restarted or changed at runtime.
S35 may now name this U1, but credentialed execution remains paused for the
founder's separate review checkpoint.

### S35 private Developer ID signing and notarization (22 August 2026)

S35 consumed only the synchronized S34 U1 parent from commit
`92b233e9c8c0ebfee57d0aceb182130d0bd7fa0b`: unsigned package
`a8ff82e0…14a88`, 13,715,801 bytes, normalized semantics
`3b7324a9…305d`, and committed unsigned-tool source `7b215b2b…7c8a`. The
separate S35 finalizer source is `264ee253…925e`; its accepted executable is
`0ac54df2…4abd`. No historical or preliminary S34 lineage was accepted.

Security-framework resolution found exactly one usable Developer ID
Application identity and one usable Developer ID Installer identity in the
default login Keychain, with one common team authority. The release tool chose
their exact certificate selectors internally; no selector, profile label,
Apple account, password, private key, or credential environment enters tracked
state or retained evidence. Public Team ID, certificate-chain hashes,
validity, and designated-requirement metadata are retained because the release
cannot be verified without them. The founder created one local nonsynchronized
`notarytool` profile interactively. Credential validation and the later Apple
calls received only that opaque profile label; command records redacted it.

P2 is `01e23c1d…5e90`, 13,726,021 bytes, with normalized semantics
`f8d4c482…7753`. Its only executable leaves are reachd
`d02ffa24…d9d` and meshd `2821c1c…1024`. Both retain arm64, their frozen
identifiers, Hardened Runtime, secure timestamps, valid Developer ID
Application chains, and an empty entitlement blob. The signed reachd help,
scripted selftest, and MLX selftest passed from isolated scratch state; the
helper smoke did not start a service.

The Developer ID Installer signed P3 is `43ffaf45…07620`, 13,739,184 bytes,
with a secure timestamp. Independent expansion rejoined exactly 50 host and 6
helper records, no Scripts or Resources, both signed leaves, and the same P2
semantics. Pre-notary local assessment was retained as observation, not a
failure or install claim.

The crash-safe journal persisted `submitting` before the one real upload. One
submission ID was durably recovered from complete output; that exact P3 hash
reached `Accepted` with status code zero and **0 issues**. The matching notary
log is `3c8e3b48…c96f7`. No timeout, ambiguity, retry, second upload, `--force`,
or replacement lineage occurred. The full submission ID stays in the private
authority pack rather than tracked documentation.

P5 is `97397473…6389f`, 13,741,205 bytes, with P3
`43ffaf45…07620` as its exact parent. `stapler validate`, both nested
Developer ID signatures, package signature verification, and local Installer
assessment all passed. A fresh independent verifier again joined 50 host and
6 helper records, no Scripts or Resources, a valid staple, and normalized
semantics `f8d4c482…7753`. The P3 and P5 packages remain private at their
recorded `/private/tmp` paths and are not duplicated into the evidence pack.

The stabilized release-tool, candidate-backed, failure-state, and live-
identity suite passed **55/55 three complete times**. ReachKit passed **95/95**;
reachd passed **250/250 across 36 suites**; and mesh-helper's complete suite,
race detector, vet, and offline module verification passed. The privacy-
minimized authority is
`/private/tmp/reach-s35-signing-notarization-authority-20260822`: its
**49-entry** manifest verifies and `SHA256SUMS` hashes to
`f195e860…37a8`. All 50 files including the manifest are 0600 below 0700
directories. It retains exact finalizer source, sanitized stage/runtime/test
authority, and three successful suite transcripts while excluding packages,
raw Apple/Keychain logs, account/team/certificate/profile data, credentials,
cluster identities/endpoints/content, Keeper, `tasks/`, caches, and every
superseded attempt.

Installed Reach never moved: reachd remains `a9660a83…6b790` at PID
21242/run 29; helper remains `a784f257…b28ca8` at PID 20190/run 1 with receipt
1.0.0; generation 37 is ready on `utun0`, one direct peer, relay configured
false/ready true. Four identity artifact classes, one device record, and zero
CA-creation events remain. A bounded final `doctor --dial` returned 13 pass,
4 expected warnings, 0 waiting, 0 fail and reproduced only the known
diagnostic-side `SecPKCS12Import -25291`; unchanged bytes remain joined to the
retained genuine authenticated 15-pass result.

**Verdict: S35 / 8B COMPLETE — PRIVATE SIGNED AND NOTARIZED CANDIDATE ONLY.**
Developer ID executable/container signing, Hardened Runtime, secure timestamps,
one exact notarization lineage, and stapling are unreimbursed M4 baseline. No
Installer invocation, receipt mutation, VM, clean-Mac lifecycle acceptance,
publication, release feed/tag, adoption, accessibility, audit, network, Keeper,
or installed-runtime action occurred. Clean-Mac install/update/rollback/
uninstall remains administrator-and-native-VM gated; publication remains a
separate founder action; September adoption, accessibility, and consortium
audit remain future. No new Now item is promoted. Keeper and its profile-
authority rider remain Held.

### S35 post-closeout verifier and evidence correction (22 August 2026)

Post-closeout review accepted the actual P3/P4/P5 lineage but found that its
forward verifier contract and retained evidence did not yet justify every
claim. The old 49-entry pack remains immutable at seal
`f195e860…37a8`; it is historical lineage evidence, not the corrected verifier
authority. No leaf or container was signed again, no timestamp was requested,
and submission `377a2eab-d486-4e6d-b08f-06b677075a5d` was not contacted or
repeated.

The bounded correction now:

- reruns complete signed Distribution/BOM/cpio/manifest/notice verification
  plus both leaf and Installer signature checks before notarization, consumes
  the canonical independent P3 report, and binds its exact hash with P3 in a
  schema-v2 journal before any upload;
- requires signed P0, P1, and U1 to equal the retained U1 provenance exactly;
- verifies every embedded leaf and XAR certificate digest in order and
  recognizes only the exact Developer ID G2 intermediate/root chain;
- covers P2 ad-hoc/runtime/timestamp/entitlement/chain, P3 payload/class, and
  P5 parent/staple/ticket/tamper refusals against the real candidate; and
- validates and reuses already durable accepted wait/log records after the
  log-write crash window instead of wedging or resubmitting the lineage.

The historical schema-v1 stapled journal is preserved honestly rather than
rewritten. Its independent P3 report `738118fe…d591` existed before the sole
submission. The corrected executable independently reproduced that P3 report
and P5 report `50d0501a…b671`; P3 remains `43ffaf45…07620`, P5 remains
`97397473…6389f`, both reconstruct 50 host and 6 helper records with no Scripts
or Resources, and P5 again passed staple validation and local assessment. The
first correction retained a composite index that names the P5 independent
report, but that index spans two roots and is not itself a directly checkable
`SHA256SUMS` authority. The later forward-boundary correction below fixes the
actual external authority root.

The complete release-tool and signed-candidate suite passed **65/65 three
complete times** from separate scratch products. The replacement privacy-
minimized pack is
`/private/tmp/reach-s35-signing-notarization-correction-authority-20260822`:
its **79-entry** manifest verifies and seals at `26fa10c0…c1bf9`; the exact
41-file corrected release-tool snapshot matches the worktree. It retains the
small decisive provenance, journal, submit/wait/log, signature-command,
staple, verifier, and refusal records while keeping package bytes external.

Read-only parity remained exact: reachd `a9660a83…6b790` stayed PID 21242/run
29; helper `a784f257…b28ca8` stayed PID 20190/run 1 with receipt 1.0.0;
generation 37 remained ready on `utun0` with one direct peer and verified
relay absence; four identity artifact classes, one device record, and zero CA
creation events remained. No new dial replaced the retained authenticated
exact-byte result or the later attributed `SecPKCS12Import -25291` diagnostic.

**Corrected verdict: S35 / 8B CORRECTED-COMPLETE.** The same private accepted
lineage is now backed by the promised fail-closed verifier, recovery, refusal,
and evidence contracts. No install, receipt, VM, publication, runtime, network,
or Keeper boundary moved, and no new Now item follows.

### S35 forward upload, credential and sidecar correction (22 August 2026)

A second review left the accepted P3/P4/P5 lineage intact but found three
forward-boundary gaps and three evidence/runbook ambiguities. This bounded
non-credentialed correction again read the accepted artifacts without signing,
timestamping, contacting Apple, submitting, stapling, installing, or changing
runtime state.

One shared retained-U1 binder now requires the signed P0, P1, and U1 stages to
equal canonical `u1-release-provenance.json` before the P3 semantic/signature
preflight and before profile authentication. The final verifier calls the same
binder. Real-candidate mutations of each stage are refused at both boundaries.
The process runner no longer tries to blacklist credential flags: it accepts
only the exact version, history, submit, wait, and log argument shapes used by
the release tool. Raw `-k`, `-d`, `-i`, joined forms, `--force`, reordered or
extra options, unredacted profiles, and unknown operations are rejected before
process creation.

All six signed-candidate tests are now explicitly disabled with a visible
reason when the entire authority environment is absent. A partial or malformed
environment fails. Three complete candidate-backed runs passed **65/65** with
zero skipped cells; a separate ordinary run visibly reported six disabled
candidate cells, and a one-variable partial environment failed as intended.

The corrected verifier executable then exercised the documented P3 and P5
commands while `--finalizer-tool-source` named the retained exact source that
minted P2, digest `264ee253…925e`, rather than the corrected checkout. P3 and
P5 remain `43ffaf45…07620` and `97397473…6389f`; their reports remain
`738118fe…d591` and `50d0501a…b671`; each joins 50 host and 6 helper files with
no Scripts or Resources, and P5 again passed staple validation and local
assessment. The actual external notarized-output root now has one directly
checkable **34-entry** `SHA256SUMS`, including both reports, with digest
`4660c0e9…f8320`.

The newest privacy-minimized authority is
`/private/tmp/reach-s35-signing-notarization-forward-correction-authority-20260822`.
Its **64-entry** manifest verifies and seals at `cda4d03e…f753`; its 41-file
source manifest hashes to `b50859aa…1e34` and matches the worktree. It retains
the three complete passes, explicit-skip and partial-refusal transcripts,
decisive small lineage records, and a clearly labeled copy of the external
sidecar while keeping package bytes external. Public Team ID and certificate
verification metadata are retained; credentials, selectors, account data,
profile labels, keys, Reach state/content/endpoints, and Keeper are absent.

Read-only runtime parity remained exact: reachd `a9660a83…6b790` stayed PID
21242/run 29; helper `a784f257…b28ca8` stayed PID 20190/run 1 with receipt
1.0.0; generation 37 remained ready on `utun0` with one direct peer and relay
verified absent. No fresh diagnostic replaced the retained authenticated
exact-byte acceptance.

**Final corrected verdict: S35 / 8B CORRECTED-COMPLETE.** The single private
accepted lineage now has identical fail-closed retained-U1 authority before
upload and after notarization, an exact non-credential argument grammar,
truthful candidate-test accounting, a runnable retained-source verification
command, and one independently checkable external sidecar. No new Now item
follows.

### S36 / 8C offline clean-Mac lifecycle implementation checkpoint (23 August 2026)

Historical S35 P5 authority could not be restored after its private scratch
roots disappeared. Its hashes remain evidence, not usable package bytes. The
founder selected a new exact sequence: replacement A is product/host `0.0.2`
and helper `1.0.2`; B is product/host `0.0.3`, with helper `1.0.2` only if the
complete signed A helper component is carried forward without re-signing.
Each release retains a separate exact-P3 checkpoint before either of the two
possible future Apple submissions. This checkpoint did not exercise either
one.

The release configuration now has a strict schema 2 while historical schema 1
remains readable. Signed provenance schema 3 binds the exact predecessor,
component disposition, complete parent authority, and P0–P5 lineage. A
successor may retain an unchanged helper version only after its complete
component bytes and executed Mach-O content match the retained parent; the
parent helper is then carried forward exactly rather than signed again. A
caller-supplied hash, reconstructed historical package, missing parent tree,
version reuse, changed bytes without a bump, or incompatible pair refuses.

The nonshipping `reach-release-acceptance` executable implements only the
private acceptance boundary. Host authority is confined to two exact Tart VM
names, pinned SSH, fixed commands, host storage floors, an Apple restore-image
record, and durable rig/evidence teardown journals. Guest authority is confined
to exact retained P5 catalogs, two receipts, immutable payloads, running inode,
one selected login owner, root-helper status/routes, and a privacy-safe retained
state baseline. Its fsynced transaction states cover install, unmanaged
migration, update, an observed real-Installer interruption, recovery, explicit
rollback, uninstall, retained-state reinstall, and verification. Three-phase
real-user contention and supervised daemon/helper crash probes prevent a
scripted fixture from standing in for those future cells. Uninstall enumerates
the complete immutable package root and refuses any member outside the signed
allowlist before removing package bytes or receipts; login-owned state remains
separate.

Final offline verification, after the teardown correction, passed:

- ReleasePackage **129/129 three times**, each with exactly six explicit
  signed-candidate skips because replacement A authority does not yet exist;
- warnings-as-errors builds of `reach-release-package`
  (`742b9f46…d6b84`) and `reach-release-acceptance`
  (`2810ae10…f724`);
- ReachKit **95/95** from fresh scratch;
- reachd **250/250 across 36 suites** from fresh scratch; and
- mesh-helper full and race suites plus vet and offline module verification.

The first sandboxed ReachKit run failed only because Keychain access was
denied, and the first sandboxed helper run failed only because Unix-domain
socket creation was denied; both passed unchanged outside that sandbox. Two
fresh reachd attempts exposed a separate Xcode 27 beta tool-discovery defect:
the Metal component was not installed, then the default wrapper still failed
to discover it. Apple's supported component install produced build
`27A5237l`, toolchain identifier
`com.apple.dt.toolchain.Metal.32023.921.1`; explicitly selecting that installed
toolchain let the unchanged suite compile its metallib and pass. This is a
developer-tool correction, not a Reach runtime or release result.

The privacy-minimized offline pack is
`/private/tmp/reach-s36-offline-authority-20260823`. Its direct nine-entry
manifest verifies; `SHA256SUMS` seals at `e7482e1a…c3e3`. The 59-file
implementation/configuration manifest hashes to `44a176b5…c865`. Directories
are mode `0700`, files `0600`, JSON parses, and the retained text contains no
home path, account address, key, credential, or numeric endpoint.

Read-only parity remained exact after the pass: refs were still synchronized
at `8028082`; reachd `a9660a83…6b790` was PID 85664/run 1; helper
`a784f257…b28ca8` was PID 543/run 1 with receipt `1.0.0`; generation 37 was
direct-ready with one peer and relay configured false/ready true. The four
identity artifact classes retained combined digest `0033884c…d5f3`. No live
Reach byte, receipt, service, state, route, CA, Keeper artifact, or installed
package changed, and no fresh diagnostic displaced the retained authenticated
exact-byte result.

**Checkpoint verdict: S36 REMAINS OPEN.** Offline implementation is ready for
independent review. Replacement-A final varied-root U1 may be minted only after
separate commit/push synchronization. Identity resolution, signing,
timestamping, notary-profile use, Apple submission, stapling, Tart
installation, IPSW download, VM creation, Installer use, lifecycle acceptance,
publication, automatic updates, and Keeper remain unearned.

### S36 offline authority correction (24 August 2026)

Independent review reproduced the first offline checkpoint but found six
acceptance gaps. The corrected candidate now:

- carries the complete signed A helper component byte-for-byte into B instead
  of rebuilding it, and checks the retained component artifact itself;
- obtains the running host/helper executable device and inode from each
  process's live `txt` vnode, requires exact login/root launch definitions,
  binds retained-state owner/group/mode/link/size/hash metadata, and enumerates
  the complete `/Library/Application Support/Reach` package root;
- reloads the local IPSW through `VZMacOSRestoreImage.load` during verification
  and refuses any changed product, build, support, resource, or hardware-model
  result;
- treats service-definition, bootstrap, or unobservable second-user failures
  as inconclusive rather than safe owner contention; and
- freezes the two credential files and complete S36 tooling root, including
  their device/inode authority, after evidence sealing and before teardown.
  Later absence claims are bound to that run and cannot name after-the-fact
  paths.

The active PLAN now labels its unavailable historical S35/default-B sequence
as superseded and non-executable. The founder-selected replacement sequence at
the top remains the only authority.

Focused correction coverage passed **38/38**. The complete ReleasePackage
suite then passed **135/135 three complete times**, each with exactly six
explicit signed-candidate skips. Fresh ReachKit passed **95/95**; reachd passed
**250/250 across 36 suites**; mesh-helper full/race/vet/offline gates passed;
and both private executables built release with warnings-as-errors. Their
hashes are `0a35ed4d…c5d2` (`reach-release-package`) and
`5bdc6a24…a829` (`reach-release-acceptance`).

The initial nine-entry pack remains honest historical evidence but is
superseded for this source candidate. The corrected authority is
`/private/tmp/reach-s36-offline-authority-corrected-20260824`: its direct
**11-entry** manifest verifies and seals at `18b62096…4d9b`; its exact
**60-file** implementation/configuration manifest verifies and hashes to
`b89216ed…4a0b`. Directories are `0700`, files `0600`, JSON parses, and privacy
searches found no home path, account address, private key, credential argument,
or numeric private endpoint.

Read-only parity remained exact: refs stayed synchronized at `8028082`;
reachd `a9660a83…6b790` stayed PID 85664/run 1; helper
`a784f257…b28ca8` stayed PID 543/run 1 with receipt `1.0.0`; generation 37
remained direct-ready with one peer and relay configured false/ready true; and
the four identity artifact classes retained combined digest
`0033884c…d5f3`. No fresh diagnostic displaced the retained authenticated
exact-byte result.

**Corrected checkpoint verdict: S36 REMAINS OPEN.** This candidate is ready
for independent review, not for credentials or VM execution. Commit/push
synchronization and replacement-A varied-root U1 remain prerequisites to the
first exact-P3 checkpoint. No identity resolution, signing, timestamping,
notary profile use, submission, stapling, Tart/IPSW/VM, Installer, publication,
live-host mutation, or Keeper action occurred.

### S36 final offline authority correction (24 August 2026)

A second independent review found four remaining acceptance-authority gaps.
The final offline candidate now:

- recognizes safe owner exclusion only from a loaded contender job that ran,
  exited nonzero, emitted the exact bounded selected-owner refusal, and created
  neither state nor a CA; the complete primary -> refused contender -> restored
  primary journal path is covered, while a different future physical outcome
  remains an honest `OWNER-CONTENTION` stop;
- binds the exact pinned-SSH identity, known-hosts file, and complete S36-owned
  tooling root to the live rig, freezes every vnode after evidence sealing,
  rechecks each opened member immediately before coordinator-owned deletion,
  and records recoverable credential/tooling destruction phases;
- requires exact `0700` mutable retained-state directories and `0600`
  single-link mutable files across enrollment tokens, staged mesh authority,
  the intent lock, and reachability state; and
- records unmanaged migration's process text vnode rather than the pathname's
  current inode. The later vnode-authority correction below supersedes this
  checkpoint's acceptance claim for replaced or unlinked live images.

The focused four-boundary spine passed **32/32**. Three separately retained
complete ReleasePackage runs each completed a **146-test** suite with exactly
six explicit signed-candidate skips because replacement A remains absent.
The joined unchanged-product gates remain ReachKit **95/95**, reachd **250/250
across 36 suites**, and mesh-helper full/race/vet/offline PASS. Fresh
warnings-as-errors executables hash to `169b3bf5…4577`
(`reach-release-package`) and `71532b56…9d68`
(`reach-release-acceptance`).

The preceding corrected pack remains honest but is superseded for this source
candidate. The final privacy-minimized authority is
`/private/tmp/reach-s36-offline-authority-final-correction-20260824`: its
direct **11-entry** manifest verifies and seals at `00c815ae…dcb2`; its exact
**62-file** implementation/configuration manifest verifies and hashes to
`89e26d2c…b4a1`. Directories are `0700`, files `0600`, JSON parses, and privacy
searches found no home path, account address, private key, credential argument,
or numeric private endpoint.

Read-only parity remained exact: refs stayed synchronized at `8028082` and the
submodule at `6dfd5389…6797b`; reachd `a9660a83…6b790` stayed PID 85664/run 1;
helper `a784f257…b28ca8` stayed PID 543/run 1 with receipt `1.0.0`; generation
37 remained direct-ready with one peer and relay configured false/ready true;
the four identity artifact classes and one device record remained exact, with
zero observed CA creation. No fresh diagnostic displaced the retained
authenticated exact-byte result.

**Final offline checkpoint verdict: S36 REMAINS OPEN.** This candidate is ready
for independent review and later commit/push synchronization, not for
credentials or VM execution. Replacement-A varied-root U1 remains the next
gate. No identity resolution, signing, timestamping, notary profile use,
submission, stapling, Tart/IPSW/VM, Installer, publication, live-host mutation,
or Keeper action occurred.

### S36 vnode-authority correction (24 August 2026)

Independent review found four false-proof paths in the final offline
checkpoint. This source candidate now closes them without changing product or
installed bytes:

- the owner-contention observer waits for state or a stopped launch decision
  rather than treating transient execution as final. After bootout and
  confirmed unload, it re-observes the contender and records refusal only when
  state remains absent and CA creation remains zero;
- credential files and the complete tooling root are atomically claimed into
  deterministic same-volume tombstones. The coordinator verifies the exact
  open vnode through each claim, durably records the complete claim, then holds
  and verifies every claimed vnode through deletion. Missing tombstones count
  as removed only behind durable per-vnode progress; unclaimed disappearance
  or substitution fails closed;
- output, absence inventory, both journals and teardown authority must be
  distinct and disjoint in both directions from every original and claimed
  deletion path before any mutation begins; and
- unmanaged migration opens and verifies the exact retained-A `reachd` path,
  then requires the running text vnode to have that same device/inode. A
  replaced or deleted live image refuses.

The focused correction spine passed **25/25 three times**. Three isolated
complete ReleasePackage runs each passed **152/152**, with exactly six explicit
signed-candidate skips because replacement A remains absent. Fresh
warnings-as-errors executables hash to `76252cdb…9bcbe`
(`reach-release-package`) and `23008f9a…8d3c6`
(`reach-release-acceptance`). An initial sandboxed package build stopped only
at an attributed `dsymutil` permission failure; its unchanged rerun passed
outside that restriction. No product source changed, so the preceding pack's
sealed ReachKit **95/95**, reachd **250/250 across 36 suites**, and mesh-helper
full/race/vet/offline gates remain the unchanged-product authority.

The privacy-minimized correction pack is
`/private/tmp/reach-s36-offline-authority-vnode-correction-authoritative-20260824`.
Its direct **11-entry** manifest verifies and seals at `d2e49779…c5776`; its
exact **62-file** source manifest verifies and hashes to `1ab020dd…75b2e`.
Directories are `0700`, files are `0600`, JSON parses, and privacy searches
found no home path, account data, private key, credential argument or numeric
private endpoint.

Read-only parity remained exact at synchronized `8028082` with submodule
`6dfd5389…6797b`: reachd `a9660a83…6b790` stayed PID 85664/run 1; helper
`a784f257…b28ca8` stayed PID 543/run 1 with receipt `1.0.0`; generation 37
remained direct-ready on `utun0` with one peer and relay configured false/ready
true. Registry, host public key, CA certificate and server certificate remain
`75d9dbf9…0def`, `99526d11…a1d`, `03a08c64…c737` and
`15302bb6…d5af`; one device remains and the current daemon log records zero CA
creation events. No fresh diagnostic displaced the retained authenticated
exact-byte result.

**Vnode-corrected checkpoint verdict: S36 REMAINS OPEN.** This candidate is
ready for independent review, not credentials or VM execution. Separate
commit/push synchronization and replacement-A varied-root U1 still precede any
identity resolution, signing, timestamping, notary-profile use, Apple
submission, stapling, Tart/IPSW/VM, Installer, publication, live-host mutation
or Keeper action.

### S36 installed-Metal authority correction (25 August 2026)

The synchronized replacement-A gate stopped before U1 at
`/private/tmp/reach-s36-u1-blocked-metal-selection-20260825`. The installed
Xcode component query reported Metal build `27A5237l`, identifier
`com.apple.dt.toolchain.Metal.32023.921.1`, status installed, and a physical
`Metal.xctoolchain` beneath a reboot-variable cryptex mount. The identifier-only
`xcrun --toolchain` form still resolved XcodeDefault and failed. The working
physical path was therefore necessary during compilation but could not become
stable provenance.

The narrow correction makes that boundary explicit and fail-closed:

- `ProcessRunner` permits only exact read-only `xcodebuild -version` and
  `xcodebuild -showComponent MetalToolchain` forms and refuses identifier-only,
  download, install, provisioning and extra-argument variants;
- one installed record derives a byte-canonical physical root. Root ownership,
  write protection, read-only filesystem, root/member vnodes, installed
  identity, and every stable metadata/tool field are revalidated before and
  after resolve, build, and bin-path selection;
- stable authority binds three metadata hashes plus `metal`
  `eaec9b1e…51b2` and `metallib` resolving to `air-lld`
  `cb7e34e0…adfc4`, with exact version output. The transient root is supplied
  explicitly through SwiftPM `--toolchain` for both build and
  `--show-bin-path`; the retained build graph must resolve every Metal-family
  invocation to those frozen vnodes;
- current payload/provenance schema 2 requires that stable authority, while
  exact historical schema 1 remains a separate no-Metal compatibility path;
  and
- two exact pinned MLX pre-generated source files contained an older cryptex
  source-location marker twice each. The build normalizes only that reviewed
  cardinality to `/Reach/MetalToolchain`, after exact input hashing, so neither
  the current nor the older ephemeral mount spelling enters release bytes.

Three complete ReleasePackage runs each passed **162/162** with exactly six
expected signed-authority skips. Three independent diagnostic candidate gates
each passed **6/6**, including current-schema Metal mutations and independent
package verification. Fresh warnings-as-errors binaries are
`29a0ebdfa720a51404056db191a2eca23fdf34bc06cebaac74f61fae5b938a15`
and
`061665133979cb0f57321f21fc857334f8058c8a1faf28693f59de5bc3258b8f`.

The bounded real build compiled and linked the MLX Metal resources through the
authenticated mounted path, then independently verified:

- unsigned diagnostic package
  `e9bf2c6c83c746504b1c6b9eb36c40c0f0166452fe19b79647af32eeca0bf19b`;
- normalized semantics
  `9bab0350fc312ac91cb625a926a22844d9f51d3c745622872ed447c1ed856947`;
- embedded manifest
  `1c92109ee325278070e755f2e134aac1f5c3eca47c04b8207df0bd618a4c3b69`;
- 50 host and 6 helper records, with no Scripts or Resources; and
- no cryptex mount spelling in the executable, payload or package semantics.

The build came from the dirty correction tree and is explicitly
`admittedU1: false`. It may not be carried into the final replacement-A gate.
No identity or credential was resolved, no signing, timestamp, Apple contact,
submission or staple occurred, no Tart/IPSW/VM or Installer action ran, and no
live product, receipt, state, network, Keeper or `tasks/` authority changed.

**Metal-corrected checkpoint verdict: S36 REMAINS OPEN.** Independent review,
commit/push synchronization, and a fresh three-process/six-build replacement-A
gate remain mandatory before U1 or any credentialed work.

### S36 structured Metal graph and portable static-verification correction (25 August 2026)

Independent review found that the preceding retained-build-graph check could
be satisfied by a correct path in free text while a real Metal role invoked a
different executable. It also found that `PackageVerifier` rediscovered the
installed compiler during every schema-2 verification, which would make the
vanilla clean guest's P5 static-trust cell depend on an unplanned Xcode/Metal
installation. The earlier source conclusion was therefore not commit-ready,
and `/private/tmp/reach-s36-metal-authority-correction-20260825` is superseded
as correction authority. Its `checks/checks.json` was also mode `0644`, not the
claimed `0600`.

The narrow correction now selects one bounded physical XCBuild
`manifest.json` under the expected pass scratch root and decodes it
structurally. It requires the exact nine current MLX `CompileMetalFile` sources,
their exact AIR outputs, and one exact `MetalLink` output/input set. Every real
role must be an XCBuild shell task whose absolute `args[0]` resolves to the
frozen Metal compiler path and vnode. Correct decoys with wrong real tasks,
arbitrary absolute or relative executables, substituted source roots, missing
compile/link roles, extra Metal-family roles, ambiguous manifests, invalid JSON
and oversized graphs all refuse.

Package verification now consumes only retained stable Metal authority.
Unsigned verification, signed-payload/P3/P5 verification, and guest static
trust join the embedded declaration to P0/U1/provenance and reports without a
live component query. Exact installed-Metal equality remains an explicit
builder and signed-finalization-host gate. Historical schema 1 remains its
separate no-Metal path.

The final focused adversarial gate passed **13/13**. Three isolated complete
ReleasePackage runs each passed **165/165** with exactly six expected absent
signed-authority skips. Fresh warnings-as-errors executables hash to
`a153091a…7c06` (`reach-release-package`) and `ee836f32…0bd2`
(`reach-release-acceptance`). The final real candidate-backed gate passed
**6/6**.

A final bounded dirty-source A/B diagnostic independently verified:

- identical reachd `6823b583…ed9f` and helper `c66e5386…1d15` bytes;
- exactly nine compile roles and one link role in each structurally decoded
  manifest;
- unsigned package `aef1821c…ac1c`, normalized semantics
  `8941fb55…2d77`, and embedded manifest `64305835…9111`;
- 50 host and 6 helper records with no Scripts or Resources; and
- no live Metal-component query during independent static verification.

The package remains outside the privacy-minimized evidence pack in a disposable
diagnostic output root. It exists at closeout, but it is explicitly
`admittedU1: false`, nonselectable, and may not enter the replacement-A gate.
That precise scoped statement supersedes the earlier pack's inaccurate
`packageRetained: false` claim.

The superseding evidence pack is
`/private/tmp/reach-s36-metal-authority-correction-superseding-20260825`.
All retained files, including checks and both manifests, are written before the
final mode verification; directories are `0700` and files `0600`. Its final
seal is recorded inside the pack and in the review handoff.

Read-only parity remained exact at synchronized `cc238493…b1fa` with submodule
`6dfd5389…6797b`: reachd `a9660a83…6b790` remains PID 1533/run 1; helper
`a784f257…b28ca8` remains PID 818/run 1 with receipt `1.0.0`; generation 37 is
direct-ready on `utun0` with one peer and relay configured false/ready true.
The four identity hashes, one device record, and zero CA-creation events remain
unchanged.

**Structured-graph checkpoint verdict: S36 REMAINS OPEN.** This dirty-tree
package is diagnostic only. Independent review, commit/push synchronization,
and a fresh varied-root replacement-A gate still precede U1, credentials,
signing, Apple contact, VM work, Installer, publication, live-runtime mutation,
or Keeper work.

### S36 byte-exact Metal graph and failure-atomic finalization correction (25 August 2026)

The next independent review found three narrower authority gaps. The structured
manifest used Swift `String`, `Dictionary` and `Set` equality for source, AIR
and metallib paths, so APFS composed/decomposed spellings could collapse despite
different bytes. The portable P5 report join omitted the stable Metal field.
And the signed finalizer copied retained U1 authority into its output before
refusing a live installed-Metal mismatch, leaving a failed output root
nonempty and nonretryable.

The correction makes every graph path identity a raw UTF-8 byte key. Compile
uniqueness, source-to-AIR membership, link inputs, `default.metallib`, the
command-key/description join and the final exact graph all use those bytes.
Focused fixtures preserve one genuine exact graph and independently change one
source, one AIR output/input and the metallib output between canonically
equivalent NFC/NFD spellings; all three substitutions refuse. The P5/static
`requireP3Hash: false` report join now requires exact stable Metal authority,
including nil and substituted-authority refusals, while P3 retains its stricter
whole-report equality. Signed finalization now performs the live host equality
gate before copying any retained output or resolving identities; its regression
proves a mismatch leaves no output entry, never consults identity authority and
permits an exact retry in the same empty root.

The final focused adversarial gate passed **16/16**. Three isolated complete
ReleasePackage runs each passed **168/168** with exactly six expected absent
signed-authority skips. Warnings-as-errors executables hash to
`201befca…b7fc` (`reach-release-package`) and `32fc29af…bd4`
(`reach-release-acceptance`). All seven current unsigned candidate/static tests
passed.

One fresh dirty-source A/B diagnostic at synthetic synchronized commit
`c383206c…f6bf` independently verified identical reachd
`6823b583…ed9f` and helper `c66e5386…1d15`, unsigned package
`1fd77f26…8f54`, normalized semantics `ac19f622…7f07`, embedded manifest
`ea4744d6…8d11`, and 50 host plus 6 helper records with no Scripts or
Resources. The package stays outside the evidence pack, is explicitly
`admittedU1: false` and nonselectable, and cannot enter the synchronized
replacement-A gate.

The superseding privacy-minimized correction pack is
`/private/tmp/reach-s36-metal-byte-authority-correction-authoritative-20260825`;
its final direct seal and source seal are recorded in the review handoff. No
identity or credential was resolved, no signature/timestamp/Apple/notary
operation ran, no Tart/IPSW/VM/Installer action ran, and no installed runtime,
Keeper or `tasks/` authority changed.

**Byte-authority checkpoint verdict: S36 REMAINS OPEN.** Independent review,
commit/push synchronization and a fresh three-process/six-build replacement-A
gate still precede U1 or any credentialed, VM, Installer, publication or live-
runtime work.

### S36 descriptor-anchored graph and byte-exact stable-Metal correction (25 August 2026)

The next review found that the selected `manifest.json` was still reached
through URL traversal: a symlinked `scratch/out` or deeper ancestor could point
at a correct decoy tree outside the build pass. It also found that synthesized
`Equatable` still gave canonically equivalent Unicode tool-version strings the
same authority even though their UTF-8 bytes differed.

The final narrow correction anchors manifest selection at the exact opened
scratch vnode. It walks `out`, `Intermediates.noindex`, `XCBuildData`, the one
bounded `<32-hex>.xcbuilddata` directory, and `manifest.json` with fd-relative
no-follow opens, raw directory-entry bytes, exact on-disk spelling, strict
entry/size bounds, and before/after vnode revalidation. A symlink at either
tested ancestor now refuses before graph decoding. Stable Metal authority,
including all component, metadata, tool, resolved-path, digest, and multiline
version strings, now compares exact UTF-8 bytes. NFC/NFD version substitution
therefore fails live installed-authority checks, revalidation, and the portable
P5/static report join while the exact retained authority still passes.

The focused authority gate passed **18/18 three times**. Three isolated complete
ReleasePackage runs each passed **170/170** with exactly six expected absent
signed-authority skips. Fresh warnings-as-errors executables hash to
`2d4e977ad2136a395211ca2c53fd625ad1b95ff37668799e8d053fec4f49f5ea`
(`reach-release-package`) and
`26106c5cc79f0e63ce4fe49328f8b4bcc3f9fd45b1e72e147ed20dd129496221`
(`reach-release-acceptance`). The exact unsigned candidate/static gate passed
**7/7**.

One bounded dirty-source A/B diagnostic at synthetic commit
`15eb0691c3ee43c401769844d8af0f9a82bfbd61` independently verified identical
reachd `6823b583ddf3b3e54a1ad8f581c6ccd84c6c1abba29a9f1876f65f39bba6ed9f`
and helper `c66e5386223a223d516d83656514b11b6fb5e50a4b947ab8d4c5064569971d15`
bytes, unsigned package
`11ea6a53d9fb9333326ae2fd2f69d97b88196d741bf0d8693c93aa9f03f482c9`,
normalized semantics
`6bcbeefc1fd224bb805a930358ec7d69ab1a76f8d5b83e56c3ec14ba62d94474`,
embedded manifest
`099da7a8250123458aab984096707423cfa83eddde6ee90881f0cf19bc544736`,
and 50 host plus 6 helper records with no Scripts or Resources. Static
verification performed no live Metal-component query. The package remains
outside the evidence pack, explicitly `admittedU1: false`, nonselectable, and
cannot enter the synchronized replacement-A gate.

The superseding privacy-minimized correction pack is
`/private/tmp/reach-s36-metal-anchor-authority-correction-authoritative-20260825`.
It supersedes the byte-authority pack only as correction authority; its direct
and source seals are recorded in the independent-review handoff. The live
runtime remains generation 37, direct-ready and relay-verified-absent on the
unchanged installed reachd/helper bytes, receipt, identities, PIDs, and run
counts.

**Descriptor-anchored checkpoint verdict: S36 REMAINS OPEN.** Review,
commit/push synchronization, and a fresh varied-root replacement-A gate still
precede U1. No identity or credential was resolved; no signature, timestamp,
Apple/notary, Tart/IPSW/VM, Installer, publication, live-runtime, Keeper, or
`tasks/` action occurred.

### S36 synchronized replacement-A U1 authority (26 August 2026)

The reviewed descriptor-anchored Metal correction synchronized at
`ff2ab11a0ec2cfb580bf00a3c2de722ea53240f0`. The final replacement-A gate
started again from empty work/output roots. Its first provisional lineage was
excluded before admission because its release-tool “source” included the local
`.build` directory. That package `dae10125…3588f`, source digest
`c8e45056…0415`, and semantics `c31be739…47e8` are non-U1 and were never
promoted.

The authoritative rerun used a clean 97-entry commit export of
`Tools/ReleasePackage`, digest `6b24a389…35930`. Three independent physical
caller roots measured 44, 64, and 83 UTF-8 bytes; each ran a fresh A/B build,
and every compiler-visible root measured 240 bytes. All six reachd binaries are
`6823b583ddf3b3e54a1ad8f581c6ccd84c6c1abba29a9f1876f65f39bba6ed9f`;
all six helpers are
`c66e5386223a223d516d83656514b11b6fb5e50a4b947ab8d4c5064569971d15`;
all three normalized semantics are
`1b9ea43ce96ae4d8841e57352e4306e4f68f737982dcda515493bc58db0a1b09`.
Stable Metal authority remained build `27A5237l`, component
`com.apple.dt.toolchain.Metal.32023.921.1`, compiler `eaec9b1e…51b2`, and
linker `cb7e34e0…adfc4`.

Three independent verifiers each joined schema 2, 50 host records, 6 helper
records, no Scripts, no Resources, embedded manifest `cbfb8762…7e25`, and the
same Metal authority. Three complete ReleasePackage runs passed **170/170**
with exactly six expected absent signed-authority skips each. The clean
candidate-backed mutation gate passed **7/7** with zero skips. Fresh
warnings-as-errors executables hash to `25d96a9b…e78` and
`2ceb60b1…f70`.

The admitted unsigned replacement-A package is
`Reach-0.0.2-unsigned.pkg`, SHA-256
`1d9945e1ffc0bb5b54eeab64a2b3e18d93e2850f283ad42aade199c40be3588f`,
exactly 13,715,965 bytes. It is retained separately under the durable S36
authority with a verified 5,162-entry manifest. The privacy-minimized external
pack is
`/private/tmp/reach-s36-replacement-a-u1-authoritative-20260826`; its 128-entry
direct seal is `f82239e3…1c7085` and its 93-entry source seal is
`be56f344…7ba92`.

Read-only parity remained exact: installed reachd `a9660a83…6b790` at PID/run
1533/1; helper `a784f257…b28ca8` at 818/1 with receipt 1.0.0; generation 37
direct-ready on `utun0`, one peer, relay verified absent; all four identity
hashes, one device record and zero CA-creation events unchanged.

**Replacement-A U1 is admitted; S36 remains open.** No identity, certificate,
credential, Team ID, notary profile, signature, timestamp, Apple contact,
submission, staple, Tart/IPSW/VM, Installer, publication, receipt, live-runtime,
network, Keeper or `tasks/` action occurred. The next gate is separately
authorized replacement-A signing/notarization; clean-Mac acceptance follows
only after exact A passes.
