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
