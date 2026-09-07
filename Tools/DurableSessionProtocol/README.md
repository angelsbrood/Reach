# S87 durable-session protocol candidate

This dependency-free helper compiles **real ReachWire** and its unchanged Apple
FoundationModels codec bridge on macOS 27 / Swift 6.4. It tests an inactive
dialect-2 protocol candidate. Shipping offers remain `[1, 0]`; no daemon,
client, provider, transport, key/store format or runtime capability is adopted.
There is no model construction/generation, network operation, Keychain use,
identity execution or durable storage in this campaign.

From the repository root:

```sh
python3 Tools/DurableSessionProtocol/run.py
```

The helper creates an owned `/private/tmp/reach-s87-protocol.*` directory and
prints its evidence path. It copies the seven real S86 wire files from commit
`95f12615fad636553bf1489322cd86602f9b9b6d`, then compiles the exact same
`LegacyWireCompatibilityTests.swift` fixture against baseline and candidate.
The candidate includes both new wire files and all six wire test source files.
No shadow codec or external package dependency is used.

The fresh comparison covers all 24 pre-S87 frame types at v0/v1, portable
request/schema/events, additive optional keys, retired/unknown types and
HelloAck v0 omission/v1 tri-state/refusals. Exact encoded bytes and invalid
categories must match. Separate candidate tests cover the eleven new frames,
requester-side phases, exact data and bounds, refusal and v2 relay inheritance.
Synthetic accepted replies prove protocol correlation only.

The two historical `GoldenCorpusTests` compile but are explicitly skipped:
the old S55 corpus files are unavailable. Their silent no-op behavior is not
counted as evidence, and the old 57/14 corpus count is not a new result. Raw
logs, test enumeration, source/fixture hashes, deterministic comparison rows,
commands, resource snapshots and command exit/join results are retained.

For private candidates, `--repo /absolute/repo --overlay /private/candidate`
overlays only the fixed source/test/package paths. `--reuse-baseline` accepts
a prior evidence directory only when its baseline commit, seven source hashes,
fixture hash, passed baseline run and corpus hash match. This allows a causal
candidate correction without rerunning unchanged baseline proof. `--filter`
selects focused candidate tests and always includes the compatibility corpus;
it does not imply a full candidate-suite pass.

One build/test command runs at a time, with four jobs and a 600-second deadline.
The supervisor checks scratch (2 GiB), evidence (64 MiB / 256 files), free space
(10 GiB minimum) at command boundaries, and observes per-log size (8 MiB) while
commands run. It joins explicitly owned commands and removes their exact
private source/build roots even on failure. Failed logs remain evidence.
This is command-level supervision, not continuous RSS monitoring or exhaustive
opaque subprocess-history proof. Retained evidence from previous invocations
must also fit the task's aggregate budget.

S86's native evidence is reused only for its unchanged historical inputs.
Frames.swift's narrow HelloAck `>= 1` change is bound by the new baseline
comparison; the old native manifest does not authenticate this changed file.
Terminal Architecture review and Planning closeout precede commit/push.
