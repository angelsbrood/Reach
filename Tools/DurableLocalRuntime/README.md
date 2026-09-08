# Normal local-runtime qualification

This runner operates an already-built **normal `reachd` product**. It creates no
alternate Swift package or worker graph. `run.py`, `native.py` and `boundary.py`
copy that payload into an eligible owner-only location, use generated local
artifacts, supervise exact child processes and retain ordinary JSON reports/logs.
The initialization child retains creator-only scoped Keychain cleanup authority.
No desktop password or existing credential item is requested.

## Build and artifacts

Build canonical `reachd/Package.swift` with four jobs and the current resolved
resources. Use an owned SwiftPM scratch/cache/config/security path and offline
cached dependency copies; never patch shared checkouts or fetch model/dependency
updates for this qualification. The daemon and durability package must resolve
the same local `Vendor/mlx-swift-lm`, with its full upstream manifest/products and
both `FoundationModelsIntegration` traits disabled. The normal MLXFilling path
must compile too. Preserve other resolved revisions.

Use `swift build --product reachd` and `swift build --build-tests` against that
same graph. The focused normal tests are `LocalRuntimeTests`,
`StructuralCoordinatorTests`, `ToolRenderingTests`, `UnconstrainedSamplingTests`,
`ResponseGuidanceTests`, `LaunchIdentityTests` and `PortableHostTests`. Run native
cells serially. Existing unchanged wire/native/Keychain evidence can be reused
when its source/dependency bindings remain exact.

Create an owned `mktemp -d /private/tmp/reach-s93.XXXXXXXX` parent, mode `0700`, and
its `fixtures` subdirectory with mode `0700`. Set `S93_TEST_ROOT` to that exact
absolute `fixtures` path when running `LocalRuntimeTests`; the normal test code
authors the tiny deterministic model and eight request files. Runtime only loads
and validates these artifacts. The test-only structural model separately proves
tools-first ordering and hidden probe prose; it is not labelled Llama inference.

Provide the normal build's compatible `default.metallib`. The runner copies it
as colocated `mlx.metallib`, the native dependency's supported resource lookup.
Authenticate its dependency/resource revision before reuse. Artifact and payload
hashes, current execution and native peak are reported; a cached library's mere
presence is not execution proof.

## Run

For each command, supply these arguments (all paths absolute):

```sh
python3 Tools/DurableLocalRuntime/run.py \
  --scratch "$scratch" --campaign crash \
  --binary "$normal_build/reachd" --metallib "$compatible_metallib" \
  --model "$scratch/fixtures/model" --requests "$scratch/fixtures/requests" \
  --mode crash
```

`--routes` optionally selects a causal subset from ordinary, guided, required,
allowed and combined. Crash mode stops only its exact begin child after positive
native work, kills and joins it, then invokes load-only recovery. Hidden tool
routes can have zero visible inbox events at this committed native checkpoint.
Recovery must perform positive work from a positive cache offset with zero
original preparation/issue/begin. It then checks terminal replay with zero native
calls. The command intentionally has not receipted the terminal batch.

Use a new `--campaign reference`, `--mode reference`, and
`--reference-dir "$scratch/crash/reports"` with the same artifact/request files.
This runs an uninterrupted **normal daemon begin**, then compares complete prepared
bindings and exact inbox batches, provider commit IDs, event bytes, order and
usage against the successful crash reports. Random bootstrap/ticket identities
are separate from this exact provider binding. Use a new campaign name for a
retry and preserve failures; do not overwrite failed evidence with later passes.

A new campaign with `--mode boundary` checks zero/short budgets, lazy compiler
failure, unsafe/reused roots, incomplete bootstrap, missing/replaced/locked scoped
Keychains, ownership contention, joined death and cancellation. The only `security`
CLI operation is `lock-keychain` on that campaign's newly created container.
All key and journal retirement stays with the original initialization process.

The supervisor denies network access for children, samples aggregate scratch
allocation/free space, bounds reports/logs and records direct-child joins. Limits
are 32 GiB live scratch, 3 GiB owned fixture roles, 20 GiB free disk, 192 MiB per
log and 1 GiB reports per campaign; runtime enforces a 128 MiB MLX allocator peak.
A 180-second command observation timeout is a supervisor limit, not a GPU deadline.
If creator cleanup blocks, its PID is retained and the process remains alive with
its capability. Join/release known workers and signal that exact creator again.
Do not replace this with a credential search or kill the cleanup owner.

Successful cells delete their owned Keychains and session model/journal trees.
After validation, retain only bounded logs/reports and remove known-owned copied
executables/resources, build copies and generated fixture input files. There is
no RSS, exhaustive descendant, physical erasure or filesystem rollback guarantee.
See [runtime usage](../../docs/durable-local-runtime.md) for the command boundary.
