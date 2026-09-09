# Durable role unlock qualification

These serial macOS campaigns qualify the explicit caller-descriptor lifecycle
described in [the operator guide](../../docs/durable-role-unlock.md). They reuse
the normal manifest and tiny numeric artifact recipe. No secret value or secret
hash is recorded in commands, environment evidence, logs, reports or receipts.

## Inputs

Use an owned mode-0700 `/private/tmp/reach-s97.*` scratch directory. Build normally
with owned caches, existing cached sources, outer network denial, disabled
experimental SwiftPM prebuilts and at most four jobs. The existing
`LocalRuntimeTests.testGenerateAndLoadActualArtifacts` emits the tiny fixture under
`S93_TEST_ROOT=<scratch>/fixtures`. Do not download or modify shared caches,
dependency resolution or Vendor sources.

```sh
python3 Tools/DurableRoleUnlock/run.py \
  --scratch "$scratch" --label reference-1 \
  --executable "$normal_executable" --metallib "$normal_metallib" \
  --model "$scratch/fixtures/model" \
  --public-model "$scratch/fixtures/public-model.json" \
  --requests "$scratch/fixtures/requests" --mode reference
```

Every invocation creates a new `qualification-<label>` directory and freezes its
own executable copy. Keep that copy until all its selected roles are absent.
Support uses the lifecycle runner's child supervision with an optional explicit
descriptor list; the previous runner's defaults remain unchanged.

The controller creates private caller fixture files with distinct host/client
inputs. Initialization and unlock receive exactly their own inherited read-only
descriptor. Ordinary workers receive no secret descriptor. Peer root, control and
secret-file read/write access is denied, with direct filesystem probes. This does
not establish securityd IPC or malicious-same-UID isolation.

## Serial cases

1. `run.py --mode smoke` joins a finite client initializer, locks its exact
   container, proves fresh-worker and wrong-input refusal with locked status,
   unlocks through a fresh process, distinguishes already-unlocked with wrong
   input, and explicitly retires the root.
2. `run.py --mode reference` records an ordinary native result with new v3 roles,
   active host unlock refusal, fresh terminal replay and fresh retirement.
3. `run.py --mode recovery --reference "$scratch/qualification-reference-1"`
   stops and joins both original workers after durable progress, locks both
   original containers, proves locked acquisition and wrong-input refusal, and
   unlocks each role in a fresh process. Fresh recovery must match the current
   reference's exact inbox/provider binding, preserve original context/reference
   and retention/deadline, resume at a positive native offset, and perform zero
   repeated original preparation/template/tokenization/issue/begin. Fresh terminal
   replay generates nothing. The selected 30-second local cap is retained. After
   terminal replay it locks the client, waits beyond the cap, makes the expired
   client manifest undecodable, then proves fresh unlock and content-free
   retirement without renewing authority.
4. `negatives.py` accepts the same common inputs and a fresh label. Its serial
   cases cover descriptor/CLI failures, wrong receipt/digest/policy, replacement
   and symlink roots, active ownership, actual post-unlock original-key failure
   with observed relock, already-unlocked semantics, legacy v2 refusal and an
   authenticated retiring role. `--case guards|legacy|retiring` selects a focused
   retry when needed; `all` is the default.

The original-key negative changes only bounded public owned fixture confirmations
and restores their original bytes afterward. A `verification-refused-locked`
diagnostic proves verification followed an observed successful OS unlock; a fresh
exact-container status query proves locked state. Focused Swift tests inject a
failed relock operation and a misleading successful return that leaves the state
unlocked, proving `relock-unconfirmed` cannot become success. These injected cases
are distinguished from the actual successful-relock CLI case.

The retiring case stops the real retirement command after its authenticated
`retiring` event, verifies the original container remains, kills/joins it, locks
that container, and unlocks in a fresh process. The phase must stay retiring and
workers must refuse before and after unlock. Fresh retirement completes cleanup.
A raced observation is a retained failed attempt, not proof of this boundary.
The separate S96 post-container-deletion retry is reused by dependency comparison.

## Evidence and cleanup

Commands, inherited descriptor counts, PIDs, waits, content-free status, public
reports and sampled bounds are retained. Before deleting caller fixture files,
the controller checks recorded command/environment and log/report/control evidence
for its fixture inputs, recording only counts/booleans. No credential hashes are
computed or retained. Initializers, workers and focused helpers are joined in
final cleanup; remaining successful roles are unlocked when needed and retired
using original product authority. On cleanup failure, preserve their original
selections, inputs and frozen executable for correction.

Run one campaign at a time, with one native generation, one host and client, and
at most one extra lifecycle/controller operation. At most two selected role
Keychains are live per pair; negatives run serially. Scratch is at most 32 GiB,
fixtures 3 GiB, each log 192 MiB and retained evidence 1 GiB; free space is at least
20 GiB and role/control records remain at most 64 KiB. Resource figures are
samples, not unobserved-peak guarantees.

After all owned roles and caller inputs are absent, bind current source,
artifact/executable and report hashes, then remove build/cache/model/TLS/Metal
and runtime material. Retain failures and explicit executable cohorts. Reuse S95
other native routes and unchanged wire/retention/crypto/parser/R1 evidence through
actual dependency comparison, without requiring removed historical safetensors
to have byte-identical serialization.
