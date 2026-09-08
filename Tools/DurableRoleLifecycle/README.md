# Durable role lifecycle qualification

These serial macOS campaigns run the normal `reachd` executable through the
finite role lifecycle described in
[the operator guide](../../docs/durable-role-lifecycle.md). Every initializer is
joined before workers start. Successful roots are explicitly retired by fresh
processes using the original public receipt and retained expected digest.

## Inputs and build

Use one owned mode-0700 scratch directory named `/private/tmp/reach-s96.*`, the
normal manifest build, its Metal library, and the existing tiny artifact fixture.
Build in owned scratch with at most four jobs, existing cached sources, denied
network access, and `--disable-experimental-prebuilts`. When reusing SwiftPM
workspace state, clear stale absolute prebuilt entries. Do not download or alter
shared caches or dependency locks. The existing
`LocalRuntimeTests.testGenerateAndLoadActualArtifacts` fixture accepts
`S93_TEST_ROOT` under this scratch and emits `model`, `public-model.json` and
`requests` using the unchanged numeric recipe.

Each campaign accepts these common options:

```sh
python3 Tools/DurableRoleLifecycle/run.py \
  --scratch "$scratch" --label reference-1 \
  --executable "$normal_executable" --metallib "$normal_metallib" \
  --model "$scratch/fixtures/model" \
  --public-model "$scratch/fixtures/public-model.json" \
  --requests "$scratch/fixtures/requests" --mode reference
```

The runner creates a new `qualification-<label>` directory, freezes a private
executable copy, records its hash, and joins every known child. Keep that copy
until every role created with it has retired. Labels cannot reuse an existing
campaign directory. Commands, PIDs, exit/join results, reports, sampled bounds and
failures remain in that campaign's `evidence.json` and `logs`/`reports` directories.

## Serial cases

1. `run.py --mode smoke` initializes a client, joins its creator, retires it in a
   fresh process and checks repeated absence.
2. `run.py --mode reference` creates an ordinary native reference, checks active
   host retirement refusal, reopens for terminal replay and retires both roles.
3. `run.py --mode recovery --reference "$scratch/qualification-reference-1"`
   stops and joins both original workers after client durable progress, starts a
   fresh host and recovering client, compares exact inbox/provider binding with
   the current reference, and checks unchanged original authority/retention,
   positive restored offset/native work and zero repeated original preparation,
   issue or begin. Fresh terminal replay generates nothing. It then waits beyond
   the original 30-second client cap, makes the expired client manifest
   undecodable and proves content-free explicit retirement of both roles.
4. `negatives.py` with the same common options and a fresh label runs serial
   client-only fixtures: wrong selection, replaced/symlink root, active lifecycle
   ownership, original-key confirmation failure, a killed retirement after actual
   Keychain deletion followed by fresh retry, and locked-container refusal.

The negative boundary fixture creates 1,024 opaque owned journal files to make
partial removal observable. It pauses after the content-free `keychain-deleted`
event, proves the original root remains with its container absent and phase
`retiring`, kills and joins that process, verifies worker refusal, and retries
with a different PID. A raced boundary is a failed attempt, never a pass.

The locked fixture deliberately cannot use product retirement before original
key authentication. It is disposed using the exact owned negative-fixture
selection via `security delete-keychain`, with current default/search-list
comparison. Evidence labels this fixture cleanup separately from successful
product retirement; no password or unlock command is used.

Each worker and retirement process is denied peer root/control access and all
network access except local loopback. Direct probes verify own access and peer
read/write denial. This proves filesystem confinement, not securityd IPC or
malicious-same-UID isolation. Controller evidence is not runtime authority.

## Bounds and cleanup

Run one campaign at a time: one native generation, one host and one client, and
at most one extra lifecycle/controller operation; at most two owned role
Keychains per pair. Keep scratch at most 32 GiB, fixtures at most 3 GiB, free
space at least 20 GiB, each log at most 192 MiB and retained evidence at most
1 GiB. Resource figures are samples, not a claim about unobserved peaks.

The scripts join known children in final cleanup and explicitly retire their
successful roots. If cleanup fails, preserve the original selection and frozen
executable for correction/retry. Never turn a refusal into an invented ready
state. Once all owned Keychains and roots are absent, bind the current fixture,
executable, Metal, source and report hashes, then remove owned build/cache/model,
provisioning and runtime material. Retain bounded logs and nonsecret evidence.
Reuse unchanged prior native/wire/retention evidence by actual dependency
comparison; these campaigns do not rerun the four other native request routes.
