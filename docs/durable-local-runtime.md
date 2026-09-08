# Local durable generation

`reachd durable-local` is an explicit macOS local qualification path. It persists
generation checkpoints and an encrypted client inbox, then resumes selected state
in a fresh process. Normal `serve`, SDK behavior, default model selection and
network offers `[1,0]` are unchanged. It starts no socket, listener or tool executor.

## Prepare the selected profile

Use the normal daemon build with `ReachDurability` and the full vendored
`mlx-swift-lm` package. The executable and its immediate parent must be owned by
the current user with mode `0700`; the executable must be a regular, singly linked
file no larger than 192 MiB. Freeze the exact normal-build bytes in a fresh private
location before initializing a root. Recovery requires the same executable path
and hash. Keep the build's compatible MLX resources available; the qualification
runner copies the verified Metal library beside the executable as `mlx.metallib`.

The only admitted profile is `local-llama-258-v1`: two-layer Llama, hidden size 16,
intermediate size 32, two attention heads, one KV head, 258-token byte vocabulary,
two simple KV caches, float32 weights and an empty extra-state codec. The model
directory is `0700`, contains exactly `profile.json`, `config.json`,
`weights.safetensors`, `tokenizer.json` and `template.txt`, and each file is `0600`.
The profile manifest binds every artifact hash. Runtime validates the selected
configuration, complete tensor names/shapes and bounded safetensors layout before
loading weights. Unsupported or changed artifacts refuse; no download or model
registry is involved.

The normal test target contains the deterministic fixture author. See the
[qualification instructions](../Tools/DurableLocalRuntime/README.md) to generate
artifacts and example request JSON. Tiny generated weights exercise actual Llama
inference but make no claim about useful answers or learned tool choice.

## Initialize, begin and recover

Choose a fresh session path under a private `0700` parent. Do not create the
session directory beforehand. Run the initializer in a foreground terminal:

```sh
"$qualified_reachd" durable-local init --root "$scratch/session" --model "$scratch/fixtures/model"
```

It prints `ready` after creating the scoped Keychain, independent root keys,
bootstrap, encrypted stores and bound profile. Leave this process alive: it
retains the exact cleanup capability and releases the lifecycle locks so other
commands can operate.

In another terminal, begin one owner-only request file:

```sh
"$qualified_reachd" durable-local begin --root "$scratch/session" --request "$scratch/fixtures/requests/ordinary.json"
```

After that command exits or its exact process has been killed and joined, recover
using only the selected root:

```sh
"$qualified_reachd" durable-local recover --root "$scratch/session"
```

Recovery loads the original ticket, client context, prepared binding and inbox
receipt. It does not accept replacement request/seed/session inputs or prepare
the original prompt again. Native work continues from the full committed
checkpoint. Later tool passes may perform their own legitimate preparation.
One generation is allowed per initialized root; a second begin refuses.

`begin` and `recover` support `--progress` for boundary counts and `--report` for a
fresh `0600` report in a `0700` directory. Without `--report`, the final report is
printed. Reports expose actual retained batches, binding, status and bounded
native observations for local qualification. Stdout is a view of the inbox, not
a transactional consumer or a new acknowledgement authority. Terminal printing
can repeat after death. The final terminal receipt is intentionally not sent by
this command, leaving committed host content available for terminal replay.

`durable-local cancel --root ...` uses lifecycle retirement. Its outer
`cancelled` disposition is distinct from the provider's committed terminal and
from tool-effect knowledge. It appends no synthetic event and executes no tool.
A preparation/compiler/native/store throw stops with a bounded type diagnostic
and, when available, the last observed committed report. It does not manufacture
success/error events or retry the failed step. Zero/short guided budgets retain
their native incomplete ending; lazy compiler failure can remain nonterminal.

## Keychain and lifecycle limits

The initializer generates a random password in memory for a new dedicated file
Keychain. It never requests the desktop password, persists or prints the password,
or places it in argv. Keychain UI is disabled. Initial key access names only the
exact qualified executable. Existing commands only open and load exact scoped
records, with no unlock, replacement, broad item search, or default/search-list
setter. Default/search-list preservation is checked using metadata only.

This requires an unlocked compatible selected Keychain and the same boot. Missing,
locked, replaced or incomplete state refuses. Keep the initializer alive; do not
kill it as the crash subject. Once all worker commands have exited and joined,
signal the initializer with Ctrl-C or SIGTERM. It reacquires both lifecycle owners,
deletes its own Keychain and owned session tree, then prints `retired`. Active
owners cause `cleanup-blocked`; release/join the worker and signal again. The
initializer retains its cleanup capability while blocked.

Current UID/GID, current boot and system monotonic clocks supply local authority.
Request JSON cannot provide caller, `allowed`, clocks, key providers or readiness.
This is cooperating same-UID use, not a remote identity or hostile same-UID
security boundary. Original deadlines do not renew on recovery. Backup exclusion
is requested and reported where supported; there is no physical-erasure,
filesystem anti-rollback, exhaustive descendant or hard GPU-call deadline claim.
The command stops at returned native/persistence boundaries and closes its owners.

The separate [`durable-transport` command](durable-client-host-transport.md) adds
an explicit same-boot loopback mTLS route with role-specific ownership. It uses
new confirmed roots; existing `durable-local` roots and behavior are unchanged.
