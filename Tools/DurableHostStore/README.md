# S81 local durable host store candidate

An isolated encrypted, single-generation host adapter for the accepted S80
provider. It commits exact provider candidates and original event-array bytes
before acknowledgement or publication. Active recovery uses full public S80
restore; authenticated terminal replay acquires no model.

Run with the selected Xcode/Metal platform approval:

```sh
python3 Tools/DurableHostStore/run.py --reach /Users/nellymoon/Documents/Swift/Reach
```

The runner authenticates 65 prerequisites, ten selected sources, pinned local
dependencies and the unchanged 35-output native composition. It builds an offline
private package with four jobs, tests filesystem/crypto/lock lifetime first, then
executes ten focused tests and eight actual process-death cases. Native suffix
inputs, cache offsets and logits are compared after continuation, alongside exact
event bytes. Required-tool active recovery and partial terminal-tail replay are
separate cases; receipt-loss replay verifies exact duplicates. Evidence is retained under
`/private/tmp/reach-durable-host-store.*`; joined-worker stores, keys, source and
build copies are disposed. No dependency download or shared build/cache mutation.

`initialize` requires a fresh 0700 root and creates a valid encrypted empty
manifest. `reopen` requires existing authenticated authority; it takes the stable
0600 close-on-exec lock and syncs a checked owner-epoch increment. All roles are
bounded, fd-relative, no-follow, same-UID regular single-link files. Unknown or
unsafe roles refuse without deletion. The private root and its ancestors are
trusted; this is a cooperating-process advisory lock.

Two independent 256-bit synthetic keys are injected through an anonymous pipe
from the surviving supervisor, never stored or passed through arguments or the
environment. CryptoKit AES-GCM uses a fresh random nonce and authenticates version,
store, record, role, compatibility and producing epoch. The encrypted manifest
selects encrypted immutable candidate/replay blobs. Replacing `current` linearizes
commitment; directory sync precedes success/ack/publication. Post-replacement IO
uncertainty blocks work and replay until disk-authority reconciliation. Exact
current retries are idempotent; no old-parent or corrupt-state fallback exists.

Replay retains each original event-array byte string in bounded binary framing.
Host event sequences start at one and differ from provider ordinals. An inside-
batch cursor returns original bytes with `skipPrefix`; the surviving fake client
checks exact duplicates, gaps and committed high. New native work waits for replay
delivery. This memory cursor is not a durable client receipt. Cancellation uses
the same reserve/commit/ack path and preserves already committed tool calls.

Caps: 192 MiB candidate, 16 MiB+4 replay, 1 MiB manifest, 4096 commits including C0,
65536 events, 16 files, 512 MiB store allocation. Before model work the adapter
reserves a full next candidate/replay/manifest plus overhead while retaining the
current set, and the worst next 4096-event/8-MiB batch. Refusal leaves history intact.
The runner allows 16 GiB combined owned scratch, 1 GiB fixtures, 128 MiB MLX tensors
and a 20 GiB free-disk floor. Observations are at command boundaries.

Acceptance is limited to same-host, same-boot, compatible-revision worker death
with a surviving key/client supervisor. Reboot/power loss, production key storage,
rollback protection against a key holder, durable receipts, tool effects, EXO
fencing, runtime adoption, release and physical-host work remain outside scope.
Keeper remains Held. S72-S80 child/RC1 and tiny-Llama recurrence evidence is reused.
