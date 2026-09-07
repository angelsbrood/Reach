# S86 durable-session discovery and recovery

This additive local macOS candidate discovers selected caller-owned S83 records
and resolves their existing encrypted context. It never uses `open` as a recovery
fallback. Each operation freezes current caller bytes, checks selected lifetime
before snapshot/ticket decryption, and rechecks current authorization and every
returned record's expiry after blocking reads and before publication. Summaries
are bounded to 64 records/64 KiB; resolve returns one context at a time.

Explicit registration retains only the exact original host ticket in a fixed
sibling directory outside the strict bootstrap/client journals. A fresh-nonce
AES-GCM key is derived by HKDF solely from the selected S83 per-record key, with
an independent S86 domain and immutable context/lifetime/bootstrap bindings.
A separate metadata-key ownership MAC authenticates orphan ciphertext without
recovering a pruned record key. No duplicate context index, wrapped recovery key,
ticket re-signing, persisted permission or new transcript is introduced.

Registration is add-only: sync temporary ciphertext, select its immutable final
role, sync the directory, then publish. Exact retries read back selected bytes.
Unselected/missing history stays incomplete. Client ownership precedes the short
sidecar lock; the lock is released before any host/native work. Client receipt and
unknown/known effect knowledge remain available without host keys or ticket storage.
Original client expiry prunes identity/key before authenticated orphan deletion.

The new workers acquire keys inside the unchanged S85 OS provider. S86 fixtures
own their fixed paths and initial frozen-worker access; original S85 guards and
descriptor/source bindings remain unchanged. A fresh recovery entry rejects ticket
and context seed fields. Discovery and ticket reads provide the routed recovery
values. Current caller authorization is supplied anew; the existing host still
verifies its original ticket MAC, authorization, context and witness before native
continuation. The cleanup-only controller never supplies recovery credentials.

Run `python3 run.py --repo /path/to/Reach` with Python 3.12 or later. Packaging is
offline and authenticates 140 accepted products/fourteen bindings, six pins, Metal
and the unchanged 35-output native composition. `--tests-only`, `--workers-only`
and `--test-filter` report only their executed subsets; evidence reuse is explicit.
Focused tests cover current caller/time, immutable registration, missing/substituted
history, finite key retention and owned cleanup. Fresh workers prove the actual
scoped Keychain access and native continuation; accepted broader S83–S85 campaigns
are reused. Separate synthetic knowledge fixtures are not native route evidence.

Only fresh disposable file-Keychains/random generic-password items are used.
Interaction is disabled; fixed-primary scoping, exact initial worker access and
unchanged unrelated default/search-list metadata are enforced. All private runtime
copies, binaries, journals, ticket stores and created Keychains are removed at
closeout; only bounded redacted evidence remains. Observation covers explicit
children and sampled resources, not exhaustive descendants or continuous RSS.

Scope is same host/boot and compatible revision, synthetic content and explicit
opt-in. Default-off performs zero key/store access. Production/auth/consent/wire,
runtime/pins, existing credentials, real effects, Linux/EXO/network/device/VM,
reboot/power loss/hostile rollback, migration, release and later phases remain out
of scope. Keeper Held.
