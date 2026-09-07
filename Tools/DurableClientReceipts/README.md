# Durable client receipts: S83 local candidate

`run.py --repo /path/to/Reach` builds an offline Foundation/CryptoKit package in
owned private scratch. It copies the source-bound WireEvent.swift byte-exact,
runs XCTest, then supervises actual worker deaths with an independent surviving
fake-effect counter. It retains bounded logs/evidence and removes source, build
and journal fixtures after joining its explicit children. No native dependencies,
network, model, Keychain or real tools are used.

The synchronous, serial `DurableClientReceipts` owner accepts a separately supplied
immutable `ClientAuthority` and fresh `ClientAuthorization` on every caller API.
The trusted supervisor must retain the original authority and random metadata key
across compatible-revision, same-host, same-boot worker recovery. Keys belong in
memory/anonymous pipes. Context binds exact caller, host/store/session/generation,
request/operation, upstream digest, route/projection/revision and original expiry.
The adapter does not verify an opaque S82 ticket. Renew with a fresh namespace.

`open`, `accept`, `inbox`, `receipt`, `effect`, `beginEffect`, `recordOutcome`,
`maintenance` and `close` form the local API. A receipt certifies the complete
original batch and its calls are durably registered in this adapter-owned inbox.
It does not certify display, forwarding, app database commitment or tool execution.
It is neither EvAck nor a wire token. Inbox reads may be repeated. Exact replay
preserves the receipt and effect state; resegmentation, unknown skipped prefixes,
changed UTF-8 bytes, call aliases, context changes and advanced cursors refuse.

Calls progress from unbegun to persisted intent/outcome-unknown, then to explicitly
known success/failure. Only the first successful intent decision returns fresh
permission. Lost replies never automatically reissue it; an effect could have
happened or not. Known outcomes require exact call bindings and typed bytes with
a recomputed domain-separated digest. The library does not execute or query tools.
A cooperating caller consumes permission once; this is not universal exactly-once
execution. Model completion/cancellation does not discharge the tool obligation.

One encrypted root manifest selects immutable encrypted generation snapshots.
AES-256-GCM authenticates root/boot/policy/role/generation/record/revision. A separate
HKDF-derived ownership MAC allows verification and deletion of unselected orphan
ciphertext without restoring erased content keys. Per-generation keys exist only
in the encrypted manifest and memory. No prepared/older-current fallback exists.
Every API reloads current and reconciles rename/sync uncertainty before a decision.
Files are owned 0600 single-link regular roles beneath an owned 0700 root, with
fd-relative no-follow access and a stable close-on-exec process-lifetime flock.
Owner epochs invalidate handles from a previous owner. Callers must serialize APIs
and must not reenter from fault hooks; arbitrary hostile same-user/ancestor races
are outside this cooperating-owner candidate.

Capacity includes actual allocated files plus conservative 64 KiB allocation
rounding, two copies of each maximum future snapshot, metadata/retirement room and
the actual base64-encoded maximum future outcome for every unresolved call.
Unbegun calls reserve outcome space at registration, before permission can exist.
These global credits cannot be borrowed by admission. Lower quotas may refuse well
before nominal independent maxima; refusals are whole transactions. No unexpired
knowledge is evicted. I/O failure may still leave unknown state, never success.

At maintenance after original session expiry, current first drops identity and
generation keys and retains bounded opaque cleanup locators. Authenticated old
prepared roles are removed; exact content deletion retries survive interruption.
An offline/unavailable key cannot promise timely erasure. This makes no SSD/backup
erasure, memory-zeroization, reboot, power-loss or hostile-rollback claim.

Evidence is new CPU adapter tests and actual worker deaths, with source-faithful
S80/S81 fixtures. It reuses unchanged S72–S82 dependency/native evidence; it does
not execute an S82-to-client join or make the host consume durable receipts.
Production app/auth/key storage, real tool effects, wire/runtime/pins, receipt
consumption, consent/retention policy, release and later phases remain outside S83.
