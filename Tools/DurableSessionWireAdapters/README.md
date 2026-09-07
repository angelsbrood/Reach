# S88 durable-session wire adapters

Offline local same-boot adapter candidate for explicit dialect 2. Shipping offers
remain `[1,0]`; no production transport, capability, consent or general request
preparer is adopted. Separate host/client adapters use the real ReachWire binary
codec and accepted S82–S86 lifecycle, encrypted journals and bootstrap/recovery.

The only request mappings are deterministic `ordinary` and `required` tiny-native
fixtures. Complete canonical request, original request UUID, configured model,
profile, route and adapter revision bind the stored ProviderBinding request ID;
operation ID remains explicit. Ticket namespace is issuer-verified, not a new
session registry. Fresh client entry takes bootstrap location and current local
caller/opt-in only. Its original ticket/context come from selected encrypted disk
state and stay pending until the actual matching host recovery reply.

`WireSessionProjection` verifies current exact caller/ticket/clock and publication,
and projects the S84 original context before attach using the same accepted
upstream-binding derivation. The real export is checked again after attach.
Receipt retry uses S84's tombstone fingerprint directly, without live context or
request export after retirement. Peer tool knowledge is a checked read-only report;
it cannot grant effect permission, change local intent/outcome or attest execution.

The supervisor's binary lane carries actual frames, without a second base64 JSON
wrapper. Local control traffic only selects fixture commands, steps/faults workers
and observes counters. The native reference/recovery and required-tool cells are
separate. Recovery must make positive new native calls before comparison. The
counted fake effect is performed only after one fresh local S83 permission; its
trusted completion oracle is separate from incoming wire knowledge.

Run from the repository:

```sh
python3 Tools/DurableSessionWireAdapters/run.py --repo /absolute/Reach
```

`--tests-only` runs focused adapter/wire tests without Keychain worker cells.
The runner reuses authenticated local composition helpers and six pins, rebuilds
the unchanged 35 dependency outputs in owned disposable copies, and binds all
nine current wire source files. Client and Keychain workers must not link MLX.
Workers acquire fresh scoped disposable Keychain records through unchanged S85
implementations; keys never leave owning workers. Existing S85/S86 guard files
are copied unchanged. S88 glue owns the new fixed roots, names and frozen access.

One build/test/native host at a time; four jobs, 16 GiB owned allocation, 3 GiB
fixtures, 20 GiB sampled free space, 192 MiB per log/evidence file, 128 MiB tiny
weights/native allocator peak. At most one explicit owned Keychain is used here,
with no existing credentials, login/default/search-list changes or interactive
unlock. Cleanup retains original created references and preserves unrelated
metadata. Logs/results distinguish executed proof, historical reuse and failures.
Only explicit owned commands and sampled allocation/cleanup boundaries are claimed;
there is no continuous RSS, exhaustive descendant, remote-clock or exactly-once proof.
