# Native recovery through a local witness

The explicit `durable-native-recovery` qualification commands can obtain authority
from the local `witness-access-qualification service`. This selection supports ordinary text generation and the existing canonical
schema-only guided lane. A receiver can resume the same durable generation after
its predecessor exits while the original service remains alive in the same boot.
It does not make the service or its private key persistent across an OS reboot.

The existing controller-pipe qualification remains selected when neither witness
option is present. Existing guided, required, allowed and schema/tool pipe
qualifications retain their existing scope.

## Select the original witness

A trusted launcher starts the existing service with its finite, complete startup
pair selection. Keep its original descriptor and independently authenticated
SHA256. The endpoint must be a private, same-UID Unix socket under the service's
owned directory; see [witness access](operational-witness-access.md).

Pass both options to native `provision`, `admit`, `accept` and `run`:

```text
--witness-descriptor /owned/control/descriptor.json
--witness-digest <independently supplied SHA256>
```

`provision` also requires `--witness-subject <original UUID>`. It takes the exact
signed pair from that descriptor. Missing options, a wrong digest or an absent
subject refuse. The descriptor is frozen for that receiver invocation; replacing
its file cannot update a running receiver's selection.

Each executable entry validates that the descriptor's selected pair equals the
pair in the original scope, including both signed registrations and their full
issuer pin. Matching only a key, subject or deadline is insufficient. Complete binding
validation reconstructs the public JSON-schema specification; a guided route tag
alone cannot admit structural tags, literal fixtures or other guided kinds.
Ordinary input/output bounds remain 256/20 tokens; schema input/generated-input
bounds remain 256/32, including intercepted EOS. Both use prefill step 256.

Required, allowed and combined schema/tool routes, and the separate prescribed
qualification factory, refuse before credential access, native construction or
executable storage work. The same early check rejects tool-boundary options,
duplicate delivery and the next-pass native fault. `--stop-with-pending-guided`
requires a schema lane in the exact authenticated original receipt provision.
This option/route join precedes leases and unlock-secret reads; bounded receipt
metadata reads needed to make that decision are allowed.

`init` and original-key retirement keep their existing ownership checks. They do
not require a live witness. Preserve the original daemon path and executable bytes
until every original role has been retired.

## Exchange and failure behavior

The adapter uses the existing `GenerationAuthorityOwner` and its action request.
It starts one five-second `IODeadline` at the action's original receiver sample,
using the same clock as that owner. Connect, transfer, framing, EOF and signature
verification are charged to that bracket. No second verifier or action counter
is created. Existing ten-second action-age checks, original expiry comparisons,
root and owner fences, and commit/publication checks remain in force.

Transport errors, refusal, invalid signatures or pins, malformed replies and
clock faults latch witness loss on that owner. Later endpoint availability cannot
revive that owner or its old actions. A fresh process must present a fresh
challenge for the same originals. A replacement issuer cannot answer for them.

A normal EOF completing one reply does not prove service loss. If the service dies
after a completed exchange, the receiver may discover that at its next exchange;
the completed action retains only its existing bounded eligibility. The adapter
does not continuously observe the service.

Socket-mode stdin accepts the existing pause/continue controls, never controller
certificates or affirmative witness observations. `socket-authority` output records
transport verification only. Its `afterReceive` sample is a separate diagnostic
observation, not the verifier's r1 or a prospective-use verdict. Initial reopen
failure now produces the existing bounded `native-refusal` counters as well.

## Disposable guest qualification

`Tools/NativeWitnessRecovery/run.py` imports the existing VM lifecycle primitives.
Supply the built normal daemon, unchanged service product, selected cached tiny
fixture and metallib, an owned scratch directory, a private retained
evidence directory, the authenticated opening baseline and the free-space sample
from before scratch preparation. `--lane ordinary|schema` is closed and defaults
to ordinary. The lane follows every phase, including cleanup, and is recorded in
inputs and evidence. Ownership prefixes are fixed: S107 for ordinary and S108 for
schema; the runner does not accept an arbitrary prefix. Its `--help` lists the
required arguments. `--campaign loss` and
`--campaign retirement` select focused fresh-original retries; their PASS covers
only those gates, and must be combined with authenticated unchanged evidence
for a complete qualification.
The runner uses one 4-vCPU/8-GiB guest, UID 503; it does not reboot it.

Each service or receiver receives its complete sandbox at launch. Only the exact
owned Unix endpoint is allowed; other Unix endpoints and IPv4/IPv6 are denied.
The controller uses the existing Tart control pipe and never relays certificates.
Do not place it beneath a deny-all network policy and try to relax child policies.
The guest probes socket access before originals. Native role operations retain
the accepted nonsecret default/search-list Keychain metadata APIs; service and
network-probe processes additionally deny data opens beneath default Keychains.

Both lanes freeze independent primary/reference preparation before admission.
Ordinary retains its eight-call cut. Schema uses the complete retained tiny-Llama
schema fixture and first runs the normal daemon's `probe-guided-fixture`, before
service originals or roles exist. This freezes a semantic cut with a visible
prefix and pending forced suffix, accepted-EOS completion, and measured frame,
action and nonce headroom. Historical call counts are not an acceptance gate.

The campaign kills and joins a receiver with a committed host batch ahead of its
client, then resumes through the surviving original service. It checks a fresh
receiver incarnation, nonce and original r0, positive-offset restore, replay
before native work and exact ordered event payload bytes against the independent
reference. Schema additionally checks exact initial saved guided state, one
forced-token consumption per advance without resampling, complete native traces
and guided progress, and one accepted EOS with no pending tokens. A valid JSON
prefix alone does not establish successful completion.

Terminal replay denies model and original-request reads and performs no native
or guided work. Serial fresh
pairs check independent original expiry, an eleven-second pause after native work,
actual service loss at a subsequent exchange and an available replacement issuer.

Reports and ordinary logs retain failed attempts. Every created original role
must retire under its original ownership and executable, including expiry and
loss cases. Cleanup compares guest default/search-list metadata, removes secrets
and payload, numerically joins known processes, verifies the guest network gate and disposes the clone. An unrelated sentinel
inside the owned payload but outside the role roots must survive product
retirement; it is then removed with that explicitly owned payload. Containment deletion alone is not retirement.
If retirement fails, the runner retains the owned VM for correction; do not delete
that clone to manufacture a successful cleanup.

Use the private terminal handback for exact candidate hashes and earned results.
Passing unit tests or the pre-original socket probe alone does not establish native
continuation acceptance or terminal Architecture PASS.
