# Native recovery through a local witness

The explicit `durable-native-recovery` qualification commands can obtain authority
from the local `witness-access-qualification service`. This selection supports ordinary text generation, canonical schema-only guided
generation and canonical sole-tool required generation. A receiver can resume the same durable generation after
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
validation reconstructs the public schema or required-tool specification and
validates the stored request, tool identity, schema, options and tokenizer. A
route tag alone cannot admit a different specification or a literal fixture.
Ordinary input/output bounds remain 256/20 tokens; schema input/generated-input
bounds remain 256/32, including intercepted EOS. Required uses exactly one tool
with no response schema, 1–512 prepared input tokens and 1–48 generated inputs,
including accepted EOS. All three use prefill step 256.

Allowed and combined schema/tool routes, the separate prescribed qualification
factory, allowed-tool boundaries and the next-pass native fault refuse before
credential access, native construction or executable storage work.
`--stop-with-pending-guided` requires a schema lane in the exact authenticated
original receipt provision. `--required-boundary` accepts only `none`,
`generating`, `ready` or `emitted`; a selected required boundary requires the
required route and cannot combine with a pending-guided or numeric cut.
`--duplicate-exact` requires required recovery and refuses with `--original`,
a numeric cut, pending-guided cut or any required boundary. This option/route
join precedes leases and unlock-secret reads; bounded receipt metadata reads
needed to make that decision are allowed. Duplicate eligibility is then checked
against encrypted durable terminal state before any model factory is entered.
Receipt metadata alone cannot establish that the generation is terminal.

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
from before scratch preparation. `--lane ordinary|schema|required` is closed and defaults
to ordinary. The lane follows every phase, including cleanup, and is recorded in
inputs and evidence. Ownership prefixes are fixed: S107 for ordinary, S108 for schema and S109 for
required; the runner does not accept an arbitrary prefix. Its `--help` lists the
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

All lanes freeze independent primary/reference preparation before admission.
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

Required uses the complete retained tiny-Llama required fixture. The current
normal daemon prepares two independent bindings and runs `probe-required-fixture`
on the host before VM clone, then repeats this in the guest before service
originals or roles. Preparation bytes must match within each platform; host and
guest backend identities may differ. The probe establishes a private generating
cut with a positive offset and a multi-token forced suffix, accepted-EOS ready
state, bounded frames, and measured action and service nonce headroom. For final
consumption M and cut consumption C, positive receiver action counts are C+2,
M−C+1, 2, 2, 2 and M+3. Including two admissions and two accepts, the primary and
reference consume 2M+16 requests, at most 112; no receiver exceeds 51 of the
existing 64 actions. The service retains its existing 128-nonce limit.

Required kills and joins the private generating receiver with both high-water
marks zero and no registered call. A fresh receiver restores the exact saved
state and drains each forced token in a separate advance without resampling.
Each generating advance performs at most one forward; the existing prepare
action performs up to two prefills. After accepted EOS, ready state still has
no delivered events or call registration. Another fresh receiver restores ready
and emits the exact call, usage and complete batch with zero forwards, leaving
host high-water 3 and client high-water 0. Model/input-denied terminal replay
then delivers all three events with exactly one registration. A separate exact
duplicate repeats neither registration nor native work and preserves the selected
commit, client receipt and inbox. An independently admitted uninterrupted
reference must match every required progress value, native offset, input digest
and ordered event byte, including original entry/call IDs and arguments.

Terminal replay denies model and original-request reads and performs no native
or guided work. The required lane also refuses an exact duplicate against active
durable state before model construction. Serial fresh
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
