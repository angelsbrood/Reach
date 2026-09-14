# Allowed-tool native recovery across reboot

S104 adds a bounded allowed-tool route to the explicit native recovery
qualification. It accepts one offered portable tool, no response schema, and
zero or one complete observed proposals. Execution and terminal review verdicts
are recorded in the private S104 handback; this description is not an execution
verdict.

The combined request extension is described in
[Combined schema and tool recovery](cross-boot-schema-tool-recovery.md).

There are two distinct executions. `reachd durable-native-recovery` uses the
existing tiny Llama artifact for no-call prose recovery. The separate
`reach-allowed-recovery-fixture` executable uses the prescribed native state
model `s104-structural-allowed-v1` for probe-to-guided integration. The latter
reuses the S91/S79 position/running-state algorithm and codec
`s79.fixture.state:position-running-v1:1`, with dimension four and immutable
probe/tool-0 scripts bound to its configuration and executable hash. It does not
establish learned Llama tool selection. The ordinary daemon has no fixture
selection switch and rejects that model/configuration.

Both use the existing `reach-native-recovery-qualification-v1` authority profile,
original v5 roles, admission, receipts, witness, action clock and checkpoint
formats. Original input and each exact derived repair input must contain 1–512
tokens. Both phases use prefill 256 and the same requested maximum of 1–64;
the probe is not given a separate larger budget. A repair is checked before its
model factory/native preparation. Provider bytes stay within 16 KiB, canonical
control and step frames within 64 KiB, and native allocation within 128 MiB.

The provider exposes read-only progress only for its exact acknowledged
candidate and fully validated native child. It retains complete proposals,
probe parsing/lookahead, current repair input and identity, whole envelope,
guided pending work, completed call and aggregate usage. Multiple proposals
refuse before guided preparation or publication; no prefix is truncated. The
existing coordinator's all-name check remains in force. The selected JSON
parser can filter unoffered names before that check; the focused XML coordinator
test covers the existing unknown-name error path without opening XML as a new
durable preparation format.

Probe and guided advances are grouped in units of at most two under one fresh
action. Each advance retains the native check, commit, acknowledgement, delivery
and receipt boundary. A phase change ends the unit. Initial and tool-0
preparation are separate actions with at most two prefill forwards; finalReady
delivery is another action with zero native forwards. The whole action retains
the ten-second ceiling. Owner, nonce and witness-registration limits remain
64, 128 and 16. The runner derives actual costs from pre-original feasibility
steps and requires at least two owner actions and eight nonces of headroom.

Recovery validates the original stored request and selected child without
encoding the original request/template or prefilling. Reconstructing an
authenticated repair is legitimate and counted separately. Restored pending
forced tokens must be consumed before new sampling. A fresh finalReady worker
loads and validates the saved model/child, then emits without native work.
Terminal replay selects durable bytes before the model factory and runs with
model and original-input reads denied.

The signed original binds request, operation, entry, namespace, sole tool and
canonical schema. The chosen proposal ID and exact aggregate usage come from
validated native history. The model-free client checks their structural bounds;
it does not claim that the original signed a later proposal ID or implement a
schema engine. It preserves probe prose and accepts either zero-call completion,
error/cancellation, or the one atomic whole-call/usage/complete batch. Host
publication checks exact selected ID, call and usage. Receipt/reopen validation
requires exact prefix, call digest, count and terminal state, with no intents or
outcomes. Exact duplicate replay preserves the inbox and zero/one registration.

`Tools/CrossBootAllowedRecovery/run_vm.py` uses one disposable four-CPU/eight-GiB
VM. Each primary and reference has a separate original witness and role pair;
all pairs run serially. The normal primary crosses a cold reboot with positive
probe state and delivered prose. The fixture primary crosses a probe reboot,
prepares its original tool-0 pass, and crosses another cold reboot with pending
guided work. Its original witness survives both reboots. Fresh ready, terminal
and duplicate workers follow. The independent uninterrupted reference uses one
generation owner and must match every event byte and per-pass native input and
offset. A separate fault pair pauses after actual tool-0 prefill for eleven
seconds and must refuse publication, retaining the last accepted commit and
honest disk-reconciliation uncertainty.

Focused tests include cancellation, shared-budget guided exhaustion after a
successful probe, and a complete envelope without accepted EOS. Failed guidance
preserves earlier prose and publishes no call or success usage. Ordinary,
schema and required regression coverage remains separate and unchanged evidence
is reused only for unchanged dependencies.

Original keys are created only in the owned UID503 guest tree and retired
through their original receipts/executables before payload and clone disposal.
Evidence retains observed numeric process joins, unchanged Keychain metadata,
sampled resource bounds and failed attempts. It does not claim exhaustive opaque
descendants, exclusive copy-on-write accounting, production/default adoption,
deployed witness availability, tool effects, migration, release or Keeper work.
