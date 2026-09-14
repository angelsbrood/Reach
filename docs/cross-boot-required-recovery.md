# Required-tool recovery across reboot

S103 extends `reachd durable-native-recovery` to one required tool, without a
response schema. It retains the explicit
`reach-native-recovery-qualification-v1` profile, original v5 role keys, signed
host admission, client acceptance and S99 witness policy. Execution and terminal
review verdicts belong in the private S103 handback; this capability description
does not claim that the reboot qualification has passed.

The required route accepts 1–512 prepared input tokens, prefill 256 and a 1–48
consumed-token budget including accepted EOS. Initial preparation may perform two
prefill forwards inside one existing ten-second action. Each generating advance
performs at most one forward; accepted EOS and ready delivery perform none.
Ordinary remains input 1–256/output 1–20; schema-only remains input 1–256/budget
1–32. Legacy artifact profiles retain prefill 64. Provider declarations remain
at most 16 KiB and canonical control frames at most 64 KiB.

`NativeRecoveryBinding` reconstructs the structural specification from the sole
original portable tool schema. The complete stored-request comparison still
validates model, tokenizer, input, stable IDs, codecs and native options before
the model factory. Allowed-tool selection, multiple offered tools, combined
schema/tool routes and arbitrary structural specifications remain outside this
qualification. Native generation and checkpoint algorithms and formats are
unchanged.

The existing coordinator has three distinct states:

1. **Generating** retains a private whole envelope and validated guided child.
   Its checkpoint can contain positive native work and pending forced tokens
   while host and client event high-water marks remain zero.
2. **Ready** follows accepted EOS and exact call parsing. It retains the complete
   call but has no public events. A fresh ready worker may load the model and
   validate the saved child; its next advance emits without a native forward.
3. **Emitted** retains the atomic call-arguments, usage and finished-complete
   batch. Terminal replay resolves this durable batch before the runtime factory
   and can run with all model and original-input reads denied.

The client projects call identity from the original signed provider without a
model dependency. Entry/call IDs, request/operation, sole name and schema source
remain original. Schema provenance is checked here; argument/schema acceptance
remains the required coordinator's accepted-EOS validation. The native inbox
accepts either the exact whole success batch or one error/cancelled ending.
Partial, extra, mixed, conflicting and contradictory batches refuse.

Persisted `live.calls`, snapshot registrations and witness call digests must
agree. Every retained native call must have no intent and no outcome. Host receipt
validation derives exact registrations, replay/call digests and terminal status
from the selected prefix, including when reopening a retained receipt. Exact
duplicate delivery retains one registration and the same inbox and receipt.
Ordinary and schema native contexts continue to allow zero calls. The native
owner grants no effect API, and legacy effect APIs reject native authority.

`probe-required-fixture` runs the normal daemon before any campaign witness,
admission or role Keychain. Two independent preparations must match. The probe
measures the whole initial preparation, per-step work, provider/checkpoint/frame
sizes and allocator peak, then validates fresh ready restore and zero-forward
whole delivery. Validated required progress is read-only and bound to the exact
acknowledged child. Each step is retained in its own bounded file; final reports
contain only initial/latest progress and file hashes.

`Tools/CrossBootRequiredRecovery/run_vm.py` uses the existing owned VM recipe with
one 4-vCPU/8-GiB guest. The guest repeats feasibility and counts the chosen
certificate protocol before originals. For a successful fixture consuming M
tokens, the primary uses M+11 certificates and the reference M+5; at M=48 their
combined 112 leaves headroom below 128. Every owner remains below 64 actions and
the primary/reference witness registers four roles below its 16-role ceiling.

The runner selects `run --required-boundary generating --leave-host-ahead`, joins
the closed/relocked checkpoint worker, and cold reboots the receiver while the
original witness survives. It restores the exact private state, consumes any
saved forced suffix before resampling, and stops at durable ready. A fresh worker
selects `--required-boundary emitted --leave-host-ahead` to leave the terminal
batch ahead of the client. Two model-denied workers then replay and apply
`--duplicate-exact`. An independently admitted uninterrupted reference must match
the exact event bytes and all native continuation offsets/input digests.

The qualification also requires an eleven-second active required native delay
to refuse publication, and real-native exhaustion to emit no call or success
usage, including a complete envelope without accepted EOS when the fixture
permits it. Refusals retain observed work and report uncertain disk state rather
than claiming rollback. Original deadlines, witness-loss latches, resource-owner
bindings and commit-before-ack ordering remain unchanged.

Test roles are created serially inside a private UID503 guest tree. All original
test keys are retired through their original ownership receipts before payload
and owned-clone disposal. Evidence includes numeric joins for exposed processes,
unchanged Keychain metadata and sampled allocation; it does not claim exhaustive
opaque descendants or exclusive copy-on-write accounting. Default adoption,
deployed witness availability, tool effects, migration, release and Keeper remain
outside this qualification.
