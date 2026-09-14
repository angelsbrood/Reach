# Schema-guided native recovery across reboot

S102 extends the explicit `reachd durable-native-recovery` qualification lane to
canonical portable JSON-schema generation. It retains the
`reach-native-recovery-qualification-v1` profile, original v5 role keys, signed
host admission, client acceptance and S99 witness authority. The private S102
handback records execution and review verdicts separately from this capability.
The separate [S103 required-tool qualification](cross-boot-required-recovery.md)
uses the same entrypoint with distinct whole-call and registration boundaries.

Admission accepts ordinary generation with its existing 256-token prefill and
1–20 output-token bounds, or schema-guided generation with 1–256 prepared input
tokens, a 256-token prefill and a 1–32 generation-token budget. The guided budget
includes intercepted EOS. A provider declaration remains at most 16 KiB.
Within the schema-only route, structural-tag and literal-fixture specifications,
tools and combined schema/tool requests are refused. Schema client receipts
continue to reject tool registrations and effect events. Default artifact profiles retain prefill 64.

`NativeRecoveryBinding` applies the closed declaration at runtime, native store
identity and lifecycle admission/reopen boundaries. It reconstructs the public
JSON-schema specification to compare the otherwise internal kind/compiler
fields and requires the canonical portable schema encoding. The existing full
`RequestPreparation.validateStored` comparison still checks the selected model,
input digest, vocabulary, tokenizer, codecs, grammar and native options before a
factory is invoked. Generation, sampling, grammar replay and checkpoint formats
are unchanged.

`probe-guided-fixture` runs the normal daemon empirically before any originals.
The selected small object has an enum value `中`, schema inclusion in the prompt
disabled, and a 32-token budget. Independent preparation passes must produce the
same complete declaration before primary and reference originals are admitted.
`run --stop-with-pending-guided --leave-host-ahead` requires an active committed
checkpoint, positive model offsets, visible client text and pending forced
acceptances. It publishes the checkpoint report and waits for the controller to
kill and numerically join the worker.

The read-only guided diagnostic is available only for a live validated native
child whose captured bytes match its exact acknowledged selected candidate.
It records commit/checkpoint identities, grammar/text/model digests, cache
offsets, accepted token origins and consumed, sampled, forced and ending counts.
It supplies evidence without selecting state or granting execution authority.
After cold reboot, the runner requires identical saved diagnostic state, consumes
the pending forced suffix before further sampling, and compares completed native
event bytes with an independent uninterrupted reference. Successful completion
requires grammar-accepted EOS within the budget.

The original serial verifier, resource-owner bindings and operation guards remain
in force. Recovery replays committed host output before native advancement;
commitment precedes provider acknowledgement and client publication. Every
boundary retains the S99 action-age ceiling, strict checks against both original
deadlines, and original root/key/ticket/witness bindings. No request preparation,
template rendering, request tokenization, new admission or prefill occurs after
reboot. Model reload and matcher reconstruction remain distinct from those
prohibited operations. A separate terminal worker denies model reads and performs
no native work.

`Tools/CrossBootSchemaRecovery/run_vm.py` uses the unchanged owned VM primitives
with one 4-CPU/8-GiB guest and serial role pairs. It repeats fixture feasibility in
the guest before starting the witness, performs the cold-reboot/reference and
terminal gates, and exercises an eleven-second native-to-commit delay while a
guided forced suffix is pending. A refusal does not claim rollback: disk state
requires authenticated reconciliation. Unchanged broader expiry/loss evidence is
identified explicitly in the handback rather than counted as new runner passes.

Guest data, original keys, compiler inputs and TMPDIR stay under the private
UID503 home tree across reboot and original-key retirement. The runner retains
failed attempts, joins and resource samples, verifies original-key and payload
removal, and disposes the owned clone. This qualification does not open default
adoption, deployed witness availability, tools/effects, format migration, release
or Keeper work.
