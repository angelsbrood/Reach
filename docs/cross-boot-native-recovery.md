# Ordinary native recovery across reboot

`reachd durable-native-recovery` is the explicit
`reach-native-recovery-qualification-v1` lane. It resumes one ordinary tiny-Llama
generation using original v5 role keys, an original signed host admission and
client acceptance, and the unchanged S99 cooperating-witness time policy.
Qualification execution and terminal Architecture acceptance are recorded in the
private S101 handback; the implementation alone is not an execution verdict.

S102 adds a separately qualified closed schema-guided route to this same explicit
lane. See [Schema-guided native recovery](cross-boot-schema-recovery.md) for its
bounds, pending-token checkpoint and cold-reboot gates.
S103 adds [one required-tool recovery](cross-boot-required-recovery.md), with
private generating/ready checkpoints and one durable registration without effects.

The original declaration freezes the request input digest, artifact declaration,
operation identity and exact prepared ProviderBinding before either independent
primary/reference admission. The S101 artifact selection uses a 256-token prefill
unit and at most 20 output tokens. Original input must fit that single unit.
This accounts for every model call without changing the preparation or native
algorithms; existing artifact profiles retain their 64-token prefill policy.

The native lane has distinct bootstrap/receipt, catalog/request, host-store,
client retention/snapshot and recovery-envelope versions and domains. Legacy
entrypoints refuse it. S100 retains its preparing/empty authentication scope.
There is no migration, profile promotion or effect executor.

Each receiver owner retains one serial S99 verifier and its invalidation/count
state. Every live host, provider, lifecycle and client resource retains an opaque
binding to its opening authority owner. Fresh actions from another same-scope
owner cannot replace that owner; resources must close and reopen. Reusable
boundaries enforce their permitted operations before IO or publication, so
original admission/acceptance actions cannot operate existing generation state.
Opaque action handles bind the original pair and admission to the current
pending challenge. Root selection, native reconstruction and each native unit,
store selection/acknowledgement, replay, client receipt and publication check the
current action. Root lifetime exclusion remains held, with exact original ready
receipt/state comparisons at boundaries. Key transactions recheck and relock
before final output. Certificates never become lifecycle clocks or persisted
observations.

Recovery reopens the original selected candidate and reconciles uncertain disk
selection. A committed host batch ahead of the client is replayed before native
advancement. Candidate commitment precedes provider acknowledgement. An expired
or invalidated action cannot authorize a retry; a fresh eligible action must
resolve authenticated disk state first. Native-to-commit failure may leave the
old candidate selected; a commit-to-publication failure may leave the new one.
Neither case manufactures rollback or a second original admission.

Admission times, last contact/observation, queue and absolute deadlines remain
original. Owner/attachment epochs and committed output may advance. Terminal
retention ends at the original host deadline. The client retains its separate
original deadline, issuer pin, successful host-export digest and ticket envelope.
Ordinary replay rejects tool/effect state. Terminal selection precedes the artifact and
provider factory, allowing a separate replay worker with model reads denied.

`Tools/CrossBootNativeRecovery/run_vm.py` uses the unchanged owned VM recipe,
four build jobs, one 4-CPU/8-GiB guest and serial role pairs. Guest originals,
model/compiler inputs and TMPDIR stay in a UID503-owned home tree across reboot.
Postboot denies original request/control-preimage reads while allowing exact
model reconstruction; terminal replay additionally denies model reads.
Original-key retirement remains independent of execution expiry or witness loss.
The runner retains ordinary process joins, failures, read-denial probes,
resource samples and cleanup evidence without claiming exhaustive opaque
compiler descendant history or exclusive copy-on-write accounting.

Production/default adoption, deployed witness service availability, broader
routes, tool/effect recovery, release and Keeper remain outside this lane.
