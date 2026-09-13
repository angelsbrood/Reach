# Conservative cross-boot clock-policy candidate

S99 supplies an isolated feasibility candidate for **new** original registrations
under an independently surviving monotonic witness. It leaves every existing
Reach runtime byte, versioned format and old-boot refusal unchanged. Its
qualification does not accept deployed timekeeping, ownership fencing, native
generation recovery or a later phase. Keeper remains Held.

S100 uses this unchanged clock contract in the explicitly selected
[recovery-authority lane](cross-boot-recovery-authority.md) for new original
allocating/preparing records. Its authority guard remains separate from scalar
runtime clocks and native continuation.

## Conditional contract

The exact versioned qualification profile binds:

| Field | Value |
| --- | --- |
| Domain | `reach-clock-qualification-v1` |
| Units | `continuous-monotonic-ns` |
| Rate factor | `2` |
| Additive error allowance | `1_000_000_000 ns` |
| Maximum certificate age | `10_000_000_000 receiver ns` |
| Maximum original cap | `86_400_000_000_000 ns` (24 hours) |

The selected cooperating-rig assumption is
`Delta witness <= 2 * Delta receiver + 1_000_000_000 ns`. It is an explicit
assumption about elapsed time during certificate use. It is not an Apple
platform guarantee, a measured worst-case bound, or an implication of placing
the witness and receiver on the same Mac. A finite campaign can observe a
violation; it cannot prove this inequality for every future interval.

For a pending request sent at receiver sample `r0`, a signed witness sample `w`,
receipt sample `r1`, and current action guard sample `r`, compute with checked
unsigned arithmetic:

```text
U(r) = w + 2 * (r - r0) + 1_000_000_000
eligible iff U(r) < originalHostDeadline
         and U(r) < originalClientRetentionDeadline
```

The witness samples after receiving and selecting the request. Charging all
receiver elapsed time from the send sample therefore includes outbound transit,
witness work, response delay, bounded decoding/signature verification, and later
blocking work. Neither symmetric transit nor a receipt-time reset is assumed.
Equality with either original deadline refuses. A short original window can be
conservatively unavailable before its actual deadline.

Every guard requires the same receiver boot and process, no observed clock
regression, `r >= r1 >= r0`, and `r - r0 <= 10 seconds`. At the age cap the charge
is **21 witness-clock seconds**. This cap is measured in receiver-clock time;
it is not a ten-second wall-time promise. Overflow, missing evidence, malformed
or oversized data, excessive age, wrong binding and signature failure refuse.

## Original authority and local action state

Before reboot, the witness signs independent host and client registrations for
the same original fixture subject. Each record binds its role, full profile,
witness public key/boot/process/epoch, original witness anchor, cap and deadline.
The registry key is original subject plus role. Re-registration can return the
exact original bytes for the same cap or refuse, including after expiry; it
cannot move the anchor. The original registration pair validates signatures,
roles, subject equality, cap and checked deadline arithmetic.

The receiver retains these exact signed bytes and the initially provisioned pin.
Each new local action generates a nonce, serializes a challenge, and samples
`r0` immediately before returning it for transport. The signature covers a
distinct certificate domain, exact profile and original registration digests,
witness identity, receiver boot/process, nonce, operation purpose and witness
sample. The receiver samples `r1` after signature and selection checks.

An opaque `Action` belongs to one verifier's pending request. It is not Codable.
The serial verifier admits only one outstanding action; repeat guards retain
that action's `r0` and `r1`. Finishing it discards the certificate. A new action
has a new nonce, and a replayed response cannot satisfy its challenge. A newly
obtained certificate can reduce uncertainty while preserving both original
deadlines. A historical scalar evaluation is diagnostic JSON and cannot be
imported as a certificate or as current authorization.

A new receiver process or boot creates a new bracket using the originals. A
changed receiver identity or observed regression invalidates an existing
verifier. The system clock samples `mach_continuous_time`, converts with checked
quotient/remainder arithmetic, and reads the current Darwin boot UUID. The
witness's ephemeral signing key is never persisted, logged or exported. Its
in-memory clock tracker latches boot/process/regression faults. An unrelated
witness has no API for importing an old registration registry.

## Witness-loss boundary

Observed loss, changed witness identity/epoch or an authenticated inconsistent
response invalidates the affected verifier incarnation. The implementation also
invalidates on malformed or unauthentic responses, so a failed acquisition does
not leave an older certificate usable. The caller must deliver observed
transport loss to `observeWitnessLoss()`; the API does not invent a failure
detector. Witness replacement cannot adopt the original pin or reissue its
registrations.

If a witness fails after signing and the verifier has **not observed** that
failure, a verified certificate can remain usable for its same action, subject
to its original send-age bound, clock assumptions and original deadlines.
Silence cannot renew this interval. The qualification controller deliberately
withholds the loss observation from one verifier, while delivering it to another,
to test these distinct behaviors. Neither behavior supplies ownership fencing,
instantaneous revocation or authority to execute a generation.

## Qualification evidence and limits

The [package README](../Tools/CrossBootTimePolicy/README.md) describes the build,
fixed commands, resource bounds and reproducible serial runner. Evidence has
three distinct kinds:

| Gate | What it demonstrates |
| --- | --- |
| Focused package tests | Deterministic bounds, edges, signatures/bindings, rollback and loss behavior, including an explicit violating-rate counterexample |
| Actual signed delays | A response signed while conservatively eligible refuses after host expiry; a post-blocking action refuses after client expiry using its unchanged send bracket; signature-only controls expose stale decisions |
| Actual receiver cold reboot | The same owned guest has a different boot UUID and receiver process while the original host witness process/boot/epoch survives; unchanged signed registrations admit fresh positive bounds, then independent expiry and replacement refusal |

The runner records witness samples inside receiver request brackets. Comparisons
between later same-boot receiver samples report observed elapsed intervals and
whether the assumed bound is visibly violated. These observations do not turn
calibration into a universal guarantee. Injected-clock tests are not actual
freshness or reboot evidence. Guest network gating and known process joins are
reported with their observation limits; no exhaustive boot packet or opaque
process-descendant history is asserted.

The 12 September 2026 implementation qualification earned 25/25 focused XCTest
passes, both real signed-delay refusal cases, and one successful cold-reboot
campaign with unchanged original registrations. The postboot campaign earned
three positive bounds, independent host/client expiry, actual original witness
process exit, bounded unobserved-loss use followed by age refusal, observed-loss
invalidation, and replacement refusal. Five finite same-boot interval comparisons
showed no violation of the selected assumption. The owned guest fixture, clone
and witness processes were disposed. Earlier sandbox, compile and guest-wrapper
failures remain separate in the retained implementation evidence; they are not
relabeled as successful campaigns. These are implementation qualification results
under the selected assumptions.

S99 terminal acceptance requires Planning to authenticate actual products,
unchanged existing tracked bytes, current repository state and retained evidence,
followed by explicit terminal Architecture PASS/BLOCK. The implementation's
campaign PASS alone does not perform that acceptance.

## Required later generation-adoption design

Changing the clock implementation alone cannot authorize old Reach roots after
reboot. A later cut must explicitly select an operational witness and accept its
rate/error/age assumptions, then define new authenticated domains at these seams:

| Existing seam | Required new-profile design |
| --- | --- |
| `DurableStoreBootstrap/RoleBootstrapContract.swift`: `RoleBootstrapCore`, `policy`, `binding()`, boot validation | Authenticate new profile selection, original witness pin/epoch and original registration digests at bootstrap. Keep v1/v2/v3 roots and after-boot cleanup authority exact. |
| `DurableHostStore/StoreContract.swift`: `StoreIdentity.validate()` and stored projections | Bind original host identity, witness-domain expiry and storage authentication without bypassing current boot checks or copying old timestamps into a new domain. |
| `DurableSessionLifecycle/SessionTicket.swift`: ticket claims/codec and lifecycle identity | Bind the new policy, original ticket/lifecycle identity, immutable host deadline and original registration into new authenticated ticket/storage domains. No second begin or reservation may renew expiry. |
| `DurableClientReceipts/IndependentRetention.swift`: `ClientLocalRetention` and independent authority | Bind an immutable original client witness anchor/cap/deadline independently of the host deadline. Host recovery must not extend client retention. |
| `DurableClientReceipts/RecoveryDiscovery.swift` and recovery envelopes | Bind original client manifest, checkpoint, root/pair/ticket and both original registrations. Reopening must authenticate original state under a fresh certificate without rewriting historical authority. |
| `WireAdapterContract/Contract.swift`: configuration, request policy, `BootstrapRecoveryBinding`, frames and effect knowledge | Negotiate the new profile explicitly in authenticated pairing/wire domains. Peer input must not select an implicit policy upgrade. Preserve effect-knowledge and replay bindings. |
| Runtime action guards | Carry a local action bracket through every pre-native, post-blocking, publication, replay and effect-knowledge guard. Recheck immediately before protected use; no saved scalar decision, receipt-time reset or silent action restart. |

The smallest later native qualification must create a **new-profile** generation
with original registrations/deadlines and a committed checkpoint, cold reboot
the receiver, obtain a fresh certificate, and reopen that original authorized
state. Compare continuation and replay against the reference. Prove no second
begin, reservation or renewal; no publication after either applicable expiry;
and no reissue of effects whose outcome is unknown. Include the appropriate
operational witness loss and replacement behavior.

No wall-time translation can migrate historical v1/v2/v3 tickets, retention or
root authority into this candidate. S99 specifies this later test; it does not
execute a synthetic-clock substitute or count a witness demonstration as native
generation recovery.
