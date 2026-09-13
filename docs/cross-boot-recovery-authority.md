# Recovery authority across a receiver reboot

`reachd durable-recovery-authority` explicitly selects
`reach-recovery-authority-qualification-v1` for new original records. It can
create one original admission and authenticate its allocating/preparing host
state and original empty client registration in a fresh process after receiver
reboot, while the original cooperating witness survives. The authentication
command returns bounded metadata describing that state.

This is a qualification lane. Ordinary daemon offers, native/wire profiles,
and existing records keep their original behavior. It does not grant native
continuation, replay or effect authority after reboot. The separate ordinary
`durable-local` smoke establishes same-boot native feasibility.

## Original records and trust

The owned controller first runs one normal-daemon `witness` process. Its signing
key and registry exist only in that process. Through bounded local pipes, it
signs separate original host and client registrations for one pair subject.
Each registration retains its own immutable anchor, cap and deadline. The
[clock-policy contract](cross-boot-time-policy.md) supplies the exact profile,
signatures, nonces, brackets and checked arithmetic.

`provision` binds those exact signed originals to fresh role IDs, a canonical
public model declaration and the original request input digest. Each `init`
creates only its own role root and Keychain, with an external ownership receipt
bound to the frozen executable. Keep the receipt's digest from successful
initialization outside the removable root. Credential input is an owned mode
0600 regular file, 32–128 ASCII alphanumeric bytes, passed through a caller-owned
read-only descriptor; it is consumed and closed, never serialized in records.

Original host `admit` loads the selected real artifacts and prepares the
ordinary request. It persists the runtime's actual immutable request, original
ticket, allocating catalog record and real empty host store, then selects
preparing state. It stops before provider start or resume. The signed public
admission export binds that exact scope and ticket. Its signing key derives
from the original confirmed host ticket key under a separate issuer domain.

Original client `accept` requires the issuer public key and export digest from
the controller's successful host result, supplied separately from the export
file. It verifies that signature and persists the actual client retention,
manifest, zero-high snapshot and encrypted recovery envelope. Later
`authenticate` takes only its own original ownership receipt/digest and unlock
descriptor. It reads the original local scope and authenticated storage; it
accepts no replacement ticket, issuer, registration, deadline or clock origin.

This original public-file carrier is confined to the owned qualification
controller. It does not add a transport or establish live wire interoperability.
An exact completed admission or acceptance retry resolves the original selected
records. Partial or ambiguous state refuses without repair or a new namespace,
admission, registration, envelope enrollment or deadline.

## Versioned binding graph

The binding order is provisioning, original bootstrap, paired scope, then
admission and client acceptance. Earlier records never depend on later mutable
state or their own digest.

| Record | New lane |
| --- | --- |
| Provision and paired scope | Version 1, explicit authority profile and both signed originals |
| Role bootstrap core | Version 4, `S100/role-bootstrap/v4` binding |
| Ownership receipt / lifecycle state | Version 2, explicit original-role ownership |
| Ticket / client context | Version 2; context revision `s100-host-client-authority-v1` |
| Lifecycle catalog / immutable request | Version 2, original storage identity and scope |
| Lifecycle storage AAD | Version 2, `S100LC02` framing |
| Empty host manifest / storage AAD | Version 2, `S100HS02` framing |
| Client retention / snapshot | Version 2, original successful acceptance and scope |
| Client manifest / storage AAD | Version 3, `S100CR03` framing |
| Recovery binding / envelope | Explicit `recovery-authority-v1` mode / version 3 |

Old optional fields remain absent in old encodings. New modes have explicit
branches and cannot fall through legacy/independent selection. Ordinary
bootstrap acquisition, scalar clocks, client discovery and wire acquisition
refuse the new lane. Original per-role scope files carry MACs under the confirmed
local storage keys; their public fields alone cannot authorize storage use.

## Eligibility stays local to one action

`RecoveryAuthorityAction` binds the exact scope, local operation and current
process to an opaque S99 action. The current receiver boot/process, nonce,
purpose, original send sample `r0`, receipt sample `r1` and signed witness sample
remain attached throughout original-key confirmation, authenticated storage IO,
blocking work, relocking and final publication.

```text
U(r) = w + 2 * (r - r0) + 1_000_000_000
eligible iff U(r) < originalHostDeadline
         and U(r) < originalClientDeadline
r - r0 <= 10_000_000_000 receiver nanoseconds
```

The factor and allowance are cooperating-rig assumptions. The ten-second age
edge charges twenty-one witness seconds. Original caps cannot exceed 24 hours.
A fresh certificate can lower uncertainty and therefore lower `U`; it cannot
renew either original deadline. `U` does not implement a runtime scalar clock
and is never persisted as an admission anchor or `lastObserved` value.

Observed witness loss or changed identity invalidates the local action. A new
witness cannot adopt old registrations. An unobserved loss retains only S99's
bounded same-action semantics. A new receiver process or boot must obtain a new
nonce and bracket against the original signed records.

Authentication holds the original role lifetime exclusion, confirms original
keys and selection, and uses the real storage codecs. The host requires exactly
one allocating/preparing record and an absent or selected empty child, with no
candidate or replay state. The client requires the original selected snapshot
and envelope, zero high, no calls or batches, no terminal state, and unchanged
owner/receipt revisions. Active, terminal, partial, nonempty, swapped and
effect-bearing records refuse. The operation returns no store, attachment,
recovery object, provider handle or reusable authorization.

## Explicit commands and retirement

All commands are dispatched through the normal `reachd` package. The finite
command family is:

| Command | Inputs and result |
| --- | --- |
| `witness` | Owned controller pipes; original registration, challenge, observation and quit frames |
| `provision` | Original registrations on stdin; `--public-model`, `--request`, `--output` |
| `init` | `--root`, `--role`, `--configuration`, `--owner-receipt`, `--unlock-secret-fd`; returns original receipt digest |
| `admit` | Both original receipts/digests, host unlock descriptor, original `--model`, `--request`, `--export` |
| `accept` | Both original receipts/digests, client unlock descriptor, `--export`, `--original-issuer`, `--successful-export-digest` |
| `authenticate` | Own `--owner-receipt`, `--expected-receipt-digest`, `--unlock-secret-fd`; fresh witness exchange |
| `retire` | Own original receipt/digest; after boot, also `--after-boot` and original unlock descriptor |

The two pair commands name their receipt arguments `--host-receipt`,
`--host-digest`, `--client-receipt` and `--client-digest`. Control frames are
canonical JSON lines, at most 64 KiB. Diagnostic reports contain digests, opaque
IDs, phase and bounded clock metadata; errors expose only bounded refusal types.
The qualification-only authentication options `--block-milliseconds` (0–12000)
and `--observe-witness` exercise the guard after real blocking work.

Retirement has no witness dependency and works after expiry or witness loss.
It uses the original receipt/digest, frozen executable, original key
confirmations, current descriptor-pinned root, lifetime lease and journal
exclusion. Existing [role retirement](durable-role-lifecycle.md) and S98's
same-observed-boot missing-container retry limits continue to apply. Clock
eligibility cannot unlock or delete a Keychain. Successful product retirement
and containment disposal are recorded separately.

## Qualification

`Tools/CrossBootRecoveryAuthority/native_vm.py` runs the ordinary same-boot
native checkpoint, fresh-process recovery, zero-native terminal replay and
uninterrupted reference using the existing native cells. It retains each failed
attempt, exact executable/resource/artifact bindings and original-creator cleanup.

`authority_vm.py` runs one owned VM, one surviving host witness and at most two
role Keychains. Independent pairs run serially for host expiry, client expiry,
and observed witness loss/replacement. Each receives one original admission and
acceptance. The controller cold-stops and joins each guest boot before restart.
Postboot authentication denies fixture/model reads, authenticates fresh receiver
identity and compares all original non-Keychain durable bytes before and after.
Keychain database bytes are excluded from this comparison because opening and
relocking can change the platform's container storage. The original key
confirmations and selected container are checked by the product.

Use reboot-persistent, owned guest paths for this campaign: this cached guest
clears `/private/tmp` on cold boot. Host build and campaign scratch remain owned
and disposable. The runner retains public original encrypted records, process
receipts, refusal evidence, resource samples and cleanup results, with private
keys and unlock inputs excluded. It does not infer native-call authority from
a successful metadata report. Tests and the authentication call path establish
that this entrypoint constructs no provider and invokes no maintenance, second
admission, allocation, replay or effect operation.

Focused tests cover new-record binding and tampering, ordinary refusal,
independent strict deadlines, a lowered fresh bound, partial operations,
original issuer provenance, local action ownership, blocking age, witness loss,
and nonempty-state refusal. The unchanged ClockPolicy tests retain arithmetic,
signature, replay, age and overflow coverage. Native feasibility and actual
postboot authority authentication receive separate verdicts in private evidence.

The separate [S101 ordinary native qualification lane](cross-boot-native-recovery.md) binds original generation records to fresh witness actions across reboot.
