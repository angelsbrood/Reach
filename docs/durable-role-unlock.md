# Explicit durable-role unlock

New finite roles can select a caller-controlled Keychain secret with
`--unlock-secret-fd`. A later process supplies the original receipt, its retained
expected digest and a private descriptor to `durable-independent unlock`. Unlock
verifies the original scoped keys before reporting success.

This selects local role core version 3 and the public policy `caller-supplied-v1`.
The original-key binding uses `S97/role-bootstrap/v3`; the immutable ownership
receipt includes that exact core and policy. Existing v1/v2 fields, domains and
defaults remain intact. Omitting the option keeps the previous random-password
behavior, and an existing root cannot acquire caller unlock authority.

## Supply the descriptor

The caller retains distinct host/client input files outside Reach's role and
control records. Each file must be owned by the current user, mode 0600, regular,
and contain exactly 32–128 ASCII alphanumeric bytes. Use an owned private parent.
No newline, whitespace, trimming or encoding conversion is accepted. Open it
read-only on a descriptor greater than 2. Pipes, sockets, TTYs, standard streams,
closed descriptors and write-capable descriptors refuse.

After provisioning as described in
[independent durable bootstrap](independent-durable-bootstrap.md):

```sh
reachd durable-independent init --finish \
  --owner-receipt /private/owned/host-control/owner.json \
  --role host --root /private/owned/host-root \
  --provisioned /private/owned/staging/host --model /private/owned/model \
  --unlock-secret-fd 3 3< /private/owned/host-input
reachd durable-independent init --finish \
  --owner-receipt /private/owned/client-control/owner.json \
  --role client --root /private/owned/client-root \
  --provisioned /private/owned/staging/client \
  --unlock-secret-fd 3 3< /private/owned/client-input
```

Retain each successful `ready` record's `ownerReceiptDigest`. Join the finite
initializers and remove provisioning before starting workers. The file descriptor
is marked close-on-exec immediately and consumed once, from file offset zero,
with a 129-byte read bound. It is closed before Keychain creation or unlock.

Reach stores no caller input, password verifier or credential file in the role,
receipt, control state or report. Arguments contain only the descriptor number;
secret values are not accepted through argv or environment. Ordinary temporary
process/framework memory copies are not claimed to be fully erased.

## Unlock and recover

Stop and join workers first. Use the same frozen executable, canonical root,
original boot and expected receipt digest throughout the role's lifetime:

```sh
reachd durable-independent unlock \
  --owner-receipt /private/owned/host-control/owner.json \
  --expected-digest "$host_receipt_digest" \
  --unlock-secret-fd 3 3< /private/owned/host-input
reachd durable-independent unlock \
  --owner-receipt /private/owned/client-control/owner.json \
  --expected-digest "$client_receipt_digest" \
  --unlock-secret-fd 3 3< /private/owned/client-input
```

The command authenticates the selected receipt/policy, root identity, frozen
executable, bounded ready/selection records and lifecycle phase before the OS
unlock. It holds the same role lease as workers and retirement, plus the journal
ownership check. It opens only the exact selected existing Keychain, disables UI,
uses the supplied bytes, and loads/confirms every original role key. It rechecks
selection and current Keychain metadata before success. It creates no keys and
does not decrypt generation journals, load a model or publish recovery content.

| Result | Meaning |
| --- | --- |
| `unlocked` | The container began locked; OS unlock and original-key verification passed. |
| `already-unlocked` | Original keys are available. The supplied input was not authenticated as a password. |
| `verification-refused-locked` diagnostic | Post-unlock verification was reached and refused; locked state was established before returning. |
| `relock-unconfirmed` diagnostic | Cleanup could not establish locked state. Preserve the original selection, caller input and executable for correction. |
| Other nonzero exit | Bounded refusal, including bad descriptor, wrong selection/input, unavailable container or busy ownership. |

Wrong input is tested from a confirmed locked state and remains locked. An
already-unlocked container is never deliberately locked merely to test a password.
If verification fails after this command unlocked a container, it attempts to
relock only that authenticated handle while retaining exclusion. No success or
rollback is claimed when the result cannot be established.

After successful unlock, run the original host and client `recover`. Unlock does
not change bootstrap IDs, keys, clocks, context/ticket, local retention or deadline.
The original request must not be repeated. The existing post-encoding client
report eligibility gate continues to apply.

## Retiring and expired roles

Unlock preserves the current `ready` or `retiring` phase. An authenticated
retiring role can unlock a still-present original container so explicit retirement
can finish; workers still refuse it. Missing/deleted containers or incomplete
remaining authority refuse. No record is reconstructed or moved back to ready.

An expired role can be unlocked for the
[content-free retirement operation](durable-role-lifecycle.md#retire-or-retry).
Its generation remains subject to original expiry. Keep caller input and the
frozen executable until the original role has retired. There is no automatic
unlock, prompt, retry loop, credential recovery, rotation or migration.

[The qualification runner](../Tools/DurableRoleUnlock/README.md) covers private
descriptor intake, fresh locked-state unlock/recovery, verification/relock,
retiring and expired cleanup. Scope remains cooperating same-Mac/same-boot
loopback with the existing tiny model and wire profile; no unattended credential
store, cross-boot unlocking, malicious-same-UID isolation or deployment is claimed.
