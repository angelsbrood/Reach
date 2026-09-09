# Explicit original-role retirement after reboot

An original v3 `caller-supplied-v1` role can be explicitly retired after this Mac
has rebooted. Its generation remains nonresumable: the original monotonic clock,
retention, ticket and publication checks continue to refuse the prior boot.
Cleanup does not rebase a clock, renew a deadline or unlock a reusable runtime
owner.

Retain the original external receipt, its expected digest from successful finite
initialization, the caller input and the same frozen executable. Run:

```sh
reachd durable-independent retire-after-boot \
  --owner-receipt /private/owned/host-control/owner.json \
  --expected-digest "$host_receipt_digest" \
  --unlock-secret-fd 3 3< /private/owned/host-input
```

The command requires an actually different current boot and an original v3 role.
Same-boot callers use the existing [unlock](durable-role-unlock.md) and
[retirement](durable-role-lifecycle.md) commands. V1/v2 roles are not admitted.
The [private descriptor contract](durable-role-unlock.md#supply-the-descriptor)
is unchanged: current-owner mode-0600 read-only regular FD greater than 2,
32–128 ASCII alphanumeric bytes without trimming. Credential values and verifiers
are not persisted or accepted through argv/environment. The descriptor is marked
close-on-exec and closed before Keychain use. Ordinary process/framework memory
copies are not claimed to be completely erased.

The original core, receipt, key references, HMAC domains, device number and
expected digest remain exact. The original device is historical provenance:
macOS may assign another number after reboot. Cleanup requires the original
canonical root path/inode, current private owner/mode and frozen executable. It
pins the current directory device/inode with a no-follow descriptor and checks
the named directory and descendants against it throughout removal. This does not
establish historical volume identity or arbitrary cloned-volume provenance.

Under the original external lifetime lease and journal exclusion, the command
opens only the selected original Keychain, disables Security UI, unlocks if
necessary and confirms every original scoped key. Public bootstrap/selection
metadata is checked before authorization. Generation manifests, snapshots, model
contents, tickets and recovery content are not loaded. An already-unlocked
container proves original-key availability, not password authentication.

After key confirmation it durably writes a bounded cleanup observation beside
the receipt, then preserves or durably enters `retiring`. Both records precede
exact Keychain deletion. Bounded content-free removal refuses symlinks,
inappropriate hard links, changed selected identities and descendant filesystem
crossings. The current-default and unrelated Keychain metadata protections remain.
Successful removal publishes the existing v1 `retired` state.

If an invocation unlocked a locked container and fails while it remains, it
attempts to relock that same handle under exclusion. `refused-locked` means locked
state was established on refusal; `relock-unconfirmed` means it was not established.
No rollback is claimed and any durable retiring state is retained. A healthy
already-unlocked container is never locked solely to test its password.

## Interrupted cleanup

If the original container still exists, supply the input again. Original-key
reauthentication can establish a new current-boot observation even after another
reboot. The original public authority is not reconstructed or migrated.

If the container is already deleted but the root remains, a fresh retry needs
the existing `retiring` state and cleanup observation matching the original
core/receipt/container-selection digests, this current boot, and the exact pinned
root path/device/inode. Only this qualified retry may omit the descriptor:

```sh
reachd durable-independent retire-after-boot \
  --owner-receipt /private/owned/host-control/owner.json \
  --expected-digest "$host_receipt_digest"
```

Any supplied descriptor is still validated. Missing/malformed observation,
another reboot after deletion, tuple mismatch, or missing container in `ready`
refuses remaining-root removal. An observation alone grants no authority.
Already absent roots produce authenticated observed absence, without claiming a
deletion or reconstructing a lost transition.

Keep each caller input and frozen executable until its original role has retired.
There is no automatic cleanup, unattended credential storage, credential recovery,
rotation, executable migration or cross-boot generation continuation. The
[qualification runner](../Tools/CrossBootRoleLifecycle/README.md) records actual
reboot, refusal, removal and retry evidence separately from injected tests.
