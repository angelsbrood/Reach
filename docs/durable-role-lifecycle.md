# Durable role lifecycle

`reachd durable-independent init --finish --owner-receipt <path>` initializes one
role, publishes its ownership receipt, and exits. Fresh workers use the original
root. A later `retire` process removes that selected root and Keychain after all
workers release ownership.

This opt-in lifecycle uses local role core version 2. Initialization without the
two new options retains the foreground creator and version 1 behavior described
in [independent durable bootstrap](independent-durable-bootstrap.md). Existing
roots are not migrated. Generation, wire, retention and report publication
semantics are unchanged.

## Initialize and retain the selection

Use the same frozen executable at the same canonical path for initialization,
workers and retirement, on the same Mac and boot. Keep it available until every
selected role is absent. Its file and parent must be mode 0700. Use fresh roots
and separate own-role control directories under owned mode-0700 parents; private
records are mode 0600. A receipt must be outside the root that will be removed.

After provisioning as described in the bootstrap guide:

```sh
reachd durable-independent init --finish \
  --owner-receipt /private/owned/host-control/owner.json \
  --role host --root /private/owned/host-root \
  --provisioned /private/owned/staging/host --model /private/owned/model
reachd durable-independent init --finish \
  --owner-receipt /private/owned/client-control/owner.json \
  --role client --root /private/owned/client-root \
  --provisioned /private/owned/staging/client
```

Retain each successful `ready` record's `ownerReceiptDigest` separately as the
expected selection for that role. Wait for both initializers to exit successfully
before starting workers, then remove the provisioning directory. The client
receives no model, host storage key or peer ownership record.

The receipt contains public ownership metadata and original key confirmations;
it contains no storage key or unlock password. Its digest is domain-separated
SHA-256 of its canonical encoding, not the raw file checksum. Do not reconstruct
the expected digest from a later deletion target or replace it after a refusal.

The immutable receipt includes the exact ready core: role/bootstrap IDs, actual
root directory device/inode, canonical root and derived Keychain path, key
selectors, own boot/origin/epoch, frozen executable, agreement/selection and quota.
The root identity deliberately does not depend on the Keychain file inode, which
can change while macOS writes the first items.

## Acquire, stop and recover

The existing `host`, `begin`, `recover` and `cancel` commands accept a version 2
root without additional options. Acquisition takes the own-role lifecycle lease
before keys and journals, checks the original ready transaction and receipt, and
holds the lease for the resources' lifetime. Another worker or retirement process
receives a bounded refusal while ownership is held. A role can operate without
filesystem access to its peer's root or control directory.

Use `begin` only for the original request. Stop and join both workers before
replacing them, then use a fresh host process and client `recover`. Initializer
exit and worker replacement do not create keys, renew retention, recenter the
clock, issue another ticket or prepare a replacement request. The existing final
client report eligibility check still applies after encoding.

## Retire or retry

After workers exit and are joined, pass the retained expected digest for each
role explicitly:

```sh
reachd durable-independent retire \
  --owner-receipt /private/owned/client-control/owner.json \
  --expected-digest "$client_receipt_digest" --progress
reachd durable-independent retire \
  --owner-receipt /private/owned/host-control/owner.json \
  --expected-digest "$host_receipt_digest" --progress
```

The command authenticates the selected receipt, current root identity, executable,
ready/selection records and original keys. It takes lifecycle and journal
ownership, durably marks the role `retiring`, deletes only its authenticated
Keychain, checks unrelated default/search-list metadata against the immediately
preceding snapshot, and removes the bounded owned root. It reports `retired` only
after removal. An already absent original target reports `absent`; a replacement
or symlink at that path refuses.

Retirement does not load a model, read/decrypt the journal, recover generation,
publish expired content or fabricate an ending. It works after local retention
expires. A locked or missing original key before the authorized transition
refuses; no unlock command or shared/default Keychain fallback is provided.

The external control directory retains these bounded records:

| Record | Purpose |
| --- | --- |
| `owner.json` | Immutable original receipt selected by the retained digest |
| `owner.json.lock` | Exclusive role lifecycle ownership |
| `owner.json.state.json` | Durable `creating`, `ready`, `retiring` or `retired` progress |
| `owner.json.next` | Temporary atomic progress update, absent at successful publication |

Keep the original receipt, expected digest, control records and frozen executable
after a failure. If interruption occurs after Keychain deletion, repeat the same
`retire` command in a fresh process. The durable `retiring` state excludes new
workers and permits removal of the remaining original root without recreating
keys. An incomplete initialization or mismatched record remains unselectable;
do not edit it into a ready root. Ordinary initialization errors clean only the
resources that invocation created.

## Qualification boundary

[The lifecycle runner](../Tools/DurableRoleLifecycle/README.md) qualifies finite
initialization, fresh ordinary native recovery, terminal replay, selected
ownership refusals, expired content-free cleanup and interrupted retirement.
The deletion scan accepts only the selected role's known root entries, owned
mode-0700 directories and mode-0600 regular files, with no symlinks/hardlinks;
it is bounded by 65,536 entries, depth 12 and 4 GiB of allocated file data.

This route remains literal `127.0.0.1` pinned mTLS QUIC with the existing profile
and tiny local model policy. It establishes same-boot local operation, not
cross-boot or unattended unlocking, anti-rollback, securityd isolation from a
malicious process with the same UID, deployment or default SDK adoption.
