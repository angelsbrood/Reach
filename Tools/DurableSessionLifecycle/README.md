# S82 local durable session lifecycle candidate

This isolated Swift package adds authenticated session tickets, bounded admission,
original deadlines and durable retirement over the unchanged S81 host store.
An exact repeated begin returns the existing operation. A retired operation cannot
be recreated under the same session namespace and generation identity.

It is a synchronous local candidate for cooperating owners on the same host and OS
boot. There is no daemon/app adoption, production authorization, Keychain access,
tool execution, durable client receipt, reboot/power-loss guarantee or release.
The accepted S72–S81 native composition and all eighteen copied coordinator,
provider and store sources remain unchanged.

## API and ownership

Create a fresh 0700 root with `DurableSessionLifecycle.initialize`, or authenticate
an existing one with `reopen`, using the same `LifecycleIdentity`, two independent
32-byte `LifecycleKeys` and clock policy. The keys are separate catalog AES-GCM
and ticket HMAC-SHA256 authorities. A missing/wrong key or boot/policy mismatch
refuses; initialization never overwrites an existing root.

All public operations are serial and synchronous. Keep one owner alive and close
it explicitly. It retains a close-on-exec root lock and takes child locks only
after that lock. Child handles remain internal. A contender cannot infer ownership
from elapsed time; a released lock after joined death/close supplies the local
takeover boundary. An unsafe or unsettled child keeps admission blocked.

Supply a current trusted synthetic `LifecycleAuthorization` on every caller API:

1. `issueTicket` creates an opaque, canonical, MAC-authenticated ticket with a new
   namespace, caller/context binding and absolute lifetime of at most 24 hours.
2. `begin` binds the namespace, generation ID and immutable S80 request. An exact
   repeat reports existing state without changing capacity, contact or deadlines.
   A changed binding or aliased operation ID refuses. Queued acceptance is distinct
   from accepted provider C0.
3. `attach` validates a surviving client cursor and increments the attachment
   epoch. Recovery loses the prior live attachment; repeated begin reports no
   attachment until explicitly attached again. `touch` records authenticated
   contact. Old owner/attachment epochs cannot touch, detach, cancel or acknowledge
   delivery for a successor attachment.
4. `step` lazily acquires the provider runtime after authority, admission, replay
   and full next-set credit checks. `replay` returns exact S81 batches, including
   skipPrefix semantics. `acknowledgeDelivery` records the surviving client's
   assertion in memory; it is not durable EvAck or proof of app/tool effects.
5. `detach` records its first residency deadline. `cancel` creates an outer
   lifecycle disposition and retires content while preserving a known committed
   provider ending. It does not synthesize a cancellation WireEvent.

`maintenance` is an explicit trusted root-key administrative operation. Caller
APIs validate authorization and ticket before invoking it. It resolves catalog
uncertainty, authenticates child metadata, enforces expiry, resumes exact cleanup
and promotes eligible waiters without constructing provider runtimes. Invalid
content becomes non-resumable; unsafe ownership refuses cleanup. There is no
initialize-over or ordinary generation fallback.

## Separate durable authorities

The encrypted catalog and S81 child manifest are independent authorities:

```text
queued -> allocating -> preparing -> active/recovering -> terminal
                     independent S81 child authority       |
             cancellation or expiry -> retiring -> tombstone
```

The catalog persists `allocating` before any child directory exists. Only that
phase may retry a structurally verified incomplete pre-provider allocation. It
authenticates an empty S81 manifest and persists `preparing` before provider C0.
Recovery reconciles a valid empty child or newer C0/terminal into the catalog.
Nonempty provider state under allocating contradicts its invariant and refuses.
Missing/corrupt preparing or active authority is never recreated.

Before a potentially terminal child call, the catalog persists its transition
start time. The actual child snapshot determines the result after the call or
recovery. A committed terminal retains that original start bound; retries and lost
promotion replies cannot move its retention deadline. Catalog replacement marks
the rename attempt uncertain before rename, then requires authenticated current
selection and directory sync before further work/publication.

Retirement first closes live children and acquires their released locks. It then
persists a no-reexecution cleanup intent with no per-generation keys, removes the
exact owned content under the held lock, and replaces the intent with a minimal
encrypted tombstone. Interrupted deletion resumes from the intent. Corrupt regular
ciphertext may be deleted using authenticated catalog locators and strict raw-role
ownership checks. Unknown roles, links or unsafe modes are preserved and refuse.
An unreadable provider ending stays unknown; no tool effect is inferred/retracted.

## Time, privacy and ceilings

The production-shaped clock uses the actual same-boot nanoseconds returned by
`clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)`. Tests inject a distinct, schema-bound
fixture policy. Clock rollback and checked arithmetic overflow refuse.

| Bound | Behavior |
| --- | --- |
| 1 active, 3 queued; 1 waiter per namespace | Allocating/preparing/recovering consume the active slot |
| 64 total records | Includes retained terminals, retiring records and tombstones |
| Queue/preparation 120 seconds | Starts at admission; repeats/restarts do not refresh it |
| Detached residency 120 seconds | Explicit detach uses its original time; missing detach uses persisted last authenticated contact |
| In-flight 15 minutes | Starts at initial admission and caps lifecycle retention |
| Terminal retention 600 seconds | Starts from the persisted transition bound, capped by absolute and ticket deadlines |
| Ticket 24 hours | Expired namespace refuses even after all tombstones are removed |
| Request/catalog 1 MiB; ticket 4 KiB; IDs 256 UTF-8 bytes | Actual encoded sizes and schema are bounded |
| Child 512 MiB; whole lifecycle 2 GiB allocated | Includes directories, all terminal children, current/prepared data and orphans |
| 64 child directories, 65 request blobs, 3 catalog/lock roles | At most 1,092 regular store files |

Every live return checks the current clock, original deadlines and authorization
after its final blocking persistence. This final check does not add another fsync.
Attachment/contact mutations also check the original record before changing it,
so an expired detached deadline cannot be cleared by reattachment. Every step
checks deadlines before work and after child settlement; replay checks again
before returning bytes. A step crossing expiry retires its settled result
without publishing it as live continuation. Current authorization is rechecked
after native calls. Only explicit attach/touch/detach updates retained contact;
callers should touch valid live attachments as appropriate. Maintenance erases at
the next owned opportunity, not at a guaranteed instant while the owner is offline.
If a ticket expires after retirement started, the next cleanup retry persists
identity removal before attempting child-lock acquisition or content deletion.
Failed cleanup retains only opaque locators and no-reexecution bookkeeping; a
failed catalog write aborts the retry without claiming identity was removed.

Fresh independent per-generation metadata/content keys protect S81 children; the
content key also encrypts the immutable queued request under separate request AAD.
The encrypted catalog alone retains these keys while content is live. Catalog,
request and ticket context binds format, incarnation, boot and clock policy.
All persistent principal/request/tombstone content is encrypted, with 0700
directories and no-follow 0600 regular files. This is injected test-root-key
protection, not OS key provisioning, guaranteed memory zeroization or SSD erasure.

Before admission and child work, reserve full S81 worst-next-set credit plus
metadata/retirement and request headroom. No credit refuses before provider work
without evicting unexpired replay. A lower configured test quota retains all upper
bounds and exercises real allocated terminal/orphan bytes.

## Focused verification

From the canonical Reach checkout, use Python 3.12 or newer and normal macOS
boot-identity/Metal permission:

```sh
python3 Tools/DurableSessionLifecycle/run.py --reach "$PWD"
```

The runner authenticates all 79 prerequisite files, twelve selected bindings,
four package pins/six source roots and Metal. It exports only existing local
sources, applies the unchanged eight native patches and checks the same 35 output
hashes. Builds use four jobs and private package/module caches, without fetching.

The focused XCTest suite covers tickets, authorization, admission, all record
slots, stale epochs, original deadlines, catalog uncertainty, schema/ownership
refusals, incomplete/corrupt authority, retirement key removal, actual aggregate
quota, terminal promotion, expiry during committed output and required/allowed
terminal replay with exact call IDs and native usage. A separate three-process
gate checks the actual product clock.

The surviving supervisor keeps root keys, tickets, client receipts, reference
events and native traces only in memory. Keys/tickets use anonymous pipes, never
arguments, environment, logs or plaintext files. One non-model lock contender
checks live-owner exclusion and joined-death takeover. Ten real SIGKILL cases cover
allocation intent/directory, empty child, C0, terminal promotion and retirement
before intent, after intent, during deletion, before tombstone and after tombstone.
An injected empty-child setup stop is identified separately from those real deaths.
The ordinary case actually continues native work after owner death; terminal replay
and expiry use zero provider factories/calls. Exact future suffix comparison occurs
only after actual continuation. S81 four-route active/death, child-codec, RC1 and
Llama evidence is reused rather than rerun as a Cartesian campaign.

Owned scratch is confined to `reach-durable-session-lifecycle.*` and the explicitly
named `reach-s82.*` companion: combined 16 GiB, fixtures 3 GiB, tiny MLX peak
128 MiB, individual evidence files 192 MiB, free disk at least 20 GiB. Build/test
and native workers run sequentially, except the non-model contender. Commands are
joined before exact private sources/builds/stores are disposed. Retained evidence
contains ordinary logs, selected/started/passed methods, transition/clock results,
input/composition hashes and command-boundary resource observations. Raw arrays
are not retained; no continuous RSS or exhaustive opaque descendant claim is made.

Runner PASS is execution evidence. Terminal Architecture PASS and Planning
closeout remain the acceptance gates for this local candidate.
