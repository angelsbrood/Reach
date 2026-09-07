# S85 durable-store bootstrap and protected root keys

This opt-in local macOS candidate adds an immutable bootstrap descriptor and real
scoped file-Keychain storage for three independent root keys. Default-off performs
no provider, bootstrap or journal access. Creation persists an intent before adding
keys, initializes the actual empty host/client stores, then selects ready state.
Interrupted creation stays incomplete; recovery never repairs or generates keys.

The nonsecret descriptor binds original host/client IDs, boot, clock policies,
quotas, source/projection revision, fixed journal roles and exact key references.
Each protected record binds that descriptor and role. Creation-time HMAC key
confirmations also detect correctly labelled key replacement, including the ticket
key that catalog AEAD cannot confirm. Keys are generated, read and used only inside
workers and the OS Keychain. They have no supervisor-message representation.

Reopen validates ready state and required key material before calling the existing
mutating store constructors. Host acquisition loads two keys; client acquisition
loads only its metadata key. The short bootstrap lock is released before journal
ownership begins. Missing host authority does not erase or block client knowledge.
Original tickets, client context and current synthetic authorization remain private
inputs from the surviving trusted supervisor; full supervisor-loss recovery is
outside this cut. No ticket/context/result is stored in the descriptor.

The macOS provider targets an explicit owned file-Keychain for every operation.
It disables process interaction, uses add-only item creation and load-only queries,
and validates exact returned service/account/record bindings. Initial item access
names only frozen owned worker binaries; access is never expanded after refusal.
File-Keychain lock blocks new acquisition, not keys already cached by a live owner.
The disposable container password is separate from root keys and stays in the
test controller's private pipes/memory. No user password is requested.

Run with Python 3.12 or later: `python3 run.py --repo /path/to/Reach`. Offline
packaging authenticates the accepted 123 products, fourteen bindings, six pins,
Metal and unchanged 35 native outputs. The CPU-only Keychain/client workers do not
link MLX. Focused XCTest supplements a real scoped OS cell, representative creation
deaths, one ordinary native continuation pair, independent key acquisition and
client knowledge checks. Earlier all-route/effect/retirement campaigns are reused.
Filtered runs describe only their executed subset and need explicit evidence reuse.
`--acquisition-only` exercises the fixed-container guard and both real independent
empty-store reopens without a native generation; it does not replace the full join.
Even a consistently altered descriptor cannot select another container for lookup.

Only new disposable generic-password items and explicit owned Keychain containers
are used. Existing credential items are never searched. Default/search-list paths
are compared only as nonsecret metadata, and no setters replace those lists.
Cleanup deletes only the created containers and owned fixture roles, then verifies
their files/registrations absent and unrelated metadata preserved. Private copies,
binaries, journals and Keychains are removed; ordinary bounded evidence remains.

This uses deprecated file-Keychain APIs for a same-host/same-boot CLI proof. It
does not adopt data-protection/login/System/iCloud Keychain behavior, production
auth/storage/consent, wire/runtime/pins, real effects, Linux/EXO/network, devices/VMs,
reboot/power-loss/hostile rollback, rotation, release or later phases. Keeper Held.
