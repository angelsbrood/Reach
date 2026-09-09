# Cross-boot role lifecycle qualification

This serial macOS runner qualifies the explicit `retire-after-boot` command in
[the operator guide](../../docs/cross-boot-role-lifecycle.md). It uses one owned
clone of the already cached, authenticated Threshold gold. The gold, Tart binary,
guest preflight and shared infrastructure are read-only inputs. The runner does
not reboot the working Mac, access its Keychain, download dependencies, install
trust material or control another VM.

Build normal `reachd` with owned caches, cached sources, four jobs, an outer
deny-network profile and disabled experimental SwiftPM prebuilts. Generate the
existing tiny artifact using `LocalRuntimeTests.testGenerateAndLoadActualArtifacts`
with `S93_TEST_ROOT=<owned scratch>/fixtures`.

```sh
python3 Tools/CrossBootRoleLifecycle/run.py \
  --scratch "$scratch" --label reboot-1 \
  --executable "$normal_executable" --metallib "$normal_metallib" \
  --fixtures "$scratch/fixtures"
```

Use a private current-owner `/private/tmp/reach-s98.*` scratch directory and a
fresh label for each attempt. The runner authenticates the exact cached Tart and
gold bindings and checks VM availability before cloning and each boot. It uses
the verified headless baseline attachment, enforces the inherited guest network
gate before fixture work on every boot, and denies external network access to
the guest phase; its child fixture processes inherit that one sandbox. This
avoids nesting a different sandbox profile on macOS. VSOCK supplies host-owned
control and file transfer. Those
observations do not establish an exhaustive boot packet history.

Before original initialization, the runner selects the public fixture descriptor's
backend from Foundation's actual guest OS version string. All other descriptor and
artifact fields stay exact. This is fixture authoring before role creation; it
does not rewrite original role authority or bypass a boot check.

The same frozen normal executable initializes original v3 host/client roots and
performs all postboot operations. Their role/control/executable parents belong to
the caller and are mode 0700. The guest retains distinct private input files and
the successful initialization digests. Original boot/path/inode/device, immutable
public records and executable bindings are captured without credential hashes.
Finite initializers and the first boot supervisor are joined before a cold boot.

Postboot qualification requires a different real boot UUID, unchanged original
path/inode and frozen executable, and unchanged original public core/receipt/key
selection bytes. Current device numbers are recorded separately. It verifies:

- Ordinary acquisition, standalone unlock and ordinary retirement refuse the
  prior boot, with no report publication.
- New-command receipt, policy, selection, executable, root, descriptor, wrong
  input and active lifetime/journal ownership refuse. An actual original-key
  confirmation failure after OS unlock establishes locked state.
- Both original roles retire despite deliberately undecodable generation
  payloads whose read-data access is denied.
- A real retirement process is stopped after exact Keychain deletion, then
  killed and joined while its root remains. A fresh process completes removal
  using the current-boot cleanup observation without a credential. Missing,
  malformed, different-boot or wrong-tuple observations refuse first.
- Original receipts remain exact, both states are retired, repeated absence is
  reported as observation, and unrelated default/search-list metadata is unchanged.

The fixed public-confirmation mutation is restored after its owned negative
case. The post-delete timing cut must actually be observed; a raced cut is a
retained failure. Injected relock failures and device/boot policy cases belong to
the focused Swift tests and are distinct from real OS/process observations.
This content-free qualification does not run a new native generation matrix;
unchanged earlier native routes need an actual dependency comparison for reuse.

Commands, PIDs, numeric joins, logs, public controls, sampled resources and boot
receipts are retained. Guest checks compare its caller inputs with recorded
guest and host evidence before removing them, retaining only counts/booleans.
On success, guest material and the exact stopped clone are removed. On failure,
known guest children are joined where reachable, the owned boot is stopped/joined,
and the failed clone/frozen material remains for bounded correction. Do not
present later containment disposal as product retirement or reconstruct a lost
launcher wait.

Limits are one VM, four vCPU/eight GiB, two role Keychains, four build jobs,
32 GiB owned scratch, 3 GiB fixture material, 192 MiB per log and 1 GiB retained
evidence. Host free space must stay at least 30 GiB and observed additional
volume consumption no more than 20 GiB. The cached disk's 150 GB logical size is
not exclusive physical allocation. Role/control records retain the 64 KiB bound;
resource measurements are samples.
