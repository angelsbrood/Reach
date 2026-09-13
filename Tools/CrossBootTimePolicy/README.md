# Cross-boot clock policy qualification

This standalone package evaluates two original witness-domain deadlines after a
disposable receiver reboots. It uses Foundation, CryptoKit and Darwin, with no
package dependencies or native Reach runtime imports. It does not reopen a
Reach generation or change any existing clock policy or encoded format.

The candidate is conditional on the cooperating rig assumption
`Delta W <= 2 * Delta R + 1_000_000_000 ns`. The factor and allowance are neither
Apple guarantees nor measured worst-case bounds. See the
[policy and adoption gates](../../docs/cross-boot-time-policy.md).

## Build and focused tests

Use the installed Apple Swift toolchain. From this package directory, create
private scratch and keep every build/cache directory there:

```sh
s99_scratch=$(mktemp -d /private/tmp/reach-s99.XXXXXXXX)
chmod 700 "$s99_scratch"
CLANG_MODULE_CACHE_PATH="$s99_scratch/clang" \
SWIFTPM_MODULECACHE_OVERRIDE="$s99_scratch/clang" \
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  /usr/bin/swift test --package-path "$PWD" --disable-sandbox \
  --scratch-path "$s99_scratch/build" --cache-path "$s99_scratch/cache" \
  --config-path "$s99_scratch/config" --security-path "$s99_scratch/security" \
  --jobs 4
```

There are 25 XCTest cases covering the bound and its limits, original-record
deduplication and capacity, independent expiry and exact equality, checked
arithmetic, canonical bounded decoding, replay, binding changes, clock faults,
and observed versus unobserved loss. Injected clocks appear only in this test
target. The violating-rate fixture deliberately demonstrates that a clock outside
the assumption can make the candidate unsafe; its passing assertion is not a
platform timekeeping guarantee.

The outer sandbox denies networking. `--disable-sandbox` disables SwiftPM's
nested manifest sandbox, avoiding nested profile application; it does not remove
the outer network denial. If the invoking environment itself prevents applying a
sandbox, run with authority to apply this one profile and retain the failed
preflight. Do not silently run the tests with networking enabled.

Find the executable with the same SwiftPM paths using `swift build
--show-bin-path`; SwiftPM build layouts vary. The executable links only standard
system frameworks and Swift runtime libraries, so the same binary can be copied
to the cached macOS guest.

## Fixed system-clock commands

`clock-qualification freshness` runs two actual process waits of 4.25 seconds.
It emits signed public responses, exact original registrations, observed samples,
and refusal evaluations. One signed response is held until original host expiry;
the other is accepted before blocking work and then refuses at original client
expiry with unchanged `r0` and `r1`. Both include a signature-only control that
would still allow using the historical witness sample.

`clock-qualification witness` starts one ephemeral issuer on stdin/stdout. Its
private Curve25519 signing key exists only in process memory. Frames are bounded
canonical JSON; the issuer accepts fixed campaign fixture registration, a
challenge, a sample request or quit. The fixed original cap pairs, in seconds,
are `(host: 180, client: 600)`, `(host: 600, client: 240)` and `(600, 600)`.
Identical registration requests return the original exact signed bytes.

`clock-qualification receiver seed|postboot|replacement OWNED_ROOT` is a controlled
fixture endpoint, driven by the serial runner. The initial pin arrives on the
controller-owned preboot pipe and is retained with the exact original signed
registrations. Postboot commands load that original pin and reject replacement.
There is no issuer-pin, time, upper-bound, expiry-deadline or injected-clock CLI
option. A controller that replaces the provisioning pipe or original fixture
file is outside this qualification trust boundary; this is not a production
bootstrap or filesystem-ownership protocol.

## Actual cold-reboot campaign

The runner uses the existing cached Tart/gold/VSOCK recipe in
[`../CrossBootRoleLifecycle/vm.py`](../CrossBootRoleLifecycle/vm.py) read-only.
`rig.py` adds this slice's tighter limits and interactive pipe transport. It
reauthenticates the pinned Tart executable, gold config/NVRAM and current shared
baseline manifest before clone/boot, and refuses a competing VM. It creates one
unique owned clone, with four vCPU and eight GiB RAM, two owned empty read-only
shares, headless attachment and the existing guest network gate enforced before
fixture execution on each boot. Witness and receiver commands also run with
`network*` denied. No host reboot, sleep/clock mutation, Keychain operation,
external service, dependency installation or model fixture is involved.

Supply the built executable and an existing private persistent evidence directory:

```sh
python3 run.py --scratch "$s99_scratch" --label 01 \
  --executable /absolute/path/from/show-bin-path/clock-qualification \
  --retain /absolute/private/persistent/evidence
```

The seed receiver creates six original signed registrations and earns positive
bounds. The controller stops and joins that guest boot, retains the original
host witness process, and cold boots the same clone without saved-state resume.
A different guest boot UUID and receiver process must earn new certificates for
the unchanged registrations. The campaign then waits for independently expired
host/client fixtures, tests bounded use after the original witness actually
exits, tests explicit observed-loss invalidation and age exhaustion, and refuses
a new witness process/key/epoch. A replacement starts only after the first witness
has exited and been joined. The entire campaign normally takes several minutes.

Every frame is capped at 64 KiB. The issuer holds at most 16 original records and
128 consumed nonces; each serial verifier permits one outstanding action and
64 actions over its incarnation. Exhaustion refuses. The runner enforces sampled
limits of 8 GiB owned scratch, 20 GiB volume free-space drop, at least 30 GiB free,
64 MiB per log and 256 MiB retained evidence. Volume deltas include other APFS
activity and are not exclusive clone allocation measurements.

## Results, retries and cleanup

`campaign-LABEL/RESULT.json` reports only the gates actually earned. Protocol and
ordinary command logs, actual receiver boot/process samples, signed originals,
known child exit/wait receipts, finite interval observations and clone disposal
are retained under the supplied persistent directory before the temporary
executable is removed. Guest fixture material is removed before final poweroff
and clone disposal on success. A failed campaign attempts owned witness/VM
cleanup and retains its failure and any missing receipt explicitly.

A harness-only retry can use `--reuse-freshness /persistent/campaign-LABEL` when
the executable hash is unchanged. It authenticates the earlier successful
freshness process receipt and raw output. A failed campaign remains failed even
when one of its independently successful gates is reused. Run a new campaign
label for every attempt; never overwrite earlier evidence.

The runner records actual joins for the processes it starts and a known guest
wrapper's child. It does not infer opaque-tool descendant history or reconstruct
missing exits. Check the result and cleanup receipts before removing owned
scratch. Do not delete shared tooling, baseline manifests, gold VMs or other
tasks' VMs. Preserve persistent evidence for Planning authentication and the
terminal Architecture PASS/BLOCK review.
