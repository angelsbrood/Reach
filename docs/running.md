# Running the daemon

## Building the private unsigned Mac package

`Tools/ReleasePackage` builds and independently verifies the deterministic
arm64 package substrate selected in S33. Its output is **private, unsigned,
unnotarized, and not an installable or trusted Reach release**. Do not pass the
result to Installer, distribute it, or treat its ad-hoc executable signatures
as a public trust chain.

The tool has three operations. `snapshot-dependencies` seals sources that are
already cached locally; it never downloads them. `build` exports the exact
clean source commit, rebuilds reachd and meshd twice with isolated caches,
assembles the two scriptless components, and emits external provenance.
`verify` expands an existing candidate into a fresh directory and independently
joins its Distribution, PackageInfo, BOM, cpio, payload, signature class,
architecture, linked libraries, notices, manifest, and provenance.
The reachd build retains Apple's default/fast Objective-C stubs. A fail-closed
post-link normalizer resolves only the nondeterministic choice between two
adjacent authenticated GOT bindings for the same `_objc_msgSend` symbol, then
derives a content-bound UUID before ad-hoc signing. It requires the exact
ordinary and 32-byte fast-stub shapes and refuses small or unknown stubs, so
reproducibility does not select the linker's size-first dispatch mode.

Swift escaping-closure diagnostics also encode the UTF-8 byte length of their
compiler-visible source filename. Prefix mapping rewrites the filename but not
that immediate operand. The builder therefore pads each private build root to
exactly 240 UTF-8 bytes before invoking Swift; an overlong caller root fails
before compilation. This is compile-path authority, not another post-link
normalization class.

Every release-tool path must use its physical, canonical spelling. Empty,
`.` and `..` components, repeated or trailing separators, and any existing
symlink ancestor are refused before the work or output root is created. The
deepest existing prefix is resolved with `realpath(3)` and must byte-match the
caller's spelling, so case-folded aliases are also refused on case-insensitive
volumes. That comparison uses `utf8.elementsEqual`, not Swift's
Unicode-canonical `String` equality, so composed/decomposed aliases are refused
too. On macOS use `/private/tmp/...`, with its exact on-disk bytes and case, not
the `/tmp` symlink or `/PRIVATE/TMP/...`. The core rechecks mutable roots
independently of CLI parsing so a programmatic caller cannot calculate the
240-byte authority from one spelling while SwiftPM compiles through another.

One `build` invocation still performs the local A/B comparison. A release U1
authority additionally requires three separate `build` processes whose
caller `--work` paths have deliberately different UTF-8 lengths. Compare all
three schema-v2 `release-build-comparison.json` files: all six
`reachdSHA256` values and all three `normalizedSemanticSHA256` values must be
identical, while every record must name the fixed-length authority and report
`compilerVisibleRootUTF8Length` as 240. Differing outer package hashes remain
acceptable only when independent expansion attributes them solely to XAR
creation time.

Build the tool in an explicit scratch product:

```sh
/usr/bin/swift build \
  --package-path /absolute/path/to/Reach/Tools/ReleasePackage \
  --configuration release \
  --scratch-path /private/tmp/reach-release-tool-build
REACH_RELEASE_BIN=$(/usr/bin/swift build \
  --package-path /absolute/path/to/Reach/Tools/ReleasePackage \
  --configuration release \
  --scratch-path /private/tmp/reach-release-tool-build \
  --show-bin-path)
```

Do not name the live `Tools/ReleasePackage` checkout as
`--release-tool-source`. Ignored local products such as `.build/` are not
visible in the repository cleanliness check but do enter the source-authority
digest. Export the exact synchronized commit into a new private root, and use
that same commit-only copy for both `build` and `verify`:

```sh
REACH_REPOSITORY=/absolute/path/to/clean/Reach
REACH_RELEASE_TOOL_EXPORT_ROOT=$(/usr/bin/mktemp -d \
  /private/tmp/reach-release-tool-source.XXXXXX)
/bin/chmod 0700 "$REACH_RELEASE_TOOL_EXPORT_ROOT"
/usr/bin/git -C "$REACH_REPOSITORY" archive \
  --format=tar \
  --output="$REACH_RELEASE_TOOL_EXPORT_ROOT/Tools.ReleasePackage.tar" \
  HEAD Tools/ReleasePackage
/usr/bin/tar -xf "$REACH_RELEASE_TOOL_EXPORT_ROOT/Tools.ReleasePackage.tar" \
  -C "$REACH_RELEASE_TOOL_EXPORT_ROOT"
REACH_RELEASE_TOOL_SOURCE="$REACH_RELEASE_TOOL_EXPORT_ROOT/Tools/ReleasePackage"
```

The export is authority for that exact commit only. Create a new export after
`HEAD` changes; never carry one forward by editing it in place.

Create the depot from explicit already-cached inputs. The paths below are
placeholders; the operation refuses missing, changed, or unclassified source
and license inputs:

```sh
"$REACH_RELEASE_BIN/reach-release-package" \
  snapshot-dependencies \
  --repository /absolute/path/to/clean/Reach \
  --swift-checkouts /absolute/path/to/swiftpm/checkouts \
  --go-module-cache /absolute/path/to/preseeded/go-module-cache \
  --go-root /absolute/path/to/pinned/go/root \
  --notices /absolute/path/to/Reach/release/notices.json \
  --output /private/tmp/reach-release-depot \
  --logs /private/tmp/reach-release-depot-logs
```

Then build from synchronized clean source. The repository authority must have
`HEAD == main == origin/main`, exact clean submodules, no tracked changes, and
no untracked entry except `tasks/`:

```sh
"$REACH_RELEASE_BIN/reach-release-package" build \
  --repository "$REACH_REPOSITORY" \
  --release-tool-source "$REACH_RELEASE_TOOL_SOURCE" \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/tmp/reach-release-depot \
  --work /private/tmp/reach-release-work \
  --output /private/tmp/reach-release-output
```

Verify the selected candidate in a new scratch root:

```sh
"$REACH_RELEASE_BIN/reach-release-package" verify \
  --package /private/tmp/reach-release-output/Reach-0.0.2-unsigned.pkg \
  --release-tool-source "$REACH_RELEASE_TOOL_SOURCE" \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/tmp/reach-release-depot \
  --provenance /private/tmp/reach-release-output/release-provenance.json \
  --notice-manifest /private/tmp/reach-release-output/notice-manifest.json \
  --scratch /private/tmp/reach-release-verify \
  --report /private/tmp/reach-release-output/independent-verification.json
```

The embedded `payload-manifest.json` deliberately has no self-entry. Its final
size and hash live only in `release-provenance.json`. Different unsigned outer
package hashes are expected when XAR creation time differs; the verifier strips
only that field and requires recursively identical component, BOM, cpio,
Distribution, and payload semantics. Any other difference refuses the build.

Both component choices are hidden, initially selected, and UI-disabled, but a
read-only S34 choice-file probe could deselect the helper. That means the clean-
Mac gate must still prove both payloads and receipts before the two components
can be called mandatory in practice. S34 did not invoke Installer or mutate a
receipt. S35 added private Developer ID signing, notarization, and stapling;
Gatekeeper installation, migration, update, rollback, uninstall, and second-
login ownership remain later separately authorized gates.

## Finalizing and verifying a private notarized candidate

S35 adds three credential-bound operations to the release tool. They produce a
private P2 through P5 chain from one already-verified U1 authority. They do not
install, publish, upload to a release feed, mutate receipts, or prove clean-Mac
lifecycle behavior. Keep every work, state, and output root private and use
physical canonical `/private/tmp/...` spellings.

`sign` consumes the exact frozen unsigned authority and two distinct source
authorities: the committed S34 tool that minted U1 and the S35 finalizer. It
requires exactly one valid Developer ID Application identity and one valid
Developer ID Installer identity in the default login Keychain, selects them by
certificate fingerprint internally, signs both executable leaves with Hardened
Runtime and secure timestamps, and signs the outer package:

```sh
"$REACH_RELEASE_BIN/reach-release-package" sign \
  --unsigned-authority /private/path/to/verified-u1-authority \
  --unsigned-tool-source /private/path/to/exact-s34-tool-source \
  --finalizer-tool-source /absolute/path/to/Reach/Tools/ReleasePackage \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/path/to/sealed-dependency-depot \
  --work /private/tmp/reach-sign-work \
  --output /private/tmp/reach-sign-output
```

Create the local credential profile only in an interactive Terminal. Use a
private, nonsynchronized profile label and Apple ID authentication. Never put
the Apple ID, app-specific password, private key, profile label, local identity
selector, or credential environment into a script, command record, repository
file, or evidence pack. Verification evidence necessarily retains public Team
ID, certificate-chain hashes and public signing metadata; those are not
credentials:

```sh
/usr/bin/xcrun notarytool store-credentials PRIVATE_PROFILE_LABEL
```

After independently verifying the exact P3 hash and complete pre-notary report,
submit it once. The durable journal owns the lineage. A timeout resumes by the
persisted submission UUID; it never licenses a second upload. An ambiguous
upload requires the explicit recovery path and renewed authority described by
the retired S35 plan. Before profile validation or upload, the notarizer now
reconstructs the complete Distribution/BOM/cpio/manifest/notice authority,
verifies both nested signatures and the Installer signature, consumes the
canonical independent P3 report, and writes its hash beside the exact P3 hash
in a schema-v2 journal. An unfinished legacy schema-v1 journal fails closed.
Existing exact accepted wait/log files are mode-checked, revalidated, and
reused after interruption rather than overwritten or uploaded again.

```sh
"$REACH_RELEASE_BIN/reach-release-package" notarize \
  --signed-authority /private/tmp/reach-sign-output \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/path/to/sealed-dependency-depot \
  --keychain-profile PRIVATE_PROFILE_LABEL \
  --state /private/tmp/reach-notary/journal.json \
  --output /private/tmp/reach-notarized-output
```

Finally, verify P5 from a fresh scratch root. Verification requires the signed
P0, P1, and U1 stages to equal the retained U1 provenance byte-for-byte, binds
the frozen U1 source and the exact S35 finalizer source that originally minted
P2, checks every embedded certificate in order, and then joins P3 parent, Apple
acceptance, staple, nested signatures, BOM/payload semantics, and local
Installer assessment. Run the corrected verifier executable from the current
checkout, but pass the retained finalizer snapshot whose canonical tree digest
is `264ee25395a16847a770e76de1b474fe71310b62b9f4f6f8ddde54b8cd98925e`:

```sh
"$REACH_RELEASE_BIN/reach-release-package" verify-release \
  --package /private/tmp/reach-notarized-output/Reach-0.0.1.pkg \
  --provenance /private/tmp/reach-notarized-output/release-provenance.json \
  --unsigned-tool-source /private/path/to/exact-s34-tool-source \
  --finalizer-tool-source /private/tmp/reach-s35.Aunigs/finalizer-tool-source/Tools/ReleasePackage \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/path/to/sealed-dependency-depot \
  --scratch /private/tmp/reach-verify-release \
  --report /private/tmp/reach-notarized-output/p5-independent-verification.json
```

When the report is written directly into the signed authority root, the
verifier atomically regenerates that root's `SHA256SUMS`. The result is one
independently checkable sidecar tree containing the P5 report and every small
authority file. A manifest that merely indexes files split across multiple
roots is composite evidence, not a directly checkable `SHA256SUMS` authority.

The six signed-candidate tests are explicitly disabled with the reason
`signed-candidate authority environment is absent` when none of their six
authority variables is present. A partial or malformed environment fails. The
credentialed acceptance gate requires all six to run and rejects a test result
containing a disabled candidate cell.

The accepted S35 package remains private. Do not pass it to Installer or share
it as a release until the separate native clean-Mac install/update/rollback/
uninstall matrix earns both mandatory receipts, retained state, and complete
recovery behavior.

## Private clean-Mac lifecycle tooling — evidenced stop, not an accepted release

S36 adds a nonshipping `reach-release-acceptance` executable and extends the
release core for exact multi-release lineage. This is test and transaction
machinery only. It is absent from both package components and creates no
updater, feed, downloader, telemetry, service, or public install path.

Historical S35 package bytes were lost. S36 selected this replacement sequence:

- A: product/host `0.0.2`, helper `1.0.2`;
- B: product/host `0.0.3`, helper `1.0.2` only if the complete signed A helper
  component is carried forward byte-for-byte without re-signing; and
- one separately reviewed exact-P3 checkpoint before each possible Apple
  submission.

Only replacement A ran. Its exact private authority is P2 `d7a2f296…b9d13`,
P3 `d426499f…c022`, one accepted zero-issue Apple submission, and stapled P5
`042f1543…1b41b`. The self-contained retained P5 remains owner-private. It is
not an installed, published, or clean-Mac-accepted release. Successor B and
every guest lifecycle cell remained unstarted because the supported final
macOS 27 restore-image resolver failed its initial call and two bounded
repeats before any IPSW or VM authority existed.

Schema-1 release configuration and schema-2 signed provenance remain readable
for historical verification. New schema-2 configuration and schema-3 signed
provenance bind the complete predecessor, component disposition, P0–P5
authority, and retained parent. Schema-2 configuration permits the unsigned
and finalizer roles to bind the same source digest; both fields remain
independently present and verified in schema-3 provenance. Historical schema 1
still requires distinct digests. Freeze the lineage only from a complete local
authority; a caller-supplied parent hash is never sufficient:

```sh
"$REACH_RELEASE_BIN/reach-release-package" freeze-lineage \
  --unsigned-authority /private/path/to/verified-u1-authority \
  --unsigned-tool-source /private/path/to/exact-u1-tool-source \
  --configuration /absolute/path/to/Reach/release/release.json \
  --notices /absolute/path/to/Reach/release/notices.json \
  --depot /private/path/to/sealed-dependency-depot \
  --scratch /private/tmp/reach-lineage-freeze \
  --output /private/tmp/reach-lineage.json
```

For B, add `--parent-authority` naming the complete retained A P5 tree. The
same parent tree is required again by `sign`; an unchanged helper is accepted
only after its payload and executable runtime-content digest match A. The
successor would embed A's complete signed helper component XAR byte-for-byte
without rebuilding or re-signing it. S36 stopped before that path began; any
future successor or clean-Mac pass requires a new ruling and fresh authority.
Never infer installability, publication, or lifecycle acceptance from the
retained private P5 alone.

The acceptance driver has two explicit authorities. Host mode may control only
`reach-s36-macos27-base` and `reach-s36-macos27-acceptance` through exact Tart
2.35.0 and pinned SSH. Guest mode implements only `inspect`, `migrate`,
`install`, `update`, `recover`, `rollback`, `uninstall`, and `verify`, plus the
bounded mandatory-choice, owner-contention, crash-recovery, and reset probes.
Every destructive operation is journaled, uses exact retained P5 authority,
and refuses mixed receipts, a mismatched live executable text vnode, altered
launch definitions, unowned or metadata-weakened state, paths anywhere under
the complete package root, or changed retained cluster state. Restore-image
verification reloads the local IPSW through Virtualization.framework rather
than trusting the recorded product/build claims. The second-user test is a
three-command ceremony:
`owner-contention-begin` as the selected owner, `owner-contention-check` as the
distinct contender, then root-owned `owner-contention-finish`; any second
service or CA authority fires `OWNER-CONTENTION`. Failure to install the probe
definition, failure to bootstrap it, or bootstrap without an observable
ownership result is inconclusive and cannot be reported as a safe refusal. A
safe refusal additionally requires one failed launchd run and the exact bounded
daemon line `Error: this Mac is already bound to another Reach login owner`,
with no state or CA creation. A transiently running contender does not settle
that decision. After the bounded application result, the driver boots the
contender out, confirms it is unloaded, re-observes its state, and only then
records refusal if state is absent and CA creation is still zero. The physical
cell stops if the installed product does not actually produce that attributable
result.

After the acceptance clone is running, bind its exact pinned-SSH files and the
complete S36-owned tooling root to the rig once. Every later SSH operation
requires this same authority. Before teardown, freeze those exact live vnodes
into the evidence run. The coordinator atomically renames each credential and
the complete tooling root to deterministic hidden tombstones on the same
volume, verifies the exact open vnode through that claim, and durably records
the complete claim before deletion. It then holds and verifies each claimed
vnode while deleting it and records per-vnode progress. Recovery accepts a
missing tombstone only behind that exact durable progress; an unclaimed
disappearance, moved credential, substituted vnode, weakened mode, or unbound
path fails closed. Output, inventory, both journals, and teardown authority
must be distinct and disjoint in both directions from all original and claimed
paths before any mutation:

```sh
"$REACH_RELEASE_BIN/reach-release-acceptance" host bind-host-authority \
  --tart-sha256 "$REACH_TART_SHA256" \
  --logs /private/path/host-logs \
  --rig-journal /private/path/rig.json \
  --identity /private/path/id_ed25519 \
  --known-hosts /private/path/known_hosts \
  --tooling-root /private/path/s36-tooling \
  --host-authority /private/path/host-authority.json \
  --output /private/path/host-authority-binding.json

"$REACH_RELEASE_BIN/reach-release-acceptance" host evidence-freeze-teardown \
  --evidence-journal /private/path/evidence.json \
  --rig-journal /private/path/rig.json \
  --host-authority /private/path/host-authority.json \
  --authority /private/path/teardown-authority.json \
  --output /private/path/freeze-result.json

"$REACH_RELEASE_BIN/reach-release-acceptance" host evidence-destroy \
  --evidence-journal /private/path/evidence.json \
  --rig-journal /private/path/rig.json \
  --kind credentials \
  --authority /private/path/teardown-authority.json \
  --inventory /private/path/credentials-absent.json \
  --output /private/path/credentials-destroyed.json
```

For unmanaged-layout migration, the retained A payload record is authoritative:
the driver opens and verifies that exact `reachd` path and requires the running
process text vnode to be the same device/inode. A replaced or deleted live
image refuses; merely finding the expected bytes at the pathname is not enough.

The vnode-authority correction completed a **152-test suite three times**, with
six explicit signed-candidate skips per run, plus a **25/25 focused spine three
times**. The prior sealed unchanged-product gates remain joined: ReachKit
95/95, reachd 250/250, and mesh-helper full/race/vet/offline PASS.
Warnings-as-errors release binaries hash to `76252cdb…9bcbe`
(`reach-release-package`) and `23008f9a…8d3c6`
(`reach-release-acceptance`). The current privacy-minimized pack is
`/private/tmp/reach-s36-offline-authority-vnode-correction-authoritative-20260824`;
its direct 11-entry manifest seals at `d2e49779…c5776`, and its 62-file source
manifest hashes to `1ab020dd…75b2e`. These results do not prove Tart, Apple restore-image,
Installer, Metal-in-VM, update, rollback, uninstall, or real teardown behavior.
At that 24 August offline checkpoint, no Tart binary, IPSW, VM, replacement
U1/P3/P5, signing identity, Apple submission, live-host install, or Keeper
change had occurred. This is historical checkpoint evidence; the later S36
closeout below supersedes its release-authority state without changing its
unchanged-product verdict.

### Installed Metal authority for release builds

Do not set `TOOLCHAINS`, use an identifier-only `xcrun --toolchain`, or copy a
cryptex mount path into release configuration. On this Xcode 27 host the
installed Metal component is discoverable only through the exact read-only
`xcodebuild -showComponent MetalToolchain` record, while identifier-only lookup
still resolves the default wrapper. The release builder therefore owns the
complete selection:

1. it parses one exact installed record and derives the physical
   `Metal.xctoolchain` root from its reported search path;
2. it authenticates that root, its vnode, read-only/root ownership, installed
   identifier/build, three metadata files, and the `metal` plus
   `metallib`/`air-lld` executables before and after each build phase;
3. it passes the authenticated physical root explicitly to both SwiftPM build
   and `--show-bin-path`, selects exactly one bounded XCBuild manifest beneath
   that pass's expected scratch authority, and structurally decodes its JSON.
   Selection is descriptor-anchored from the already authenticated scratch
   vnode: every `out/Intermediates.noindex/XCBuildData/<32-hex>.xcbuilddata`
   component and `manifest.json` is opened relative to its parent with
   no-follow semantics, raw directory-entry bytes, exact on-disk spelling, and
   before/after vnode checks. A symlinked scratch child or a correct-looking
   manifest outside that chain therefore cannot satisfy the gate.
   The current graph must contain exactly nine named MLX `CompileMetalFile`
   tasks and one AIR `MetalLink` task, with the exact source/AIR/metallib paths;
   every task's absolute executable must resolve to the frozen physical path
   and vnode. Decoy text, relative or foreign tools, missing or extra roles,
   ambiguous manifests, and oversized graphs refuse; and
4. it persists only stable component identifier/build and metadata/tool
   hashes/versions. The reboot-variable mount spelling must not enter the
   payload, package semantics, or provenance.

That live installed-toolchain equality is deliberately limited to build and
signed-finalization hosts. Generic unsigned verification, signed payload/P3/P5
verification, and the clean guest's static-trust cell do not run
`xcodebuild -showComponent` or require Xcode/Metal to be installed. They
structurally validate the embedded stable Metal authority and join it to the
retained P0/U1 provenance, reports, configuration, notices, and depot. A
different or unavailable local compiler therefore cannot block static package
verification; any changed declared authority still refuses. Historical
schema-1 material remains the distinct no-Metal compatibility path.

Current replacement releases require this schema-2 Metal authority.
Historical schema-1 material remains verifiable only through its historical
no-Metal compatibility path. A package built from an uncommitted correction is
diagnostic (`admittedU1: false`), even if its independent package verification
passes. Review, commit/push synchronization and the complete varied-root gate
are still required before naming U1.

XCBuild graph paths and stable Metal strings are byte authorities, not Swift
`String` identities. The
verifier converts every expected and observed source, AIR and metallib path to
its exact UTF-8 bytes before duplicate detection, membership checks or final
graph comparison. Canonically equivalent composed/decomposed spellings are
therefore different and refuse the build. Stable component, metadata, tool,
resolved-path, hash, and multiline tool-version fields use the same byte-exact
equality, so Unicode canonical equivalence cannot substitute a retained
authority. Signed static verification likewise
requires the retained P5 payload report's stable Metal authority to equal the
independently reconstructed authority. On a signing host, the live installed-
Metal equality gate runs after portable U1 materialization but before any
output-authority file is copied and before the login Keychain is consulted; a
mismatch leaves the empty output root reusable by a later invocation. The
materialized work root is still disposable transaction state and is not
reusable after that failed invocation.

### S36 closeout boundary

Replacement A's private P5 remains a verification authority only. Native
static verification rejoins its 5,264-entry retained manifest, 50 host files,
6 helper files, Developer ID chains and timestamps, stapled ticket, and local
Installer assessment. It does not prove installation, owner selection, model
execution, dialing, update, rollback, uninstall, or retained-state reinstall.

The decisive rig stop occurred before any guest was created:
`VZMacOSRestoreImage.latestSupported` failed once and then failed in two
bounded repeats. No restore-image record or IPSW existed, so the final-build
validator was never invoked. The host's seed-suffixed build is only contextual
runner drift; it was not passed to or rejected by the image validator. A future
clean-Mac or physical-hardware pass must begin with new, independently reviewed
rig authority. S36 created no install instructions, updater, feed, publication,
or live-host mutation.

## The reference relay hub is accepted substrate, not a running Reach service

`relay-hub/` has a measured scriptless package boundary on native Ubuntu 26.04
arm64, but Reach does not install or operate it. The package is inert: it
contains only the static binary, systemd unit, sysusers/tmpfiles declarations,
licenses/notices and route-inventory documentation. An administrator must
supply strict operator files and a local firewall, then explicitly enable the
unit. The service runs as `reach-relay` with zero capabilities; its wildcard
WireGuard UDP listener is safe only behind the mandatory terminal port-drop
policy described in [`relay-hub/README.md`](../relay-hub/README.md).

The accepted operator paths are `/etc/reach-relay-hub/config.json` and
`routes.json`; live status is `/run/reach-relay-hub/status.json`. `systemctl
reload reach-relay-hub` performs the serialized local reread. `SIGUSR1`
revalidates live backend/router authority and refreshes status. Package removal
does not destroy operator-owned configuration or state; retirement requires an
explicit stop/disable, purge, operator-state removal, firewall removal, and
account removal only after confirming nothing else owns it.

This is Linux arm64 runtime/package acceptance, not an operational relay, a
public endpoint, a Reach road, amd64 runtime acceptance, or permission to
provision one. The complete bounded evidence is recorded as S30 in
[`spikes.md`](spikes.md).

The accepted unit also started at the schema maximum—253 devices plus the
host—without approaching its fixed cgroup, task or file-descriptor limits.
The service identity could not create a link, route, network namespace or
nftables table. The same PID then returned to the three-peer encrypted fixture
and forwarded 3/3 before the package, account, firewall, fixture and VM were
removed. This is a capacity/privilege acceptance fact, not sizing guidance for
an operational public hub.

`reachd serve` in a terminal is a legitimate way to work and is how every
demo has been shot. What it is not is a service: when the process dies —
a crash, an update, a Mac that rebooted — nothing brings it back, and every
granted app on every device sees a cluster that is simply not there.

`reachd doctor` says which of the two you have, under **supervision**.

## Whether the cluster can actually answer

`doctor` on its own is about the host: the state directory, the config, the
CA, the ports being held, the agent being installed. All of it can be green
over a cluster that cannot serve a client — the port check binds `INADDR_ANY`
and can only tell you that *something* holds the port, never that the
something answers.

```
reachd doctor --dial
```

opens a real session against the running daemon with the ordinary client
stack, and reports the road the daemon says it came in on:

```
PASS  dial              a session opened over 127.0.0.1:47337 in 38 ms — the cluster answers a client
PASS  road              the daemon logged the session: opened from 127.0.0.1:65246
```

It mints an ephemeral identity from the cluster's own CA — five minutes,
`reach://diagnostic/…`, never stored, never in the keychain — and asks for no
tokens: `reachd selftest --mlx` already proves generation end to end, and the
model prewarms asynchronously at every login, so a dial that wanted a token
would fail on a healthy cluster that had just started.

A daemon that is simply not running is `WAIT`. A daemon that is running and
cannot answer is `FAIL`, and only `FAIL` gates the exit status.

`--via <host[:port]>` dials one chosen road instead of loopback, which is how you
prove a road from the host side before asking a device to use it, and
`--dial-budget <seconds>` (default 10) bounds the whole attempt — the dial gets
half of it and the exchange on the far side gets the rest, so both halves stay
inside the number you asked for.

⚠️ **A tunnel address is the exception**: this host cannot dial its own mesh
address — plain UDP and ICMP to it are dropped the same way — so `--via` the
mesh address must be run from the other end of the tunnel, not from the
cluster.

## Automatic mappings

While serving, reachd holds two long-lived UDP mapping requests through the
macOS system broker: the configured session port and WireGuard `51820`. It asks
for the same external ports and the system-default lease lifetime, but the
router may assign different ports. Enrollment is not mapped. The system renews
the mappings and reports network, address, or port changes on the same request;
stopping the daemon deallocates both.

`doctor` prints separate `session mapping` and `mesh mapping` findings. Active
public mappings pass. A private/shared outer address or an explicit double-NAT
callback warns and is described as usable only from that outer network.
Probing waits; unsupported, disabled, absent-router, zero-endpoint, and broker
errors warn without changing local or pinned behavior. A dead process's active
record is called stale, and endpoint movement names the replaced value. The
evidence lives at `reachability.json` in the state directory with mode `0600`;
it is runtime diagnostics, never configuration and never an authority for a
road.

An assigned endpoint can be exercised directly:

```
reachd doctor --dial --via 198.51.100.8:55001
```

The QUIC listener requires a cluster-issued client certificate at TLS even
when mapped onto a public interface. WireGuard accepts only enrolled peer keys.
Neither fact makes a private double-NAT address public: single-NAT edges are
the direct-mapping case, while CGNAT, building routers, and VPN layers may
still require a manually reachable endpoint or a configured and provisioned
relay as described in [relay.md](relay.md). Negotiated calling-card support is
installed, but no public endpoint or Keeper-provisioned device exists. A client
already away when an endpoint moves keeps its
stale road until it can authenticate on another one and receive a fresh hello.

## When the model slot is busy

The current MLX filling executes one public generation at a time. Three more
generations may wait globally in FIFO order, with at most one waiter from a
given session. Waiting is resident work: it can lose its QUIC stream and
re-attach without taking another place, and every schema or tool pass stays
inside the one lease held by that public generation.

A fourth accepted generation occupies the last waiting place. A fifth is
refused immediately with `cluster-busy`; so is a second waiter from one
session. Those refusals mean the authenticated cluster answered and its road
is healthy. A waiter that spends 120 seconds without reaching the model slot
ends with a generation error rather than running late or masquerading as a
network failure.

The daemon logs only privacy-safe admission transitions: startup policy,
active/waiting counts, FIFO promotion time, release outcome, refusals,
cancellation and timeout. It logs no prompt, output, endpoint, identity or
token count. `provider admission queued` followed by `promoted the oldest
waiter` is normal load; `waiting room is full` calls for retrying after current
work finishes; `timed out queued work` says the road stayed healthy but demand
outlived the two-minute bound. Live queue state is intentionally absent from
`doctor` and `service status`: v0 has no management channel from which either
command could read an authoritative remote snapshot.

## When replay capacity is exhausted

The daemon keeps unacknowledged generation events in memory as their exact
encoded v0 frames. One generation has a 16,777,220-byte window (one maximum
wire frame including its length prefix), and the process has four windows, or
67,108,880 bytes. These are replay limits, not answer-length or token limits:
an attached client continues receiving live events when storage pressure
starts.

Startup records the policy without reporting live usage:

```
[reachd] replay store ready: exact framed bytes, one maximum-frame window per generation, four-window process budget, volatile across daemon restart
```

Capacity and integrity notices are deliberately privacy-safe. A
`replay capacity exhausted for one generation` or `replay process budget
unavailable to the appending generation` line means live delivery continued,
but a later re-attach may be refused if it asks inside the discarded prefix.
The process budget never reclaims another generation's window. A
`generation event exceeded the wire frame limit` line instead means one event
could not fit any v0 envelope; that generation receives a legible terminal
error rather than a false success. An integrity failure likewise discards the
affected window and refuses future replay; its count remains package-internal
rather than becoming a live operator metric. None of the replay logs contains
a prompt, output, endpoint, identity, byte total, cursor or token count.

Acknowledgements release exact framed bytes. The popped frame's backing
`Data` is destroyed in that same operation rather than waiting for queue
metadata compaction, so physical payload ownership follows the byte counter.
Queued generations have emitted no events and consume none. A completed
generation record keeps any remaining unacknowledged replay for the existing
ten-minute window, detached work keeps the existing two-minute residency, and
daemon shutdown clears all replay immediately. There is no spill file or
transcript database to inspect or clean up; process durability is a separate
design boundary.

## When the daemon process dies

Do not confuse four healthy but different mechanisms:

- launchd restarts the service and preserves the cluster's on-disk identity,
  grants, mesh intent and configuration;
- the in-memory replay store preserves exact frames only while the same daemon
  process is alive;
- the pinned MLX stack can save raw KV tensors, but not the complete iterator,
  sampler, detokenizer, grammar/tool-parser, usage and event-cursor state of a
  public generation; and
- the adopting app, not the daemon, owns any effect caused by a delivered tool
  call.

S27 killed the installed daemon after four clients had established one active
and three queued residents. Approval latency let the first active generation
finish and promoted the oldest waiter before the signal arrived, so the actual
kill caught one active and two queued. The promoted generation, which had
started producing work, ended with the existing legible lost-answer sentence.
The two unseen waiters reopened fresh sessions and were accepted at sequence 0
by the empty replacement daemon, meaning they executed as new work rather than
recovering queue state. This is why the startup admission/replay counters return
to zero after a restart.

Operationally, a visible in-flight answer is not resumable after process death.
The app says that it stopped and that asking again starts a new one. Work that
had not delivered an event may be resent idempotently by the client, but it is
not a restored provider task and must be treated as re-execution. The pinned
stack's raw KV-cache files do not change that conclusion: S27 found no complete
checkpoint for ordinary, guided, allowed-tool or required-tool routes, and its
loader accepted both a truncated and a bit-flipped probe file. No durable
generation journal or generated content exists to inspect, rotate or erase.

## As a service

⚠️ **`reachd` is not a single file.** SwiftPM emits resource bundles beside the
executable, and MLX finds its Metal library by looking there. A binary copied
on its own starts, prints that it is serving, binds the port, and *then* dies
loading the model — which under launchd is a crash loop at every login whose
only clue is a metallib path deep inside a build directory. Copy the
directory, not the file:

```
swift build -c release --package-path reachd --scratch-path ~/Library/Caches/reach-spm/reachd-release
```

```
mkdir -p ~/.local/libexec/reach && cp -R ~/Library/Caches/reach-spm/reachd-release/out/Products/Release/{reachd,*.bundle} ~/.local/libexec/reach/
```

```
ln -sf ~/.local/libexec/reach/reachd ~/.local/bin/reachd && reachd service install
```

`~/.local` rather than `/usr/local/bin` because the agent runs as you and
needs no `sudo`; either works. `service install` refuses a binary with no
`mlx-swift_Cmlx.bundle` beside it, and refuses one inside a build directory:
`~/Library/Caches` is purgeable — macOS reclaims it under disk pressure
without asking — so an agent pointed there works until the day it silently
does not. It also refuses to install as root: the service belongs to one login
user and one `gui/<uid>` domain.

The installed command normalizes its executable identity before argument
parsing or MLX access. These all reach the same binary and the same seven
adjacent bundles:

```
~/.local/libexec/reach/reachd selftest --mlx
~/.local/bin/reachd selftest --mlx
reachd selftest --mlx
```

Absolute, nested and `PATH` symlinks are resolved once with no wrapper shell
and no resource copies beside the alias. User arguments, the environment and
the working directory survive the process replacement. `service install`
retains its independent guard: it resolves symlinks before writing the plist,
so the supervised agent records `~/.local/libexec/reach/reachd`, verifies the
adjacent MLX bundle, and starts directly in the canonical layout.

### ⚠️ Reinstalling can quietly destroy the cluster

A `serve` that cannot find its CA does not fail — it **mints a fresh one**,
which orphans every paired device and voids every grant, unattended, at
ten-second intervals under `KeepAlive`. So a reinstall is guarded rather than
just done:

1. Back up `~/Library/Application Support/Reach` and record
   `shasum ~/Library/Application\ Support/Reach/ca/*` — four files.
2. Build the release, as above.
3. `launchctl bootout gui/$(id -u)/systems.reach.reachd` — **before** copying.
   Never copy over a running binary. (`reachd service install` does its own
   bootout and bootstrap and is the supported path; by hand is for watching
   each step.)
4. Copy the binary **and the bundles**. Count what lands: eight items. On a
   reinstall, copy the executable to a fresh sibling such as `reachd.next`,
   run `codesign --verify --verbose=4` on it, and then
   `mv -f reachd.next reachd` while the agent is stopped. Do not use `cp` to
   overwrite the existing executable inode in place: launchd can retain that
   vnode's old code-signing state and kill the otherwise-valid replacement with
   `OS_REASON_CODESIGNING`.
5. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/systems.reach.reachd.plist`
6. Then seven checks, and it is not installed until all seven pass:
   `grep -c "cluster CA created" ~/Library/Logs/reachd.log` is **0**; the four
   CA fingerprints are unchanged; `doctor` says `PASS supervision`; and
   **`doctor --dial` says the cluster answers**. The first six are about the
   host and were all green, five separate times on 6 August 2026, over a
   cluster that could not serve a client.

`reachd service status` reports the owning login UID and `gui/<uid>` domain,
the exact state and log paths, whether the agent is loaded, and separately
whether an exact `10.86.0.0/24` mesh address is present. An unrelated
`10.86.1.x` address is not Reach mesh readiness. A running PID with a missing
mesh is explicitly incomplete away readiness, not a healthy service inferred
from process state.

`reachd service install` writes the plist through
`PropertyListSerialization` and pins the owning login user's canonical Reach
state with an explicit `REACH_STATE_DIR`; paths containing spaces or
XML-significant characters are data, not hand-built XML. A shell may use
`REACH_STATE_DIR` for foreground or scratch commands, but it may not relocate
the persistent service: installation refuses any nonempty override that does
not standardize to the canonical login state and tells the operator to unset
it. `--no-load` does not bypass that check.

Status and doctor parse the installed plist rather than falling back to the
calling shell. An unreadable plist, missing or relative state value, or
noncanonical installed state is a failure. Ordinary doctor also fails when an
ambient override makes it inspect a different state; explicit
`doctor --state` keeps that deliberate scratch report useful by saying the
scratch state is not supervised.

`reachd service uninstall` removes it. Output goes to
`~/Library/Logs/reachd.log`, because every line the daemon writes is `print`
or stderr and launchd sends those nowhere by default. `serve` line-buffers
stdout so that log is readable while the daemon is healthy — block buffering
would fill it only when the process died, which is the wrong way round.

### It starts at login, not at boot

This is deliberately a **login-owned LaunchAgent**. A Mac that has rebooted
does not serve at the login screen; it begins serving after the owning user
logs in and the `gui/<uid>` domain exists. Two physical reboot trials showed
that exact bounded refusal before login and one automatically supervised
daemon after login.

The reason is the selected ownership contract, not a login-keychain
requirement. The cluster state, operator commands, and MLX/Metal process belong
to one user. The listener leaf is loaded from that user's disk state and
imported into process memory with `kSecImportToMemoryOnly`. A root process with
no explicit state path would instead resolve `/var/root/Library/Application
Support`, mint a different CA, and silently become a different cluster.

Accordingly, `service install` refuses root, and `reachd serve` refuses root
unless `REACH_STATE_DIR` names an explicit absolute state directory. That
override is for controlled foreground/scratch/system-context work; it neither
relocates the persistent login service nor makes pre-login serving supported.
The generated agent always sets `REACH_STATE_DIR` to the owning user's
canonical Reach directory, so launchd never guesses which cluster it should
start.

### What closing the lid does

Sleep is measured separately from reboot. On one MacBook Pro (`Mac17,9`) under
macOS 27.0, the installed cluster survived two roughly one-minute sleeps, two
roughly ten-minute sleeps, and two sleeps longer than eight hours without a
daemon restart, listener loss, WireGuard loss, CA change, or model reload.
`ProcessType: Interactive` was left alone: it controls launchd's resource
classification and does not prevent system sleep.

An in-flight response may appear to pause while the machine is fully asleep.
In both short trials the same generation resumed and completed after wake.
During both ten-minute trials, active QUIC traffic instead caused network dark
wakes long enough for the real-weight response to finish while the lid was
closed; macOS then returned to deep sleep. The 120-second residency window
still bounds an unavailable generation, but closing the lid does not by itself
start a countdown while the OS continues servicing that flow.

The idle overnight result is colder: the same launchd PID and run count,
listeners, roughly 4.3 GiB resident model, and `10.86.0.1` interface survived
8 h 18 m and 8 h 00 m sleeps. A fresh authenticated generation succeeded after
each wake. The temporary mapping trial found that a 7,200-second router lease
can expire while the host is deeply asleep; the unchanged macOS broker rebuilt
both mappings four seconds after wake. Because it already performs that wake
refresh, reachd has no custom sleep observer or wake handler.

This is evidence from one host and OS build, not a promise that macOS will keep
every process resident indefinitely. Unconditional launchd supervision still
covers a process death. If the listener is absent after wake, inspect
`~/Library/Logs/reachd.log`, the launchd run count, `lsof -nP -iUDP:47337`, and
`reachd doctor --dial` rather than assuming sleep was healthy because the PID
now exists.

Sleep also does not erase the login boundary above. The S23 lifecycle matrix,
before the privileged helper existed, repeated lock once, logout/login twice,
and reboot/pre-login/login twice. Lock preserved the same daemon; each login
created exactly one new supervised daemon with unchanged state. Both reboots
returned the LaunchAgent after login but did not raise WireGuard. Raising
`reach0` manually after the daemon started worked without a daemon restart:
the wildcard listener accepted the mesh road immediately, and the next
authenticated hello advertised the new address.

S24 replaced that manual road ownership with `systems.reach.meshd`. A final
reboot of the route-corrected installed helper brought `10.86.0.1/24` and its
connected route up before login while `reachd` remained absent. Login then
started exactly one serving daemon, and a building-network phone cold-opened
over `10.86.0.2` and streamed to completion without a Terminal command.
Pre-login serving remains unsupported; automatic mesh preparation is now the
root helper's launchd contract. Fast user switching and OS-update survival
remain unmeasured.

### What it restarts

Everything. `KeepAlive` is unconditional, with `ThrottleInterval` putting a
ten-second floor under the retry. Measured: `kill -9` on the daemon and it is
back in about two seconds.

It was first written as `KeepAlive: {Crashed: true}`, on the reasoning that
the daemon's considered non-zero exit for a held port should not become a
respawn loop. Installing it and killing the daemon showed that reasoning was
worth less than the test: **launchd counts a crash as the SIGSEGV/SIGABRT
family, not a deliberate signal, so `Crashed` did not bring it back at all.**
It also misses the kernel's own `SIGKILL` under memory pressure, which is the
likeliest unplanned death of a process holding several gigabytes of weights.
A supervisor whose job is that the cluster is there cannot be selective about
which deaths count.

The consequence is that a genuinely held port re-attempts every ten seconds.
That heals itself the moment the port frees — which is the restart race, and
the common case — and if something else owns 47337 permanently, the reason
lands in the log at the same pace. `lsof -nP -iUDP:47337` finds who has it.

### The mesh has a separate privileged owner

The login service still owns the cluster; a distinct root service owns only
the WireGuard interface:

| owner | executable | data it may read |
| --- | --- | --- |
| login user | `reachd` | cluster state, CA, registry, model, non-secret `mesh-intent.json` |
| root | `systems.reach.meshd` | one strict mesh specification and its own root state |

`systems.reach.meshd` is one ad-hoc-signed Go executable with pinned
`wireguard-go` embedded in it. It has no Homebrew, `wg`, shell, user
environment, cluster-state or model dependency. Its scriptless component
package installs exactly the executable at
`/Library/PrivilegedHelperTools/systems.reach.meshd` and a fixed
`/Library/LaunchDaemons/systems.reach.meshd.plist`. The job is `RunAtLoad`,
unconditionally kept alive, throttled to ten seconds, and starts with umask
`077`. The currently installed local package records hashes and still uses an
ad-hoc code signature. S35 produced a separate private Developer-ID-signed and
notarized release candidate without installing it; trusted clean-Mac install/
update/rollback/uninstall acceptance remains future work.

The helper's version-1 input is data, not a configuration language. It fixes
the host at `10.86.0.1/24`, UDP `51820`, MTU `1280`, installs the connected
`10.86.0.0/24` route on the interface it created, and accepts only an
ordered set of unique `10.86.0.2...254/32` peers with canonical 32-byte keys
and bounded keepalives. Unknown or duplicate JSON keys, hooks, commands,
paths, malformed routes, unsafe files, reused generations and rollbacks are
refused. The root service retains the last-known-good generation and exposes
only a public status containing its version, PID, generation, public digest,
interface name, readiness, peer count, timestamp and bounded error. Readiness
and the bounded error are separate facts. `ready: true` says the named
generation and interface are live; an accompanying `configuration rejected`,
`update refused`, or `rollback restored` records the most recent nonfatal
update outcome without claiming that the active road went down. `ready: false`
always has an empty interface name and a current blocker such as
`unconfigured` or `interface unavailable`; generation, digest and peer count
may remain only as recovery context for the durable active specification.
`rollback restored` is never a non-ready state. A normal successful start,
apply, or idempotent reapply clears the old bounded outcome.

The user-owned `mesh-intent.json` is the persistent enrollment intent and
contains no host private key. On the first upgraded serve, Reach strictly
imports the existing hook-free `reach0.conf` once and leaves its bytes
untouched as rollback evidence. It will never execute that file. Every later
peer change updates intent and says that an administrator apply is pending:

```
reachd mesh stage
reachd mesh apply
```

`stage` cross-checks the intent against the active device registry and creates
one mode-`0600` secret-bearing file inside a mode-`0700` user directory.
`apply` prints the exact operation, then uses `/usr/bin/sudo` to invoke only
the installed root-owned helper. The helper requires a real root invocation,
a valid `SUDO_UID`, the unchanged regular file owned by that user, and the
root-only control socket; it consumes the staging file on acceptance or
refusal. There is no `NOPASSWD` rule or permanent authorization. During a
bounded local install/acceptance session, the package install, first apply,
crash check and rollback can be grouped behind one native administrator
authorization instead of prompting for each operation.

### Optional host relay intent

One existing interface and host key can also own one optional relay overlay.
Changing that intent is unprivileged and never applies it automatically:

```text
reachd mesh relay set \
  --network 10.87.0.0/24 \
  --hub-public-key <base64-public-key> \
  --endpoint <numeric-ip:port>
reachd mesh apply

reachd mesh relay remove
reachd mesh apply
```

`relay set` accepts one canonical RFC1918 `/24`, derives host `.1/32` and each
device's matching relay `/32`, requires a numeric IPv4 or bracketed IPv6
endpoint on port `1024...65535`, and fixes keepalive at 25 seconds. It refuses
overlap with the direct mesh and active non-default IPv4 routes. That CLI check
is only early feedback: the privileged owner rereads the Darwin route table
immediately before mutation and is authoritative. Existing exact helper-owned
relay routes are exempt only for an idempotent update.

The commands do not print the hub key or endpoint. They print generation plus
complete, direct and relay public digests and instruct the operator to run the
separate apply ceremony. Enrollment and relay edits use one secure intent lock;
when a direct peer is added while relay is configured, its relay `/32` is
rederived in the same generation. Removing relay returns the intent to
canonical version 1 while preserving every direct field except generation.

Helper status version 2 exposes independent direct and relay components. Read
them separately: direct can remain PASS while desired relay is WAIT for apply,
or while a refused update leaves the last-known-good direct road live. Overall
ready requires exact direct authority plus either exact configured relay state
or verified relay absence. A relay-only change does not restart `reachd` and
does not restart the WireGuard interface; unchanged direct peers retain their
runtime state. A removed/recreated hub peer may not.

This host-side state is never an ordinary direct road. Pairing, legacy
`addrs`, and authenticated `HelloAck.roads` exclude every relay alias and every
non-direct IPv4 on the interface owning `10.86.0.1`. Do not interpret a relay
alias in `ifconfig` as a direct candidate. Selected-v1 sessions may advertise
it only through the separate authenticated `relayRoads` field; selected-v0
sessions omit and ignore that vocabulary.

The installed S31 acceptance deliberately added, updated, refused, crash-
recovered, and removed a local synthetic relay while the daemon PID and direct
authority stayed fixed. Its final exact-byte interruption test also held
claimed generation 12 apart from newer pending generation 13 across a helper
crash. The complete rerun ends at intent generation 18 in canonical version 1,
helper status version 2 with
`direct.ready: true`, `relay.configured: false`, and `relay.ready: true`, and
no relay alias, route, hub peer, pending specification, or claimed
specification. A normal operator should therefore treat
`relay configured false; verified absent` as a healthy direct-only ending, not
as a missing mesh. The exact accepted reachd and helper hashes are recorded in
`docs/spikes.md`; a real authenticated `doctor --dial` passed after the rerun.
The final acknowledgement correction binds `mesh apply` to the staged
generation and public digest: completing an older surviving claim can no
longer make a newer invocation report success. Its installed regression proved
that ordering directly, then repeated the full matrix and restored canonical
direct-only generation 25 with helper `a784f257…b28ca8`. Reachd remained PID
86352 throughout, and the final authenticated dial passed on attempt 1.

### Negotiated relay calling cards

Reachd and ReachKit now support dialect v1 over the unchanged `reach/0`
envelope. Direct calling cards and relay calling cards remain separate:

- `relayRoads` omitted preserves the authenticated relay store;
- `relayRoads: []` clears it; and
- a nonempty list replaces it atomically.

Relay candidates are held in Keychain service
`systems.reach.cluster-relay-roads`, not the direct-road service. A selected-v0
session neither reads the field nor mutates that record. Deleting a cluster
identity deletes both records. Only the current authenticated road epoch may
commit a declaration, so a delayed probe cannot restore stale relay authority.

The measured hedge is **100 ms**. Direct candidates start immediately; relay
candidates start 100 ms later unless direct has already won. The positive grace
is deliberate: a 0 ms race is fastest-authenticated-road behavior and cannot
promise direct preference. All attempts share the same ten-second deadline and
all losers are cancelled. A healthy relay session or reattached generation
stays where it is. Once a session is invalidated, however, its previously
proven direct road is no longer a direct-only fast path; the next independent
open returns to the tiered race under that original deadline.

Privacy-safe logs and generation receipts use `relay-overlay` only when the
raw source falls within the operator-configured relay prefix. Use the private
transport log, helper routes, and WireGuard counters for exact acceptance
joins; the privacy-safe category deliberately contains no address or port.
`service status` and `doctor` diagnose host ownership, not whether a live
client currently has a relay store.

S32's corrected exact bytes installed reachd `a9660a83…6b790` and left helper
`a784f257…b28ca8` unchanged. The local matrix authenticated an exact backed-up
v0 client, exercised v1 replace/preserve/clear, the measured 100 ms direct-first
and relay-only cold dials, and completed one same-generation transition in each
direction. Final helper generation 37 is canonical direct-only with relay
configured false and verified absent; all identities, direct-road stores,
Keeper, and CA-creation count were unchanged. Installed scripted/MLX selftests
and an authenticated 36 ms dial passed. This is not a public relay deployment
and does not provision Keeper.

`reachd service status` and `reachd doctor` report the login daemon and mesh
owner separately, using the same mesh-owner verdict. An absent or
not-yet-configured helper is `WAIT`; a legacy manually raised interface is
usable but unmanaged. Unsafe ownership, malformed state, PID or interface
disagreement, a generation rollback, a configured non-ready road, or a ready
claim without exact `10.86.0.1` is `FAIL`. Exact desired/live authority with
no bounded outcome is `PASS`; the same ready authority with a nonfatal outcome
is `WARN`; and a ready generation behind login-owned intent is `WAIT`, includes
the outcome, and names `reachd mesh apply`. Thus “the last update failed but
the old road is healthy” cannot be mistaken for “there is currently no road.”

The helper may already have prepared the mesh at the login screen after a
reboot. That does not broaden Reach's serving boundary: no `reachd`, model or
cluster session exists until the owning user logs in. Once the login daemon
starts, it immediately sees the existing wildcard road. If the mesh instead
rises later, **do not restart `reachd`**; every authenticated hello recomputes
current addresses. A client already away still needs one reachable hello to
learn a road that did not exist on its previous calling card.

For diagnosis:

```
reachd service status
reachd doctor
sudo launchctl print system/systems.reach.meshd
cat '/Library/Application Support/Reach Mesh/status.json'
/sbin/route -n get 10.86.0.2
```

The status file is deliberately public and privacy-safe. The active and
pending specifications under the adjacent `private` directory are root-only
and must never be printed. The route query must name the helper's current
`utun`; a default route or LAN interface means the address alone is not a
usable mesh road. Uninstalling means booting out the system job, removing the
two packaged artifacts and `/Library/Application Support/Reach Mesh`,
forgetting the package receipt, and verifying that the control socket,
process, `utun` address, and connected `10.86.0.0/24` route are gone. This
leaves the login-owned cluster state, host key, registry, intent and preserved
legacy file untouched.

## Exact two-node EXO lifecycle package

The repository's `exo-runtime/` subtree defines one inert reference bundle for
EXO 0.3.70, official MLX 0.32.0 on Linux/arm64 CPU, and the immutable
`mlx-community/Qwen3-0.6B-4bit` snapshot at
`73e3e38d981303bc594367cd910ea6eb48349da8`. It is not a general EXO installer
or model manager. Repository bytes contain declarations and tests only; the
provider source, Python closure, model, images, credentials, certificates and
generated payload remain external and hash-bound during materialization.

Install is offline and inert: it creates immutable `/opt/reach-exo` program
bytes, the unprivileged `reach-exo` identity, and separate writable
`/var/lib/reach-exo` and `/run/reach-exo` roots, but leaves the systemd units
disabled and stopped. The operator separately owns `/etc/reach-exo` config/TLS
and the read-only `/srv/reach-exo-models` view. Configuration must name exactly
two private IPv4 nodes, their exact interface/MAC pairing, the connector
authority, the selected model, and the
global `0..<14` / `14..<28` ranges. Unknown fields, hostnames in address
positions, duplicate identities, wider networks, changed ranges, wrong file
ownership/modes, or model/hash drift refuse before EXO starts.
For this exact selected closure, the worker owns `0..<14` and the coordinator
owns `14..<28`; readiness authenticates those measured associations.

On explicit enable/start, the worker waits for a mutually authenticated
coordinator. A fresh coordinator handshake owns both provider process groups;
only then does it start EXO, verify an empty exact two-node CPU topology, create
one exact pipeline instance, and wait for both runners. The package's nftables
guard blocks EXO's broad API listener on every non-loopback interface and
seals service-identity egress to loopback, the exact peer, the declared
connector address, and private discovery only.

For Lima VZ's isolated two-guest Ethernet, a mutually bound companion service
holds only `CAP_NET_RAW` and rewrites only the Ethernet destination of this
node's exact EXO IPv6 discovery frames to the configured peer MAC. Each rank's
EXO process retains its API listener only so the opposite authenticated rank
can prove `/node_id` and form the two directed topology edges; nftables admits
that port only from the one configured peer and rejects every other
non-loopback source. The provider
does not inherit that capability, and either service exiting tears down the
other. A root pre-start helper installs the corresponding exact IPv6 link-local
neighbor only after recording root-owned intent outside the service account's
writable runtime directory; post-stop removes only the marker-authenticated
kernel tuple. The two exact rank identities may probe one another's frozen EXO
Zenoh and API ports for topology measurement, while every other non-loopback
API source remains rejected.

The operator runs the bundled Darwin/arm64 connector as the same login account
that owns the development or installed `reachd`. It binds exactly
`127.0.0.1:52415` as unauthenticated plain HTTP and authenticates the private
coordinator gateway with TLS 1.3 client credentials. On VM systems whose
private Ethernet is intentionally unroutable from the host, the connector may
instead use the exact account-owned `127.0.0.1:53422` SSH tunnel endpoint to
the same gateway; mTLS remains mandatory through the tunnel, which must itself
bind only numeric host loopback. Only `GET /v1/models` and
`POST /v1/chat/completions` are published. Direct guest APIs, host nonloopback
addresses, dashboards, `/state`, instance/control routes and independent-peer
paths refuse. Set Reach's EXO endpoint to exactly
`http://127.0.0.1:52415`; no cluster credential belongs in Reach config.

The connector refuses until one fresh epoch has exactly two expected friendly
identities, two `MlxCpu` backends, one selected model instance, exactly two
ready runners, exact 14/14 ranges and no prior generation task. Peer heartbeat
loss, provider death, or any later topology/identity/backend/range/model/runner
drift closes active connector streams and destroys the whole epoch. Recovery
is a new epoch; one-node continuation and stale readiness are never published.
The systemd restart window is bounded to three starts per two minutes.
MLX CPU's generated shared objects use the package-owned
`/var/lib/reach-exo/tmp` directory because Linux mounts `/run` `noexec`; that
directory remains under the unprivileged service identity and is removed with
all service-created state.

`systemctl disable --now reach-exo-node` removes publication and provider work;
disabled state persists across reboot. The bundle remove command deletes its
unit, immutable program, writable state, runtime files and service-created
caches while preserving operator config, TLS and model bytes. Explicit purge
can remove only the package-created `node.json` after its exact root-owned
single-link marker is proved; it still preserves TLS and models. See
`exo-runtime/README.md` for the reproducible build, schemas, commands and exact
claim limits.

## What a restart costs

Identity, grants, the CA and the mesh are on disk and survive. Sessions are
not, and do not need to be: the transcript rides the wire on every request, so
a client whose session the daemon has forgotten opens a fresh one and asks
again without anyone seeing it. The one real casualty is a generation actually
in flight, which ends saying so. Queued work that had emitted nothing may be
resent and executed by the replacement daemon; that is fresh execution, not a
durable queue. `wire.md` has the protocol detail and the five recovery
boundaries.

The first generation after a restart is slower — the weights are paged in on
use rather than at load — and no supervisor shortens that.
