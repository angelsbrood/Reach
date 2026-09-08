# Durable client/host transport qualification

This controller runs separate **normal `reachd` executables** through the explicit
`durable-transport` command. It uses owned loopback only, retains direct-child
joins and reports, and lets each foreground initializer retire its own Keychain
and root. It never kills the initializer as a crash subject. No model download,
shared checkout mutation, default Keychain import or production service is needed.

First build the normal `reachd` graph and its tests with the existing pinned
local dependencies, in an owned scratch directory and with at most four jobs.
Do not substitute a private worker graph. The verified cached Metal library must
be colocated with the normal executable and with the XCTest binary when running
native tests. Keep the build/test commands and resource hash with the results.

The existing `LocalRuntimeTests.testGenerateAndLoadActualArtifacts` authors the
small deterministic **test** weights and request files. Set `S93_TEST_ROOT` to
`/private/tmp/reach-s94.<suffix>/fixtures`, with that directory already `0700`.
The runtime itself accepts selected artifacts; it does not manufacture test
weights or take a scripted native outcome.

Example, using an already built and verified normal graph:

```sh
python3 Tools/DurableClientHostTransport/run.py \
  --scratch /private/tmp/reach-s94.example --label reference \
  --mode reference \
  --executable /private/tmp/reach-s94.example/build/arm64-apple-macosx/debug/reachd \
  --metallib /private/tmp/reach-s94.example/build/arm64-apple-macosx/debug/mlx.metallib \
  --model /private/tmp/reach-s94.example/fixtures/model \
  --requests /private/tmp/reach-s94.example/fixtures/requests \
  ordinary guided required allowed combined
```

Repeat with `--mode crash --label crash --reference
/private/tmp/reach-s94.example/qualification-reference` and the same inputs.
The controller waits for durable client registration and a committed nonterminal
checkpoint, kills and joins only the host, restarts that host on the same port,
and leaves the initializer and client alive. It checks exact inbox bytes and
prepared request binding against the reference. Required and combined cuts name
the hidden checkpoint and require `high == 0`. Every route also gets fresh host
and client terminal replay with zero generation. Ordinary new later tool-pass
preparation is distinct from rerunning original request preparation.

The runner records actual loopback socket observation through `lsof`, pinned
peer digests, process IDs and joins, executable/resource hashes, and sampled
allocation/free disk. Its output directory must be fresh. A raced or failed cut
is a failed attempt to retain and correct, not a different passing scenario.
The runner's PASS covers only its selected routes; it is not terminal Architecture
acceptance of the whole feature.

Additional focused normal-graph tests live in `ReachDurableRuntimeTests`:

- `TransportContractTests`: role acquisition guards, reservation reopen and
  replacement refusal, request-binding digest, quotas and unchanged offers.
- `TransportNetworkTests`: real pinned TLS, same-CA wrong leaf, no certificate,
  unrelated CA, fragmented/overlimit/truncated reads, cancellation and contention.
  For the unrelated-CA case, retain **only public CA DER** from a prior disposable
  S94 initializer in `<scratch>/evidence/disposable-public-ca.json` as
  `{"caDER":"base64 DER"}`. Do not copy signing keys or use existing credentials.
- `TransportPeerTests`: controlled raw peer against an explicitly initialized
  normal host. Set `S94_PEER_ROOT` to its owned qualification root. Run the old
  dialect/pre-Hello and terminal-receipt tests before the one-shot withholding
  test. The latter intentionally leaves a host reservation without a client
  journal selection; inspect refusal/restart/cancel behavior and then retire it.
- ReachKit's readiness cancellation and bounded frame tests, plus the affected
  wire compatibility/codec tests, exercise the shared transport seam.

Keep process-level client-death, lost nonterminal receipt/reply, sixty-second
reconnect exhaustion and returned preparation-failure observations with the
handback. Do not infer these from the reference/crash runner. Client-only recovery
must use its encrypted selection with no cached request/ticket arguments. The
client must persist before receipt; do not equate transport reads with receipt
allowance. Terminal receipts remain excluded.

Resource ceilings are 32 GiB aggregate scratch/build, 3 GiB fixture/journal/key
material, at least 20 GiB sampled free space, 192 MiB per log, 1 GiB retained
campaign evidence and 128 MiB selected native allocator peak. Run one campaign at
a time with one initializer, host and client, plus at most one controlled negative
peer. Stop/join workers before initializer cleanup. If cleanup blocks, retain its
exact capability and report the blocker. After qualification, remove owned build,
executable, model and credential material while retaining bounded logs, reports
and hashes. These are application/ownership observations, not aggregate RSS,
physical-erasure or exhaustive opaque descendant claims.
