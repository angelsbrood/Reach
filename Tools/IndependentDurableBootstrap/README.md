# Independent bootstrap qualification

Run one owned serial macOS campaign with a normal `reachd` build, its matching
`default.metallib`, and the qualified artifact/request/public-model fixtures.
The normal focused `LocalRuntimeTests.testGenerateAndLoadActualArtifacts` test
authors the fixtures under `S93_TEST_ROOT=/private/tmp/reach-s95.<id>/fixtures`.
No model or dependency download is performed.

```sh
python3 Tools/IndependentDurableBootstrap/run.py \
  --scratch /private/tmp/reach-s95.<id> --label reference-1 \
  --executable /owned/build/reachd --metallib /owned/build/default.metallib \
  --model /private/tmp/reach-s95.<id>/fixtures/model \
  --public-model /private/tmp/reach-s95.<id>/fixtures/public-model.json \
  --requests /private/tmp/reach-s95.<id>/fixtures/requests \
  --mode reference ordinary guided required allowed combined
```

Repeat with a fresh label, `--mode crash`, and `--reference` pointing to the
reference qualification directory. Each host is stopped and killed at a native
boundary, then independently reopened while both original initializers and the
client survive. The runner compares exact inbox/request binding, positive saved
native offsets, zero original preparation/issue/begin and fresh terminal replay.
It verifies the retained local deadline and both role clock policies.

The additional modes `client-restart`, `lost-receipt` and `retention-exhaustion`
take only `ordinary` and the same reference argument. A lost-receipt cut must
prove persisted high is above acknowledged high; a raced cut remains a failure.
Retention exhaustion selects a three-second local cap and verifies bounded
refusal without replacement work. `peers.py` takes the same reference-mode
arguments plus `--test-bundle /owned/build/ReachDurableRuntimeTests.xctest` and
checks selection/role/TLS/confirmation/profile refusal, pre-registration ambiguity,
persistent reservation, one outstanding batch, and host-local cancel.

Every run uses separate roots/containers and original role creators, removes
provisioning before live work, denies direct peer-root reads/writes, and retires
in reverse initialization order after known workers join. Logs, failures,
executable hashes, clock selections, reports and sampled allocation remain in
the qualification directory. Creator cleanup failure is an explicit stop with
the original creator left alive; it is never silently replaced.

One native generation at a time; no more than two initializers, one host, one
client and one negative controller worker. Use at most four build jobs. The
runner checks <=32 GiB owned scratch, >=20 GiB free space, <=192 MiB per log;
the final inventory additionally bounds fixtures <=3 GiB and retained evidence
<=1 GiB. Remove owned binaries/models/build scratch after binding the results.
Filesystem denial and cooperative selector observations do not claim securityd
IPC confinement, exhaustive opaque descendants, RSS or physical erasure.
