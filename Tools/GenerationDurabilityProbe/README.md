# Generation durability reference probe

**Synthetic model only.** This standard-library Python probe exercises decisions
in the [proposed durability contract](../../docs/generation-durability-design.md).
It is not a Reach runtime component, a provider checkpoint implementation,
encryption or evidence that an in-flight model generation survives a crash.

The fake provider emits small integer events and saves a next-integer cursor.
One atomic local image joins the fake checkpoint, replay and owner counter.
A private process-lifetime `flock` excludes a second controller; stale owner
numbers refuse writes. A separate fake client effect journal and counter show
why receipt is different from a known tool outcome. SHA-256 detects damaged
model images, not malicious modification. No keys, prompts, models, network,
Swift/Metal builds, services, identities or real tools are used.

## Run

Python 3 standard library is sufficient; S71 used Python 3.14.7. Use `-B` to
prevent bytecode writes. Run from this tool directory with a new private scratch
outside the checkout:

```sh
scratch=$(mktemp -d /private/tmp/reach-durability.XXXXXX)
mkdir -m 700 "$scratch/tests" "$scratch/demo"
REACH_DURABILITY_SCRATCH="$scratch/tests" PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -m unittest -v test_probe
python3 -B probe.py demo --root "$scratch/demo"
```

The caller owns this exact scratch directory and may remove it after reviewing
the synthetic files: `rm -rf -- "$scratch"`. Do not substitute a shared directory
or reuse one containing other work. The demo requires an empty current-owner
0700 canonical directory under `/private/tmp`; files are 0600. Tests remove
their individual state directories even on ordinary failures.

The demo closes/reopens controllers, loses a receipt, deduplicates replay and
replays a terminal without a new provider start. The tests use **fresh owned
subprocesses** for selected death/reload cases. Their deliberate `os._exit(86)`
exits only the probe child; a child is always awaited, with a five-second timeout
that kills and joins it. There is one test controller and at most one child at
a time (below the S71 ceiling of two). There are no background jobs.

## Covered boundaries

- Incomplete candidate, committed-before-publish and published-before-death,
  each with zero or one previously visible event. Only committed events replay;
  a discarded unpublished step resumes at the previous checkpoint.
- Lost receipt, unchanged duplicate suppression and terminal replay without
  provider execution; changed event bytes and gaps refuse.
- Duplicate begin/recovery, an exclusive owner lock and stale owner token;
  one active and three queued records, no durable FIFO claim; an unknown external
  owner cannot advance or release its occupied capacity.
- Receipt without a fake tool effect, effect performed with unknown outcome,
  and known outcome replay without incrementing the counter again.
- Request/revision/session mismatch, expired/cancelled records, corrupt,
  incompatible, incomplete and over-limit images; content removal and tombstones.

`advance`, `recover` and `effect` are test-driver commands. `--fault` selects a
synthetic child exit before commit, after commit, after publication or after the
fake effect. They are not service administration or live-crash tools.

Records are capped at 1 MiB; the model caps eight generation records and 256
synthetic events per generation. Tests create one private case directory at a
time. Keep total synthetic fixtures below 64 MiB, task scratch below 256 MiB
and host free space above 20 GiB. This tiny fixture budget is separate from the
future runtime storage-policy proposal. No cache benchmark or exhaustive
scheduling proof is implied.

The model keeps all bounded synthetic replay and a surviving client's cursor;
it does not implement real wire negotiation, durable app handoff, checkpoint
codecs, real remote fencing, encryption/key availability, production pruning or
the eventual provider-disabled flag. A caller-supplied `provider_settled` value
only drives the synthetic decision, not actual settlement evidence. Unknown
effects always require explicit safe resolution; no exactly-once external-effect
promise follows from the local counter. Real provider and all-route integration
remain the dependencies listed in the design.
