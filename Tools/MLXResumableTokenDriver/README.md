# MLX resumable token driver candidate

S72 is a **local native dependency candidate**, not an adopted upstream API or
Reach runtime durability. The patch adds an opt-in paused raw-token driver to
`mlx-swift-lm`; Reach's production source, dependency pins and shared checkouts
are unchanged. No ordinary, guided, tool or EXO route becomes durable here.

## Supported boundary

The model owner supplies an explicit compatibility identity, exact cache layout
and typed state codecs. The owner attests that all mutable forward state lives
in those caches and `LMOutput.State`: no hidden RNG, mutable weights, independent
background work or effects. A weights hash alone cannot establish that contract.
The driver is serially confined; callers must not retain/mutate its caches through
the model. It is deliberately not `Sendable`.

- Batch-one text tokens, with no mask or media preprocessing. Preparation directly
  calls the declared text forward interface in bounded chunks and carries typed
  state across every chunk. It does not call generic `model.prepare` or `generate`.
- Exact `KVCacheSimple` (default allocation step 256) and `RotatingKVCache`, with
  declared heads, dimensions, float dtype, rotation size/keep/allocation step.
  Subclasses, other cache families and dynamic/quantized conversion are refused.
- Greedy sampling and a versioned owned explicit-key sampler. Public MLX key
  splitting and categorical sampling retain the current key/position. Restore
  neither seeds global RNG nor changes `RandomState` internals. Temperature and
  top-p → min-p → top-k semantics match the pinned sampler on supported options.
- Existing repetition → presence → frequency penalty composition, including each
  complete ring buffer, count and write position. Arbitrary samplers/processors,
  speculative/MTP execution and batched/multimodal routes are outside the subset.
- Nil/empty typed state is preserved. Every present key must have an exact typed,
  versioned codec; duplicate/conflicting registrations and unknown keys refuse.
  Codecs are pure, deterministic value encoders/decoders. Payloads may contain
  bounded metadata and frozen tensors, never live references or external effects.

`prepare` settles C0 with the first sampled-but-not-returned token. `advance`
returns one token with its matching settled checkpoint, computing the following
pending token only when needed. The final token exhausts the driver without an
extra model/sampler call. `maximumTokens == 0` does no model work. `close` discards
unused lazy values; all submitted evaluation is synchronous, and further advance
or capture refuses. The legacy `TokenIterator` keeps its default pipeline.

`capture()` produces independent contiguous tensor bytes plus versioned metadata.
Checkpoint schema 2 records each cache's physical allocation length separately
from its logical tensor slices. Restore pads the logical values into that same
bounded capacity (zeroing unused spare storage), then restores the logical offset.
This preserves the pinned allocator's next-growth behavior. The live per-key/value
tensor cap remains 8 MiB, independently of the 8 MiB encoded checkpoint cap; spare
capacity is not serialized as content. Schema 1 snapshots refuse as incompatible.
`restore(checkpoint:model:identity:options:cacheSpecs:codecs:)` creates fresh owned
state, with no prefill, reseed or sample. It checks bindings, shapes, dtypes,
lengths, cache metadata, RNG accounting and history cursors before unchecked
legacy setters. Failure does not mutate an existing driver/model/cache or fall
back to generation. Unexpected unsupported output/state during execution returns
no usable token/checkpoint pair and closes the affected driver.

The JSON envelope contains a payload and SHA-256 checksum. **It is not encrypted,
authenticated against an attacker, or a durable host commit transaction.** The
8 MiB encoded limit applies before accepting serialized input or writing a
checkpoint. Compatible local backend/revision/native byte order is required;
there is no cross-hardware bitwise, power-loss or large-model performance claim.

## Reproduce offline

Run on the selected arm64 macOS 27 host with
`/Applications/Xcode-beta.app/Contents/Developer`, Swift
`swiftlang-6.4.0.33.1`, and Python 3.14.7. Host GPU access is required; the Codex
filesystem sandbox cannot enumerate Metal devices on this host.

```sh
python3 -B /Users/nellymoon/Documents/Swift/Reach/Tools/MLXResumableTokenDriver/run.py \
  --reach /Users/nellymoon/Documents/Swift/Reach
```

`Package.swift` is a private harness template, instantiated by `run.py`. Do not
run SwiftPM directly in this tool directory. The runner exports local tracked
sources and their pinned submodules, routes the unchanged Llama and default LLM
protocol files into a tiny target, applies the patch only in private scratch,
and wires local transitive dependencies. It downloads or upgrades nothing.

Exact local pins:

| Package | Revision |
| --- | --- |
| mlx-swift-lm | `83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8` |
| mlx-swift | `0bb916c67f4b9e5c682cbe02a42c701c93ab5021` |
| swift-numerics | `0c0290ff6b24942dadb83a929ffaaa1481df04a2` |
| swift-argument-parser | `6a52f3251125d74daf04fcbd5e6f08a75d074382` |

The existing compatible Metal library is copied from
`reachd/.build/out/Products/Debug/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib`,
SHA-256 `684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5`.
Its actual tiny-array GPU evaluation must pass before candidate testing. The
runner uses SwiftPM's currently supported `native` build mode; its deprecation
warning is retained in logs. No shared shader/build output is modified.

## Focused evidence

The selected tests cover C0, post-token, history/cache wrap and exhaustion;
checkpoint immutability; nonempty typed state; exact RNG/penalty continuation;
malformed/incompatible/unknown state; non-mutation on failed restore; cancellation;
and legacy sampling/penalty/cache/typed-state regressions. The full selection now contains 38 XCTest methods and five existing Swift Testing
functions, with no download tests. The pre-RC1 run passed the original 41 tests and
32 worker pairs. RC1 reuses those unchanged results and runs seven allocation/restore
checks: two new boundary regressions, the checkpoint refusal tests, all existing
in-process continuation boundaries and unsupported-logit refusal.

For that focused correction run:

```sh
python3 -B /Users/nellymoon/Documents/Swift/Reach/Tools/MLXResumableTokenDriver/run.py \
  --reach /Users/nellymoon/Documents/Swift/Reach --cache-allocation-only
```

This mode compiles the revised candidate and uses the prior compatible native
lane and matrix evidence instead of repeating them. It records exactly seven
newly executed XCTest methods and zero newly executed fixture workers. The two
regressions use Float32, 32 heads, dimension 256, allocation step 256, one prompt
token and two output tokens, for Simple and Rotating(maxSize: 257). They verify
that source and restored cache storage both remain 256 slots / 8,388,608 bytes
per tensor, with matching suffix and checkpoint state. The original implementation
reproduced a restored-only refusal after growing to 257 slots.

The fresh-process matrix has 32 producer/restore pairs: tiny fixed-weight Llama
and a state-bearing analytic MLX model, simple/rotating cache, greedy/stochastic,
and cuts 0/1/7/12. Every producer exits before its fresh restore process starts.
Workers compare exact tokens, RNG/integer metadata, weights identity and counts;
floating logits/cache/state use `atol=1e-6`, `rtol=1e-5` on the same backend and
step schedule. Llama weights are filled deterministically by named parameter and
index, fully realized, and hashed in each worker. No pretrained weights or real
prompt are used. Restore and exhaustion counters must show no extra model work.

Each run prints its private `/private/tmp/reach-mlx-resume.*` evidence directory.
It retains ordinary logs, commands/timings, source/artifact hashes, test counts,
worker results and resource observations, then removes its source/build/fixture
copies, including on ordinary failure. The runner joins each owned process and
signals its owned process group on timeout; it does not claim an exhaustive
history of opaque tool descendants.

Ceilings are 16 GiB scratch, 64 MiB synthetic fixtures, 8 MiB/checkpoint,
128 MiB tiny model/state tensors, at least 20 GiB free, build jobs ≤4,
one build/test command and one fixture worker at a time. These are test limits,
not proposed production capacity or benchmark thresholds.

The patch does not include detokenizers, output queues, guided matchers/parsers,
allowed/required tool coordination, EXO ownership, encrypted host storage or
client/wire/effect integration. Upstream adoption and Reach integration remain
separate work. This advances S71's named raw-token dependency without narrowing
its eventual all-route requirement.
