# ReachDurability

Canonical macOS durability modules and the explicit `ReachDurableRuntime` facade
used by `reachd durable-local` and the explicit `reachd durable-transport` command. This package promotes the fifteen accepted Reach
modules, uses the real ReachKit wire codec, and shares the daemon's full vendored
MLX language-model package. Both consumers disable `FoundationModelsIntegration`.
The durability graph is outside ReachHost and the Linux daemon target closure.

The facade selects one artifact-backed, 258-token tiny Llama profile. It loads
actual config, float32 safetensors, tokenizer, vocabulary and template files,
validates their hashes and supported shapes, and uses the normal native model.
The deterministic artifact author and structural branch model live only in
`reachd/Tests/ReachDurableRuntimeTests`; historical Tools workers are not runtime
dependencies. This profile qualifies persistence and native continuation, not
learned model quality, Gemma support or tool execution.

Read [local runtime usage and limits](../docs/durable-local-runtime.md) and the
[normal-executable qualification runner](../Tools/DurableLocalRuntime/README.md).
Old Tools packages remain historical evidence inputs. Vendored native provenance
is recorded in `Vendor/mlx-swift-lm/REACH-VENDOR.json` at the repository root.

The public root-key/provider and lifecycle protocols retain accepted dependency
injection points for testing and embedding. The command facade supplies current
OS ownership, same-boot system clocks, scoped file-Keychain acquisition and the
selected artifact policy itself; request JSON cannot select those authorities.

The [loopback transport](../docs/durable-client-host-transport.md) separates the
host and client owners, pins both mTLS peers, and paces durable batches by exact
nonterminal receipts. Its client uses only a portable descriptor and client-owned
state; model loading and native work remain host-only. See its
[normal-executable runner](../Tools/DurableClientHostTransport/README.md).
