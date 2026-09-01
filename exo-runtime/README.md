# Reach EXO lifecycle package 0.2.0

This subtree is the inert source and package declaration for one exact
Linux/arm64 lifecycle bundle and its one admitted offline update edge. It is
intentionally not a general EXO installer or updater.
It admits only EXO 0.3.70 at commit
`21a54c5ea0230a3bec1e1a786d200126c7e34ec6`, the accepted official-MLX
derivative, and the immutable `mlx-community/Qwen3-0.6B-4bit` snapshot named in
`internal/authority`.

The repository contains no EXO checkout, Python environment, wheel, model,
guest image, credential, certificate, private key, or generated package. Those
inputs remain external and must pass the exact hashes enforced by
`scripts/materialize.sh`.

## Runtime boundary

Each compute node installs the same bundle and runs `reach-exo-node` as the
dedicated `reach-exo` account. The worker starts no provider until a mutually
authenticated coordinator supplies a fresh epoch. The coordinator starts its
provider only after that acknowledgement, verifies an empty two-node EXO
baseline, creates the single exact 14/14 pipeline instance, and publishes the
gateway only after both runners are ready. The accepted closure's deterministic
cycle gives the worker `0..<14` and coordinator `14..<28`; both associations are
declared and checked rather than inferred from role names.

The coordinator-to-worker control socket and coordinator gateway use TLS 1.3,
a private CA, required client certificates, and fixed peer names. The EXO API
is blocked on every non-loopback interface except the exact opposite rank as
the sole admitted source for that API socket; the package uses this exact path
to authenticate `/node_id` and the directed topology edge. The same
guard permits the service identity to reach only loopback, the exact peer, the
declared connector address, and local discovery traffic; external DNS and
egress are refused. A separately sandboxed companion holds only `CAP_NET_RAW`
and forwards only this node's exact EXO IPv6 discovery frames to the configured
peer Ethernet address. A root pre-start helper records and installs only that
same peer MAC's derived IPv6 link-local neighbor, and a root post-stop helper
removes it only while its single-link ownership marker and kernel tuple remain
exact. Either service stopping or failing stops the other; the provider never
inherits that capability. The gateway and host connector publish only:

- `GET /v1/models`
- `POST /v1/chat/completions`

All dashboard, state, instance, event, control, and path-confusion forms return
`404`. The host connector binds only `127.0.0.1:52415`. Its authenticated
upstream is either the coordinator's private numeric address on port `53421`,
or the fixed account-owned `127.0.0.1:53422` endpoint when the VM boundary
requires an SSH loopback tunnel to that same gateway. The tunnel carries mTLS
unchanged and is never a public Reach-facing listener. That final HTTP leg is
deliberately unauthenticated and belongs to the local login account; no
credential enters Reach. Its upstream leg authenticates the coordinator.

Worker heartbeat loss, provider exit, topology/identity/backend/range/model
drift, or runner drift closes active gateway connections first and tears down
the entire provider epoch. Recovery cannot reuse the old epoch or readiness.
The systemd service has a bounded three-start window and starts only after an
operator supplies strict configuration and explicitly enables it.

## Declared roots and disposition

| Root | Owner | Mode/use | Ordinary removal |
|---|---|---|---|
| `/opt/reach-exo` | root | immutable program and closure | removed |
| `/etc/reach-exo` | operator/root + service group | node config and TLS | preserved |
| `/srv/reach-exo-models` | operator | read-only model view | preserved |
| `/var/lib/reach-exo` | `reach-exo` | writable service state, private logs, removable MLX CPU JIT temp | removed |
| `/run/reach-exo` | `reach-exo` | ephemeral status and sockets | removed |
| `/run/reach-exo-peer-neighbor.json` | root | exact ephemeral neighbor ownership | removed on stop |

The explicit purge command removes only `node.json` and the exact
root-owned, single-link `0600` marker created by `configure-node.sh`. It never
removes operator TLS or model bytes.

## Build and verification

Run unit/static tests with external caches:

```sh
GOCACHE=/private/tmp/reach-exo-gocache \
GOMODCACHE=/private/tmp/reach-exo-gomodcache \
go test -count=1 ./...
```

`scripts/build-binaries.sh` performs two independent, trim-path, build-ID-free
builds and byte-compares the Linux node, Linux package-transaction command and
Darwin/arm64 host connector.
`scripts/materialize.sh` must run on Linux/arm64 with uv 0.8.22 and Python
3.13.7. A connected run populates an external uv cache; an offline run reuses
only that authenticated cache. Both outputs must have identical
`PAYLOAD-MANIFEST.tsv`, package metadata, configuration schemas, and license
inventory. Runtime caches, status and private provider logs are outside the
payload manifest and are removed by `remove.sh`.

Installation verifies the complete bundle manifest, creates the service
identity and declared writable roots, copies immutable payloads, and proves the
unit is disabled and stopped. It performs no network operation and never
starts or enables the service.

## Exact offline update and rollback

Bundle B `0.2.0` admits only exact parent A `0.1.0`, whose package, payload,
metadata, node and connector digests are compiled into B and repeated in B's
immutable package metadata. The operator must retain authenticated, extracted
A and B bundle roots and their original package archives. No transaction
downloads, resolves or selects an artifact.

Run the B wrapper with absolute paths and the independently authenticated B
archive, payload-manifest and metadata digests from the frozen materialization
output. The A digests are fixed to the only admitted parent; its archive digest
may be given explicitly:

```sh
sudo /absolute/B/scripts/update.sh \
  --candidate-root /absolute/B \
  --candidate-archive /absolute/reach-exo-lifecycle-0.2.0-linux-arm64.tar.gz \
  --candidate-sha256 B_ARCHIVE_SHA256 \
  --candidate-payload-sha256 B_PAYLOAD_MANIFEST_SHA256 \
  --candidate-metadata-sha256 B_METADATA_SHA256 \
  --parent-root /absolute/A \
  --parent-archive /absolute/reach-exo-lifecycle-0.1.0-linux-arm64.tar.gz \
  --parent-sha256 fe3a5e334ea89f30487bba02bfbd749ad9a8c51736cda35699aedc7b1eb5e138
```

The command authenticates both artifacts and every installed A payload object
before mutation. It holds the root package lock, records previous enabled and
active intent in a bounded fsynced journal, installs a persistent systemd
start guard, stops publication/provider work, and replaces the complete
program and unit generation with fresh inodes. `/etc/reach-exo`, operator TLS,
`/srv/reach-exo-models` and the `reach-exo` UID/GID are never payload inputs.

After an interruption, run `recover.sh` with the same arguments. Recovery
accepts only the exact journal-bound artifact paths and digests and converges
to complete B; a corrupt/missing journal or artifact mismatch stays guarded
and down. Do not copy files manually. Once both nodes report the same exact B
generation, provider creation and gateway publication may resume. Missing,
unknown, A/B, B/A or unequal generation identities refuse before B provider
creation/publication.

Explicit rollback uses the same retained artifacts:

```sh
sudo /absolute/B/scripts/rollback.sh \
  --candidate-root /absolute/B \
  --candidate-archive /absolute/reach-exo-lifecycle-0.2.0-linux-arm64.tar.gz \
  --candidate-sha256 B_ARCHIVE_SHA256 \
  --candidate-payload-sha256 B_PAYLOAD_MANIFEST_SHA256 \
  --candidate-metadata-sha256 B_METADATA_SHA256 \
  --parent-root /absolute/A \
  --parent-archive /absolute/reach-exo-lifecycle-0.1.0-linux-arm64.tar.gz
```

Rollback accepts only B's exact parent A, restores exact A software bytes and
account receipt, removes B receipts, and preserves prior service intent and
operator state. `remove.sh`, `configure-node.sh` and
`purge-created-config.sh` share the same lock and refuse an incomplete
transaction.

## Limits

This reference package covers exactly two isolated Linux/arm64 CPU nodes, one
Qwen snapshot, one 28-layer 14/14 pipeline, and the existing Reach adapter. It
owns only the exact manual A `0.1.0` to B `0.2.0` update and exact-parent
rollback described above. It does not own model acquisition, certificate
issuance, persistent topology, a feed or general version selection, physical
host deployment, performance, Keeper, public relay, Linux reachd, or any other
provider/model closure.
