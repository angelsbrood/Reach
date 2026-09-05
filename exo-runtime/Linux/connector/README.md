# Private Linux EXO connector companion 0.1.0

This independent Linux/arm64 package runs the existing Reach EXO connector as
`reach-exo-connector.service`. It binds `127.0.0.1:52415` and authenticates the
coordinator's gateway using the operator's connector certificate. The direct
route lets an installed Linux Reach service use EXO without a Mac connector or
provider tunnel. Loopback HTTP retains the existing local-account trust boundary;
it is not an authenticated multi-tenant API.

The companion reuses the existing configuration, mTLS and gateway packages. It
does not change or replace exact provider bundle B 0.2.0, its Darwin connector,
bootstrap authority, model, or the Reach service. It contains no EXO, Python,
MLX, model or credential payload. Its binary and `.deb` have independent hashes.
This is a private companion, not a public release or a cluster orchestrator.

## Build and focused checks

Use Go 1.26.5 with caches outside the checkout. On a native Linux/arm64 system,
run the new lifecycle tests, including races, and the reused boundary tests:

```sh
export GOTOOLCHAIN=local
export GOCACHE=/absolute/private/build/go-cache
export GOMODCACHE=/absolute/private/build/go-mod
export GOTMPDIR=/absolute/private/build/tmp
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"
go test -count=1 ./internal/config ./internal/gateway ./internal/mtls
go test -race -count=1 ./internal/connectorservice ./cmd/reach-exo-connector-linux
go vet ./...
./scripts/static_test.sh
./scripts/linux-connector-static-test.sh
./scripts/build-linux-connector.sh /absolute/private/connector-build
./scripts/package-linux-connector.sh /absolute/private/connector-build /absolute/private/packages
```

The build script fixes `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=arm64`, trim-path,
build-ID-free flags and the Go version. It also gathers Go and vendored notices.
The package script requires `dpkg-deb` and Python 3, checks ELF64/arm64 identity,
and packages root-owned files, the Reach license, notices and operator examples.
Native tests require a C compiler for Go's race runtime; the shipped binary does
not. Existing Darwin commands remain separate and can still be built normally.
Generated artifacts must remain outside this source subtree.

## Inert installation and identity

Install the private `.deb` explicitly. Installation creates only the dedicated
non-login account and empty `/etc/reach-exo-connector` directory, and reloads
systemd's unit definitions. It does not fetch inputs, configure credentials,
start, enable, preset, or install the optional Reach dependency.

The account is distinct from `reachd` and `reach-exo`. A compatible account
with the exact declared primary group, description, `/nonexistent` home and
`/usr/sbin/nologin` shell may be reused without alteration, including after
removal. A conflicting account, orphaned group, symlinked parent or incompatible
existing parent ownership/mode refuses configuration; existing identities and
operator files are not rewritten.

| Path | Ownership and mode | Purpose |
|---|---|---|
| `/usr/lib/reach-exo-connector/reach-exo-connector` | root, 0755 | static executable |
| `/etc/reach-exo-connector` | root:reach-exo-connector, 0710 | operator-managed traversal boundary |
| `connector.json`, `connector-key.pem` under that parent | reach-exo-connector, 0600 | configuration and private key |
| `ca.pem`, `connector.pem` under that parent | reach-exo-connector, 0644 | public certificates |
| `/run/reach-exo-connector` | reach-exo-connector, 0700 | private runtime directory, removed on stop |

The loader requires canonical distinct absolute TLS paths and regular,
singly linked, non-symlink files with these exact modes and UID ownership.
Do not add `reachd` to the connector group. Reach needs the loopback HTTP
endpoint, not the connector's configuration or credentials. The unit exposes
operator files read-only, has no capabilities, and confines writable state to
its runtime directory.

## Project a verified S54 connector role

Use the unchanged S54 creator and independent verifier on its supported
Darwin/arm64 operator host. The inventory must use `gateway_mode: direct-gateway`
and the actual three distinct private node/connector addresses. Retain the
complete externally held authority commitment and verify it before deployment:

```sh
reach-exo-bootstrap verify --authority-root /absolute/authority \
  --expected-authority-sha256 EXTERNALLY_HELD_SHA256
```

Keep that original authority tree unchanged. Transfer only its verified
`connector/connector.json` and the connector role's `tls/ca.pem`,
`tls/connector.pem`, and `tls/connector-key.pem` into an owner-only staging
directory on the service host. Check transferred bytes against the verified
manifest. Never copy the CA private key or either provider's private key.

S54's JSON binds its original absolute TLS paths. The deployed JSON therefore
projects only those three paths into `/etc/reach-exo-connector`. Schema version,
loopback listen address, direct gateway address, server name and all other fields
must match the verified original. S54 attests its original B/topology/TLS
material; it does not attest this new Linux executable or this projected file.
Record the companion binary/package hash and projection separately.

For a fresh deployment, after verifying the staged role, the following root-run
Python recipe installs exact role bytes without overwriting an existing file.
Set the staging directory and gateway to the actual verified inventory:

```python
import copy, json, os, pwd
from pathlib import Path

stage = Path('/absolute/private/staged-connector-role')
original = json.loads((stage / 'connector.json').read_text())
assert original['schema_version'] == 1
assert original['listen_address'] == '127.0.0.1:52415'
assert original['gateway_address'] == '192.168.118.3:53421'  # verified inventory
assert original['server_name'] == 'reach-exo-gateway'
parent = Path('/etc/reach-exo-connector')
account = pwd.getpwnam('reach-exo-connector')
assert not parent.is_symlink()
assert (parent.stat().st_uid, parent.stat().st_gid,
        parent.stat().st_mode & 0o777) == (0, account.pw_gid, 0o710)
projected = copy.deepcopy(original)
files = [('ca', 'ca.pem', 0o644), ('certificate', 'connector.pem', 0o644),
         ('private_key', 'connector-key.pem', 0o600)]
for field, name, mode in files:
    projected['tls'][field] = str(parent / name)
assert {k: v for k, v in projected.items() if k != 'tls'} == {
    k: v for k, v in original.items() if k != 'tls'}
for field, name, mode in files:
    target = parent / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write((stage / 'tls' / name).read_bytes())
        os.fchown(out.fileno(), account.pw_uid, account.pw_gid)
        os.fchmod(out.fileno(), mode)
fd = os.open(parent / 'connector.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as out:
    json.dump(projected, out, indent=2)
    out.write('\n')
    os.fchown(out.fileno(), account.pw_uid, account.pw_gid)
    os.fchmod(out.fileno(), 0o600)
```

Verify deployed role hashes/fingerprints and the projected fields, UID/modes and
Reach's inability to read the key/config. Explicitly start the connector only
after configuration is complete. Do not retain private keys in diagnostic logs
or evidence packets. Remove staging credentials after verified deployment.

## Readiness, shutdown and opt-in ordering

The main process validates configuration and credentials, binds loopback, enters
the HTTP serving loop, and then sends `READY=1` to systemd's UNIX datagram socket.
Both pathname and Linux abstract socket forms are supported. This reports local
connector availability, not gateway, rank or model readiness. Reach still needs
a successful provider catalog preflight within its unchanged startup budget.
This follows systemd's [service](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml)
and [notification](https://raw.githubusercontent.com/systemd/systemd/main/man/sd_notify.xml) contracts.

Configuration, permission, TLS, bind and notification failures exit 64 without
an automatic restart. Diagnostics log the failure category, not configuration
values or credentials. Unexpected runtime failure uses `RestartSec=2s` and at
most three starts per 60 seconds. The unit uses a ten-second start limit,
five-second stop limit, 256 MiB memory limit, 128 tasks and 1024 descriptors.
SIGINT/SIGTERM starts the existing three-second graceful HTTP shutdown; on
expiry connections close and the process exits with failure. No provider is
started, stopped, retried or reconfigured by the connector.

For deliberate foreground operation without systemd, use
`reach-exo-connector --foreground /absolute/path/connector.json` with
`NOTIFY_SOCKET` unset. This mode sends no readiness notification. An absent
socket in ordinary service mode is a startup failure, not implicit foreground
success.

The package ships `reachd-ordering.conf` only as an example. To opt in, install
it yourself as `/etc/systemd/system/reachd.service.d/exo-connector.conf`, then
run `systemctl daemon-reload`. Its `Wants`/`After` dependency orders local
connector readiness before Reach. Keep A/B already whole-ready when starting
or rebooting R; this ordering does not make simultaneous cluster cold boot fit
Reach's ten-second startup deadline. Reach's other lifecycle limits are unchanged.

Disabling the connector alone does not prevent a retained Reach `Wants`
dependency from starting it. To keep both stopped across reboot, disable both
units and explicitly remove the operator-owned dependency drop-in, then reload
systemd. The package never installs or silently removes that drop-in.

## Removal

Normal removal stops/disables only the connector service and removes its owned
executable, unit, examples, notices and runtime directory. Removal and purge
preserve `/etc/reach-exo-connector`, operator credentials, a sentinel, any
operator-installed Reach drop-in, and the static account needed by those files.
They do not modify Reach or the provider package. Explicit operator teardown
owns later deletion of credentials and the account; do not delete the account
while retained files still rely on its UID. Companion update/rollback,
physical-host operation and public distribution are separate work.
