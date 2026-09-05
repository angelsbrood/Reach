# Linux Reach identity bootstrap

`reach-identity-bootstrap` creates one fresh, private Reach authority with one
server and one manually provisioned client. It runs offline as an unprivileged
Linux/arm64 operator. It neither installs nor starts a service. Existing Mac
issuance and enrollment behavior are unchanged. This is a private provisioning
tool, not a public release or an ongoing client issuer.

## Build and checks

Use Go **1.26.5**, Python 3 and a POSIX shell. This is a separate Go module with
only standard-library imports. Supply absolute, outside-checkout locations for
all output, caches and temporary files; do not reuse a checkout through a symlink.
For example, after creating `/var/tmp/reach-build` as your own 0700 directory:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off
export GOCACHE=/var/tmp/reach-build/go-cache
export GOMODCACHE=/var/tmp/reach-build/go-mod-cache
export TMPDIR=/var/tmp/reach-build/tmp
mkdir -m 700 -p "$GOCACHE" "$GOMODCACHE" "$TMPDIR"
make static test vet
make OUTPUT=/var/tmp/reach-build/artifact build
```

The script requires the exact toolchain and the explicit `linux` target. It
produces a CGO-disabled Linux/arm64 executable with trimmed paths, no VCS stamp
and no build ID, plus project and Go notices, `BUILD.json` input hashes and
`BINARY.sha256`. There is no Darwin executable, installer or Debian package.
Native Linux checks include the actual CLI; host unit checks do not prove the
Linux filesystem or Apple consumer contract.

## Create and independently verify

Create a canonical absolute owner-private directory, for example
`/var/tmp/reach-operator`, and save this UTF-8 JSON as `request.json` with mode
0600 inside it. Replace the names, UUID and endpoints deliberately:

```json
{
  "schemaVersion": 1,
  "clusterName": "Private Reach Cluster",
  "clientName": "Operator Mac",
  "clientID": "00000000-0000-4000-8000-000000000001",
  "listen": { "address": "127.0.0.1", "port": 4433 },
  "advertisedRoads": [ { "address": "127.0.0.1", "port": 4433 } ],
  "modelID": "operator-selected-model",
  "exoEndpoint": "http://127.0.0.1:52415"
}
```

Names are 1–128 printable ASCII bytes and the model identifier is 1–256,
without leading/trailing whitespace. The UUID uses the hyphenated hexadecimal
form; its client URI uses lowercase. All endpoint ports are 1024–65535. Listener
and 1–16 distinct advertised roads use canonical numeric IPv4, excluding
multicast and `255.255.255.255`; only the listener may use `0.0.0.0`. The EXO
endpoint is exactly `http://127.0.0.1:<port>`, matching the service's IPv4 host;
other `127/8` addresses refuse. No path, query, fragment or credentials are
allowed. These are tool-input limits, not a service schema
change or an assertion that the endpoints/model are reachable.

Requests are at most 16,384 bytes. Unknown, duplicate, missing, null, incorrectly
cased or malformed fields and trailing data refuse. An optional
`"validitySeconds": { "ca": 86400, "server": 3600, "client": 3600 }` may shorten
the defaults: CA 730 days, server 30 days, client 365 days. Each duration must be
positive, at most its default and within the CA duration. Certificates share
an issuance instant and a one-hour not-before tolerance.

```sh
/absolute/reach-identity-bootstrap create \
  --config /var/tmp/reach-operator/request.json \
  --output /var/tmp/reach-operator/new-cluster
```

Retain the printed `ca_der_sha256` outside the new bundle. In a new process,
verify using that retained lowercase 64-character CA DER digest:

```sh
/absolute/reach-identity-bootstrap verify \
  --config /var/tmp/reach-operator/request.json \
  --bundle /var/tmp/reach-operator/new-cluster \
  --expected-ca-sha256 EXTERNALLY_RETAINED_CA_DER_SHA256
```

Create success reports `created`; only independent verify success reports
`valid`. Verification is read-only. It checks the exact files, private modes,
ownership, links, request projection, expected CA, self-signature, validity,
leaf chain and explicit role EKU, and all certificate/private-key relationships.
The retained digest identifies the CA, not every byte of an authority record.
Verifier PEM inputs must retain the canonical encoding emitted by the tool.

## Roles and deployment

| Role | Fixed files | Destination |
| --- | --- | --- |
| `operator` | `ca.pem`, `ca-key.pem` | Creating Linux operator only |
| `server` | `ca.pem`, `server-chain.pem`, `server-key.pem`, `reachd.json` | Linux Reach service |
| `client` | `client.reachidentity` | That client only |

All generated directories are 0700 and files 0600. Request, bundle and parent
paths must be canonical, absolute and outside Git checkouts; inputs must be
current-owner regular, singly linked files. Existing output always refuses.
Creation uses exclusive writes and checked flushes. On failure or interruption,
any private incomplete tree remains; verify refuses it and create never
overwrites it. An operator may inspect and explicitly discard the exact owned
incomplete tree. There is no automatic recovery, renewal or power-loss guarantee.
Filesystem acceptance covers the selected guest-local filesystem, not shared
mounts or adversarial same-UID/root races.

The CA uses P-256/ECDSA-SHA256, critical CA constraints with path length zero,
and keyCertSign only. Distinct server/client keys use critical digitalSignature
and respectively serverAuth-only/clientAuth-only EKUs. The server includes DNS
`localhost` and the deduplicated listener/road IPv4 SANs excluding the wildcard.
The client URI is `reach://device/<lowercase UUID>`. All keys retain Reach's
full-width scalar guard for the existing Apple PKCS#12 conversion path.

After independent verification, guest administration installs only server-role
bytes. Prepare canonical root-owned `/etc/reach` and `/etc/reach/tls` parents
without group/other write permissions, with the TLS directory searchable by
`reachd` (for example root:reachd 0750). Exclusively create, refusing every
existing destination, these root:reachd 0640 regular singly linked files:

| Source under the verified `server` directory | Destination |
| --- | --- |
| `reachd.json` | `/etc/reach/reachd.json` |
| `ca.pem` | `/etc/reach/tls/ca.pem` |
| `server-chain.pem` | `/etc/reach/tls/server-chain.pem` |
| `server-key.pem` | `/etc/reach/tls/server-key.pem` |

Use checked exclusive creation rather than a copying command that overwrites
destinations. Verify installed hashes and ownership/modes before starting.
Keep the operator tree inaccessible to `reachd`; never deploy the CA signing
key or client bundle to that account. The schema-1 JSON already names these
deployment paths. Establish the configured provider before explicitly starting
Reach; consult [the Linux service workflow](../../docs/running.md).

Transfer only the client's `.reachidentity` and public CA through an authenticated
private channel. The bundle uses the existing `ProvisionedIdentity` Codable
fields and base64 data, with X9.63 public point plus private scalar. It contains
a client private key and is not a diagnostic artifact. Compatibility checks can
use `ProvisionedIdentity.load`, CryptoKit key reconstruction and the explicit
memory-only `IdentityStore.identity(fromPKCS12:passphrase:)` API. Conversion of
an already issued client to PKCS#12 does not issue a CA. Do not use
`IdentityMaterializer.materialize` or `ProvisionedIdentity.install` for a
memory-only check: those routes can write to Keychain.

Normal Linux package removal preserves `/etc/reach` and the separate operator
bundle. Credential deletion is an explicit operator action. Keep private keys,
client bundles, passphrases, prompts and generated text out of logs/evidence.
