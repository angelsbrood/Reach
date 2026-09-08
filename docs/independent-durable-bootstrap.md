# Independent durable bootstrap

`reachd durable-independent` is an explicit macOS route for one selected
`local-llama-258-v1` generation over pinned mTLS QUIC on literal `127.0.0.1`.
It uses dialect 2, ALPN `reach/0`, and profile `reach-durable-independent-v1`.
Normal daemon and SDK offers remain `[1,0]`; `durable-transport` retains its
original paired bootstrap and profile.

For finite initialization and fresh-process explicit retirement, select the
[durable role lifecycle](durable-role-lifecycle.md). The examples below retain
the original foreground creator mode and version 1 roots.

## Provision and initialize

The operator supplies the selected artifact directory, request, and a public
model declaration (`IndependentPublicModel`: portable descriptor and canonical
artifact-manifest digest). The declaration is authored alongside the artifacts.
The qualified fixture authoring test emits `public-model.json` with its existing
model and requests. Provisioning reads only that bounded declaration, creates
disposable TLS leaves, and writes a separate physical agreement copy for each
role. It does not create storage keys, journals, or model state.

Use fresh paths below an owned mode-0700 parent, and an exact frozen executable
whose file and parent are mode 0700. Private input files must be mode 0600.

```sh
reachd durable-independent provision --public-model /private/owned/public-model.json \
  --output /private/owned/staging --port 54195
reachd durable-independent init --role host --root /private/owned/host-root \
  --provisioned /private/owned/staging/host --model /private/owned/model
reachd durable-independent init --role client --root /private/owned/client-root \
  --provisioned /private/owned/staging/client
```

Run the two initializers separately and leave each in the foreground after its
`ready` record. Each retains its own original cleanup capability. The client
accepts no model argument and loads no model or host journal. Each local ready
transaction confirms only that role's IDs, keys, root, container, public agreement,
local boot/origin/epoch, executable, TLS archive, descriptor and quota selection.
There is no paired `BootstrapCore`, sibling journal or unused sibling key.

Remove the provisioning directory, including both staging TLS archives, after
both initializers report ready and before serving or recovery. The roots contain
their own physical agreement/TLS copies and never consult provisioning again.

## Run and recover

```sh
reachd durable-independent host --root /private/owned/host-root --progress
reachd durable-independent begin --root /private/owned/client-root \
  --request /private/owned/request.json --report /private/owned/result.json
reachd durable-independent recover --root /private/owned/client-root \
  --report /private/owned/recovered.json
```

`begin` is an explicit original request. After loss, use `recover`, which accepts
no ticket, context, peer epoch, clock origin, timestamp or expiry override. It
reopens the client's encrypted original selection and authenticates a fresh
pinned connection. Host reservation persists before original preparation. A
reserved or ambiguous generation never authorizes a replacement request.

The same transport loop applies verified replay before native continuation,
including an empty replay. It permits one outstanding batch: client persist,
nonterminal receipt, host `receiptAccepted`, then the next batch. Native
checkpoints can advance without visible events. The client withholds terminal
retirement receipts. Fresh terminal replay performs zero generation; the host
still materializes the qualified model on acquisition. Later tool-pass encoding
remains part of the unchanged native contract.

Retries use a fresh pinned connection, a ten-second connection deadline,
250 ms to two-second backoff, and a sixty-second loss window, further bounded by
the client's original local retention deadline. Protocol/host refusal is distinct
from retryable transport loss. No provider ending or tool effect is fabricated.

## Clock and retention authority

Each initializer persists a raw monotonic origin and fresh epoch. The role clock
uses checked `rawNow - origin + 1` under `role-monotonic-ns-v1:<epoch>`, with an
own-boot guard and rollback checks. Restart retains both values. Host and client
origins and epochs are distinct; they need no common monotonic coordinate.

Host context and ticket bytes retain their original host timestamps. The host
alone verifies its ticket MAC and expiry. Immediately before the original open
send, the client captures its local anchor. After the authenticated acceptance,
it persists encrypted `ClientLocalRetention`, binding the exact context/ticket,
pair, original host boot/policy, own boot/policy, anchor, cap and deadline. The
duration is the smaller of the checked host ticket duration and the selected
client cap; `provision --retention-seconds` permits 1 through 86400 seconds.

This local window limits retention and retries. It does not convert or extend
host expiry. Either side may expire first. Delayed initial acceptance consumes
the original window. Every client read, publication, effect-knowledge operation,
discovery, reopen and pruning path uses the effective local window. Duplicate
registration and recovery cannot renew it. Missing anchor/retention, malformed
mode, wrong clock/boot, overflow, rollback or incomplete original registration
refuses. No current-time lease reconstruction occurs.

The independent encrypted manifest is version 2, with host issued/expires fields
still in their original domain and a separate retention record. Recovery-envelope
version 2 authenticates the retention digest obtained from the encrypted local
manifest before ticket decryption. Original legacy encodings remain version 1;
trusted local selection chooses the mode, with no inference or downgrade from
peer frames. Reports can expose nonsecret retention diagnostics; reports are
never read as authority. Final client report publication rechecks authenticated
local eligibility after assembly and encoding. If the local window is exhausted
or registration is unavailable, no new content-bearing report is written, including
cached recovery prefixes and original acceptance/context. A requested report file
can therefore be absent on refusal; already published reports are not erased.

## Retire and qualification limits

Stop and join workers first. Optional host-local cancellation is:

```sh
reachd durable-independent cancel --root /private/owned/host-root
```

For roots initialized without `--finish`, signal the original client initializer and await `retired`, followed by the
original host initializer. Reverse creation order preserves the scoped Keychain
metadata checks. Each creator reacquires only its own journal before deleting its
own container/root. A `cleanup-blocked` creator remains available for correction;
do not replace or kill it to bypass ownership.

The qualification runner in `Tools/IndependentDurableBootstrap` runs the roles
with peer-root read/write denial, joins known owned children, and checks exact
role key selectors. Direct filesystem denial does not establish control over
securityd IPC or isolation from a malicious process with the same UID. The
campaign uses real distinct local origins and injected-clock tests for expiry
and boot differences. It establishes neither physical cross-machine operation
nor cross-boot/unattended key reopening. Public endpoints, default model/SDK
adoption, real effects, installed credentials/services and deployment remain
outside this route.
