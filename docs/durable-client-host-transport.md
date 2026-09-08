# Explicit durable loopback transport

`reachd durable-transport` runs a selected durable generation in separate macOS
host and client processes over pinned mTLS QUIC. It is opt-in and limited to one
same-boot local pair and the `local-llama-258-v1` tiny Llama artifact profile.
The ordinary daemon, SDK, model catalog and default wire offers remain unchanged.

## Commands and ownership

Use the same eligible normal `reachd` executable for initialization and every
worker: its file and parent directory must be owned, canonical and mode `0700`.
The model source is an owned `0700` directory containing the selected `0600`
profile, configuration, weights, tokenizer and template files. The normal build's
Metal resource must be available to that executable. No model is downloaded.

In a dedicated foreground initializer:

```sh
reachd durable-transport init --root /private/tmp/owned-parent/pair \
  --model /private/tmp/owned-parent/model --port 54194
```

The root must be new. Wait for `ready`; keep the initializer alive throughout the
run. It owns the new scoped Keychain's deletion capability and releases both
journal locks before reporting readiness. Its random Keychain password remains
in memory. Workers use load-only access; they do not request a desktop password,
unlock a Keychain, or search for replacement credentials.

In a second process, run the host:

```sh
reachd durable-transport host --root /private/tmp/owned-parent/pair --progress
```

In a third process, begin one request:

```sh
reachd durable-transport begin --root /private/tmp/owned-parent/pair \
  --request /private/tmp/owned-parent/request.json --progress
```

The request uses the [local runtime's bounded request format](durable-local-runtime.md).
`--report` writes a bounded JSON report to a fresh file in an owned directory;
without it the report goes to stdout. `--progress` emits non-content commit and
receipt boundaries. Host checkpoint phases describe committed native state;
`high: 0` is possible during hidden tool work.

After a client process stops, recover with its original encrypted disk selection:

```sh
reachd durable-transport recover --root /private/tmp/owned-parent/pair
```

Recovery has no request, ticket, clock, caller or model override. The host must be
running, or return within the bounded reconnect window. A running client retains
its own journal owner while reconnecting to a restarted host.

Stop and join the serving host before host-local retirement:

```sh
reachd durable-transport cancel --root /private/tmp/owned-parent/pair
```

This records the existing outer cancellation disposition. It does not append a
provider ending or claim a tool effect. After all workers have stopped, signal
the initializer with SIGINT or SIGTERM. `retired` confirms owned Keychain and tree
cleanup. If it reports `cleanup-blocked`, retain that initializer and resolve the
held owner or damaged fixture before signalling again.

## Authority and delivery

The initializer creates one CA and separate host/client leaf identities. Only
role-owned PKCS#12 leaf files persist, at mode `0600`, and reopen imports explicitly
into memory. The archive's fixed passphrase is a container convention; filesystem
ownership protects these files. No login, System or iCloud identity is installed.

Each role has its own key-confirmed selection binding the bootstrap, current boot,
exact executable, portable model descriptor, artifact digest, port, CA and both
leaf digests. TLS evaluates against only that CA under the peer's SSL role policy;
the actual peer DER must then match the selected leaf before Hello is read.
The caller is fixed from the CA digest, client leaf digest and
`reach.durable-transport.loopback.v1`. Peer labels and JSON do not grant authority.

The host acquires two storage keys and its journal and model. The client acquires
one key, its journal and encrypted recovery ticket sidecar, its TLS identity, and
its portable descriptor. It does not acquire a host key, open a host journal,
load weights or call MLX. Both roles may inspect shared bootstrap/directory
metadata. This is a cooperating same-UID ownership contract, not protection
against a malicious process with the same UID and executable.

Only literal `127.0.0.1` and the selected high UDP port are used. The command
requires an explicit `[2]` Hello, version 2 acknowledgement and the fixed model
before durable traffic. There is no discovery, advertisement, handover, alternate
address, volatile fallback or global promotion of dialect 2.

A key-confirmed host reservation persists before original request preparation.
It permits one generation per initialized root, including after failures,
restarts and retirement. Losing a reply before the client finishes durable
context and encrypted-ticket registration reports `unknown-lost`; it does not
prove the request did not run, and does not automatically begin again.

After acceptance, the host replays from the current durable client witness before
advancing native work. It sends one batch, waits for its exact nonterminal receipt,
and sends `receiptAccepted` before the next batch. The client persists before
acknowledging. Hidden steps continue without waiting for a nonexistent batch.
Native work runs on a serial host queue; disconnect stops it at its next returned
boundary without cancelling the generation.

The client retains terminal content and does not send a terminal-retirement
receipt. Unsolicited terminal retirement is refused. Terminal recovery performs
zero generation, while bounded host model materialization remains allowed.
There is no peer effect executor or tool permission endpoint.

## Bounds and failures

There is one admitted QUIC group/stream and no unbounded frame or send queue.
The demand reader checks the five-byte envelope before allocating its body and
requests at most 64 KiB at a time. Control and bulk body limits remain 2 MiB and
14 MiB; replay validates at most 16 MiB of event bytes and encodes only the next
batch, within the 32 MiB encoded-workset ceiling. These are application buffer
bounds, not total RSS claims. Excess connections and streams are cancelled.

Every reconnect uses fresh TLS, Hello and adapter state after draining the old
stream. Retry delay starts at 250 ms and doubles to at most two seconds. Dial and
handshake are bounded to ten seconds, and reconnect is bounded to sixty seconds
from detected loss and the original authority expiry. Pin, role, model, store and
protocol refusals stop the client. `reconnect-exhausted` preserves recoverable disk
state without leaving a retry worker or inventing an ending. Native calls have
returned-boundary supervision rather than an asserted hard interruption deadline.

Each journal quota is 1 GiB. The selected native allocator ceiling is 128 MiB.
Use only disposable owned fixtures for crash tests; the initializer is never the
crash subject. Cross-machine bootstrap, clocks, consent, identity rotation and
terminal-receipt recovery after retirement remain outside this route.
