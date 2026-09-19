# Local operational witness access

S106 adds a foreground Unix-domain service and receiver adapter to the standalone
`Tools/CrossBootTimePolicy` package. An independently launched receiver can obtain
a fresh certificate from a surviving service against exactly the same original
registrations. The service retains one in-memory `Witness`; each receiver retains
one `Verifier`. The existing [clock policy](cross-boot-time-policy.md), signed wire
formats, caps and time assumptions remain unchanged.

This boundary is for explicitly selected cooperating processes on one Mac.
Native recovery integration, access across receiver OS reboot, issuer persistence,
remote provisioning, automatic launch/discovery and deployment remain separate
work. Same-user filesystem permissions and peer credentials do not isolate
hostile code already running as that user. A certificate supplies conditional time
evidence; it does not authorize an effect or establish ownership fencing.

## Startup and trusted selection

`witness-access-qualification service` takes three required arguments:

```text
--endpoint /private/tmp/owned-private-root/s
--selection /private/tmp/owned-inputs/selections.json
--descriptor /private/tmp/owned-inputs/descriptor.json
```

The endpoint's parent must be a fresh, empty, same-user mode-0700 directory, with
no symlink components. Its full absolute UTF-8 pathname, including NUL, must fit
104 bytes. The service creates a mode-0600 socket and never unlinks an occupied
path to force a launch. Both socket peers check the selected UID with `getpeereid`.
The socket uses nonblocking I/O and `SO_NOSIGPIPE`.

The owned mode-0600 selection file contains canonical sorted-key JSON, without
whitespace or a trailing newline. Each tuple supplies a lowercase UUID `subject`
and integer `hostCap` / `clientCap` in nanoseconds. For example:

```json
[{"clientCap":240000000000,"hostCap":180000000000,"subject":"11111111-1111-4111-8111-111111111111"}]
```

The service validates the entire selection before creating any registration.
One to eight distinct subjects are admitted; identical duplicate tuples collapse
to one pair and conflicting tuples refuse. Both roles are provisioned once. Any
failure aborts startup before descriptor publication and readiness. Registration,
reanchoring and pin replacement are unavailable on the work socket.

After complete provisioning and endpoint readiness, the service exclusively
creates the public descriptor file and prints a `ready` report with its SHA256.
The bounded descriptor contains the endpoint, UID, exact qualification profile,
full witness identity and exact signed original pairs. The private key, registry
and nonce history remain inside the service process. The service ignores stdin;
closing its launcher's control pipe or ending a receiver does not end it.

A trusted launcher supplies the receiver's descriptor path, expected digest and
selected subject separately:

```text
witness-access-qualification receiver --descriptor PATH --digest SHA256 --subject UUID
```

The receiver bounds the owned regular file to 64 KiB, checks its complete digest
before adopting any fields, then checks the canonical descriptor and original
signatures. It never learns a new pin from a socket or replacement ready file.
The expected digest must come from the trusted selection, not from rereading an
arbitrary updated descriptor. The library exposes `Descriptor.load`,
`AccessOwner.exchange`, `evaluate`, `finish` and `observeWitnessLoss` for the same
explicit ownership model. Owners and services are serial; they are not shared
concurrently across callers.

## Framing, time and loss

Each connection contains one request and one response, each with a four-byte
big-endian length followed by 1–65,536 bytes. A client half-closes its send side;
the server requires EOF after the request and closes after its response. Extra
frames, partial EOF and oversized lengths refuse. No body allocation follows an
unvalidated incoming length.

`Verifier.begin` supplies the original send sample before connect or transport
I/O. One absolute five-second continuous-monotonic deadline includes connect,
queueing, partial transfer, framing, signature validation and parsing. Poll
wakeups, EINTR and partial progress do not restart it. The service independently
limits each accepted connection to five seconds. A full queue can refuse a
connection immediately. No retry resends a challenge or creates a fresh bracket
inside the same exchange.

After exact response EOF, the unchanged signed response reaches
`Verifier.receive`. Every prospective use must call `evaluate` again after any
blocking work and require `outcome == .eligible`. The existing conservative
bound must remain strictly below both immutable deadlines. Signature validity
alone is insufficient. `finish` releases the action but preserves the receiver's
64-action lifetime budget. The witness retains its 16-registration and 128-nonce
lifetime limits without expired-slot reclamation.

Every ambiguous exchange failure, including connect failure, timeout, malformed
response, refusal, wrong pin or signature, invalidates the owner. All its old
actions and subsequent exchange attempts then refuse. Making the endpoint
available again cannot revive it. A separately launched receiver can create its
own fresh owner against the same originals and surviving witness.

Normal completed EOF is not evidence of subsequent service death. A completed
action may remain conditionally eligible within its age/deadline bounds until
loss is observed. The adapter does not claim continuous liveness observation.
Fatal witness clock faults end service operation; there is no replacement epoch
inside a service lifetime. An explicit service restart creates a new identity
and new work, and cannot adopt old originals.

## Qualification

Build the dependency-free package with at most four jobs, closed IP networking
and host Keychain access denied. The existing ClockPolicy test sources remain
unchanged. New access tests cover provisioning, descriptor and path refusal,
framing, exact deadline edges, action/nonce/registration limits, replay, loss
latching and startup failure. Socketpair unit fixtures use small bounded payloads;
actual blocked-write behavior is exercised by separate real-clock processes.

The serial runner applies a sandbox permitting only its explicitly selected Unix
endpoint, with other networking and host Keychain reads denied. Run actual Swift
feasibility first; campaign mode requires a successful result for the identical
executable:

```text
python3 scripts/qualify-witness-access.py --mode feasibility \
  --executable ABSOLUTE_EXECUTABLE --scratch OWNED_BUILD_ROOT --output NEW_FEASIBILITY_DIR
python3 scripts/qualify-witness-access.py --mode campaign \
  --executable ABSOLUTE_EXECUTABLE --scratch OWNED_BUILD_ROOT --output NEW_CAMPAIGN_DIR \
  --feasibility NEW_FEASIBILITY_DIR/result.json
```

Use a short, real path such as an owned directory under `/private/tmp` for the
scratch root. Output directories must be new. The runner is the trusted selector
for synthetic qualification subjects; it is not a provisioning UI. Its selected
fault modes are CLI-only qualification mechanics, never work-socket commands.

Feasibility covers both peer checks, split delivery, exact EOF, partial/trailing/
oversized replies, blocked reads/writes, queue-full connect refusal, repeated
partial traffic and interrupted waits. Negative sandbox probes cover another
Unix bind, IPv4/IPv6 loopback binds and a denied Keychain-directory open; they do
not claim IP-connect qualification or read any Keychain contents.

The process campaign checks independent receiver continuity, mid-exchange loss,
replacement refusal and timeout latching. Separate fresh serial cohorts first
obtain eligible controls, then exercise an authentic pre-deadline reply held
about 4.25 seconds for host expiry, a completed action reevaluated after client
expiry, and a prompt exchange reevaluated after more than ten seconds for age
refusal. A transport timeout is recorded as loss, never as signed expiry.

Numeric direct-child PIDs, reaps, original bytes, signed responses, samples,
selected sandbox profiles, logs and failures are retained in the supplied output.
Services are joined before owned endpoints are removed; cleanup refuses unexpected
files and preserves an unrelated sentinel. The runner monitors a 4 GiB aggregate
owned allocation, 32 MiB per log, 128 MiB output and at least 30 GiB free space.
The caller also accounts for prior retained attempts in the overall campaign
budget. No exhaustive compiler-descendant or hostile-filesystem race guarantee
is claimed. Architecture acceptance remains a separate actual-byte review.
