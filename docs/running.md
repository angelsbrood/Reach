# Running the daemon

`reachd serve` in a terminal is a legitimate way to work and is how every
demo has been shot. What it is not is a service: when the process dies —
a crash, an update, a Mac that rebooted — nothing brings it back, and every
granted app on every device sees a cluster that is simply not there.

`reachd doctor` says which of the two you have, under **supervision**.

## Whether the cluster can actually answer

`doctor` on its own is about the host: the state directory, the config, the
CA, the ports being held, the agent being installed. All of it can be green
over a cluster that cannot serve a client — the port check binds `INADDR_ANY`
and can only tell you that *something* holds the port, never that the
something answers.

```
reachd doctor --dial
```

opens a real session against the running daemon with the ordinary client
stack, and reports the road the daemon says it came in on:

```
PASS  dial              a session opened over 127.0.0.1:47337 in 38 ms — the cluster answers a client
PASS  road              the daemon logged the session: opened from 127.0.0.1:65246
```

It mints an ephemeral identity from the cluster's own CA — five minutes,
`reach://diagnostic/…`, never stored, never in the keychain — and asks for no
tokens: `reachd selftest --mlx` already proves generation end to end, and the
model prewarms asynchronously at every login, so a dial that wanted a token
would fail on a healthy cluster that had just started.

A daemon that is simply not running is `WAIT`. A daemon that is running and
cannot answer is `FAIL`, and only `FAIL` gates the exit status.

`--via <host[:port]>` dials one chosen road instead of loopback, which is how you
prove a road from the host side before asking a device to use it, and
`--dial-budget <seconds>` (default 10) bounds the whole attempt — the dial gets
half of it and the exchange on the far side gets the rest, so both halves stay
inside the number you asked for.

⚠️ **A tunnel address is the exception**: this host cannot dial its own mesh
address — plain UDP and ICMP to it are dropped the same way — so `--via` the
mesh address must be run from the other end of the tunnel, not from the
cluster.

## Automatic mappings

While serving, reachd holds two long-lived UDP mapping requests through the
macOS system broker: the configured session port and WireGuard `51820`. It asks
for the same external ports and the system-default lease lifetime, but the
router may assign different ports. Enrollment is not mapped. The system renews
the mappings and reports network, address, or port changes on the same request;
stopping the daemon deallocates both.

`doctor` prints separate `session mapping` and `mesh mapping` findings. Active
public mappings pass. A private/shared outer address or an explicit double-NAT
callback warns and is described as usable only from that outer network.
Probing waits; unsupported, disabled, absent-router, zero-endpoint, and broker
errors warn without changing local or pinned behavior. A dead process's active
record is called stale, and endpoint movement names the replaced value. The
evidence lives at `reachability.json` in the state directory with mode `0600`;
it is runtime diagnostics, never configuration and never an authority for a
road.

An assigned endpoint can be exercised directly:

```
reachd doctor --dial --via 198.51.100.8:55001
```

The QUIC listener requires a cluster-issued client certificate at TLS even
when mapped onto a public interface. WireGuard accepts only enrolled peer keys.
Neither fact makes a private double-NAT address public: single-NAT edges are
the direct-mapping case, while CGNAT, building routers, and VPN layers may
still require a manually reachable endpoint or the future relay described in
[relay.md](relay.md). A client already away when an endpoint moves keeps its
stale road until it can authenticate on another one and receive a fresh hello.

## As a service

⚠️ **`reachd` is not a single file.** SwiftPM emits resource bundles beside the
executable, and MLX finds its Metal library by looking there. A binary copied
on its own starts, prints that it is serving, binds the port, and *then* dies
loading the model — which under launchd is a crash loop at every login whose
only clue is a metallib path deep inside a build directory. Copy the
directory, not the file:

```
swift build -c release --package-path reachd --scratch-path ~/Library/Caches/reach-spm/reachd-release
```

```
mkdir -p ~/.local/libexec/reach && cp -R ~/Library/Caches/reach-spm/reachd-release/out/Products/Release/{reachd,*.bundle} ~/.local/libexec/reach/
```

```
ln -sf ~/.local/libexec/reach/reachd ~/.local/bin/reachd && reachd service install
```

`~/.local` rather than `/usr/local/bin` because the agent runs as you and
needs no `sudo`; either works. `service install` refuses a binary with no
`mlx-swift_Cmlx.bundle` beside it, and refuses one inside a build directory:
`~/Library/Caches` is purgeable — macOS reclaims it under disk pressure
without asking — so an agent pointed there works until the day it silently
does not. It also refuses to install as root: the service belongs to one login
user and one `gui/<uid>` domain.

The installed command normalizes its executable identity before argument
parsing or MLX access. These all reach the same binary and the same seven
adjacent bundles:

```
~/.local/libexec/reach/reachd selftest --mlx
~/.local/bin/reachd selftest --mlx
reachd selftest --mlx
```

Absolute, nested and `PATH` symlinks are resolved once with no wrapper shell
and no resource copies beside the alias. User arguments, the environment and
the working directory survive the process replacement. `service install`
retains its independent guard: it resolves symlinks before writing the plist,
so the supervised agent records `~/.local/libexec/reach/reachd`, verifies the
adjacent MLX bundle, and starts directly in the canonical layout.

### ⚠️ Reinstalling can quietly destroy the cluster

A `serve` that cannot find its CA does not fail — it **mints a fresh one**,
which orphans every paired device and voids every grant, unattended, at
ten-second intervals under `KeepAlive`. So a reinstall is guarded rather than
just done:

1. Back up `~/Library/Application Support/Reach` and record
   `shasum ~/Library/Application\ Support/Reach/ca/*` — four files.
2. Build the release, as above.
3. `launchctl bootout gui/$(id -u)/systems.reach.reachd` — **before** copying.
   Never copy over a running binary. (`reachd service install` does its own
   bootout and bootstrap and is the supported path; by hand is for watching
   each step.)
4. Copy the binary **and the bundles**. Count what lands: eight items. On a
   reinstall, copy the executable to a fresh sibling such as `reachd.next`,
   run `codesign --verify --verbose=4` on it, and then
   `mv -f reachd.next reachd` while the agent is stopped. Do not use `cp` to
   overwrite the existing executable inode in place: launchd can retain that
   vnode's old code-signing state and kill the otherwise-valid replacement with
   `OS_REASON_CODESIGNING`.
5. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/systems.reach.reachd.plist`
6. Then seven checks, and it is not installed until all seven pass:
   `grep -c "cluster CA created" ~/Library/Logs/reachd.log` is **0**; the four
   CA fingerprints are unchanged; `doctor` says `PASS supervision`; and
   **`doctor --dial` says the cluster answers**. The first six are about the
   host and were all green, five separate times on 6 August 2026, over a
   cluster that could not serve a client.

`reachd service status` reports the owning login UID and `gui/<uid>` domain,
the exact state and log paths, whether the agent is loaded, and separately
whether a `10.86.0.x` mesh address is present. A running PID with a missing
mesh is explicitly incomplete away readiness, not a healthy service inferred
from process state. `reachd service install` writes the plist through
`PropertyListSerialization` and pins the user's existing state with an
explicit `REACH_STATE_DIR`; paths containing spaces or XML-significant
characters are data, not hand-built XML.

`reachd service uninstall` removes it. Output goes to
`~/Library/Logs/reachd.log`, because every line the daemon writes is `print`
or stderr and launchd sends those nowhere by default. `serve` line-buffers
stdout so that log is readable while the daemon is healthy — block buffering
would fill it only when the process died, which is the wrong way round.

### It starts at login, not at boot

This is deliberately a **login-owned LaunchAgent**. A Mac that has rebooted
does not serve at the login screen; it begins serving after the owning user
logs in and the `gui/<uid>` domain exists. Two physical reboot trials showed
that exact bounded refusal before login and one automatically supervised
daemon after login.

The reason is the selected ownership contract, not a login-keychain
requirement. The cluster state, operator commands, and MLX/Metal process belong
to one user. The listener leaf is loaded from that user's disk state and
imported into process memory with `kSecImportToMemoryOnly`. A root process with
no explicit state path would instead resolve `/var/root/Library/Application
Support`, mint a different CA, and silently become a different cluster.

Accordingly, `service install` refuses root, and `reachd serve` refuses root
unless `REACH_STATE_DIR` names an explicit absolute state directory. That
override is for controlled scratch/system-context work; it does not make
pre-login serving supported. The generated agent always sets
`REACH_STATE_DIR` to the owning user's existing Reach directory, so launchd
never guesses which cluster it should start.

### What closing the lid does

Sleep is measured separately from reboot. On one MacBook Pro (`Mac17,9`) under
macOS 27.0, the installed cluster survived two roughly one-minute sleeps, two
roughly ten-minute sleeps, and two sleeps longer than eight hours without a
daemon restart, listener loss, WireGuard loss, CA change, or model reload.
`ProcessType: Interactive` was left alone: it controls launchd's resource
classification and does not prevent system sleep.

An in-flight response may appear to pause while the machine is fully asleep.
In both short trials the same generation resumed and completed after wake.
During both ten-minute trials, active QUIC traffic instead caused network dark
wakes long enough for the real-weight response to finish while the lid was
closed; macOS then returned to deep sleep. The 120-second residency window
still bounds an unavailable generation, but closing the lid does not by itself
start a countdown while the OS continues servicing that flow.

The idle overnight result is colder: the same launchd PID and run count,
listeners, roughly 4.3 GiB resident model, and `10.86.0.1` interface survived
8 h 18 m and 8 h 00 m sleeps. A fresh authenticated generation succeeded after
each wake. The temporary mapping trial found that a 7,200-second router lease
can expire while the host is deeply asleep; the unchanged macOS broker rebuilt
both mappings four seconds after wake. Because it already performs that wake
refresh, reachd has no custom sleep observer or wake handler.

This is evidence from one host and OS build, not a promise that macOS will keep
every process resident indefinitely. Unconditional launchd supervision still
covers a process death. If the listener is absent after wake, inspect
`~/Library/Logs/reachd.log`, the launchd run count, `lsof -nP -iUDP:47337`, and
`reachd doctor --dial` rather than assuming sleep was healthy because the PID
now exists.

Sleep also does not erase the login boundary above. The later S23 lifecycle
matrix repeated lock once, logout/login twice, and reboot/pre-login/login
twice. Lock preserved the same daemon; each login created exactly one new
supervised daemon with unchanged state. Both reboots returned the LaunchAgent
after login but did not raise WireGuard. Raising `reach0` manually after the
daemon started worked without a daemon restart: the wildcard listener accepted
the mesh road immediately, and the next authenticated hello advertised the
new address. The final installed repeat also lost the mesh on both
logout/login cycles, even though the earlier measurement happened to retain
it. Interface survival across logout is therefore not a supported contract.
Fast user switching and OS-update survival remain unmeasured.

### What it restarts

Everything. `KeepAlive` is unconditional, with `ThrottleInterval` putting a
ten-second floor under the retry. Measured: `kill -9` on the daemon and it is
back in about two seconds.

It was first written as `KeepAlive: {Crashed: true}`, on the reasoning that
the daemon's considered non-zero exit for a held port should not become a
respawn loop. Installing it and killing the daemon showed that reasoning was
worth less than the test: **launchd counts a crash as the SIGSEGV/SIGABRT
family, not a deliberate signal, so `Crashed` did not bring it back at all.**
It also misses the kernel's own `SIGKILL` under memory pressure, which is the
likeliest unplanned death of a process holding several gigabytes of weights.
A supervisor whose job is that the cluster is there cannot be selective about
which deaths count.

The consequence is that a genuinely held port re-attempts every ten seconds.
That heals itself the moment the port frees — which is the restart race, and
the common case — and if something else owns 47337 permanently, the reason
lands in the log at the same pace. `lsof -nP -iUDP:47337` finds who has it.

### The mesh road is still yours to raise

`wg-quick up reach0` wants root, so it is not in the agent. That separation is
intentional: the current Homebrew script executes hook fields and the current
configuration is user-owned, so an unattended root job consuming it would be
a privilege-escalation path. Automatic bootstrap needs a trusted installation
and sanitized structured configuration of its own.

Until the interface is up, the daemon may serve on LAN but has no mesh road to
fall to. `reachd doctor` and `reachd service status` both distinguish that
state. Once WireGuard rises, **do not restart `reachd`**: every authenticated
hello recomputes current addresses. A phone already away cannot learn an
address that appeared after its last hello; let it authenticate once on LAN or
another surviving road, then its next cold away launch can use `10.86.0.1`.

## What a restart costs

Identity, grants, the CA and the mesh are on disk and survive. Sessions are
not, and do not need to be: the transcript rides the wire on every request, so
a client whose session the daemon has forgotten opens a fresh one and asks
again without anyone seeing it. The one real casualty is a generation actually
in flight, which ends saying so. `wire.md` has the detail.

The first generation after a restart is slower — the weights are paged in on
use rather than at load — and no supervisor shortens that.
