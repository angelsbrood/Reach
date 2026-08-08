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
does not.

⚠️ **MLX commands currently need the canonical installed path.** Measured on
8 August 2026, invoking `selftest --mlx` through the `~/.local/bin/reachd`
symlink made the pinned MLX runtime search beside `~/.local/bin` and refuse
with `Failed to load the default metallib`; invoking the same installed binary
beside its seven bundles passed. Until launch-path normalization lands, run
GPU-bearing diagnostics (and a manual `serve`) as:

```
~/.local/libexec/reach/reachd selftest --mlx
```

`service install` is safe through the symlink: it resolves symlinks before
writing the plist, so the supervised agent records
`~/.local/libexec/reach/reachd` and uses the adjacent bundles.

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
4. Copy the binary **and the bundles**. Count what lands: eight items.
5. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/systems.reach.reachd.plist`
6. Then seven checks, and it is not installed until all seven pass:
   `grep -c "cluster CA created" ~/Library/Logs/reachd.log` is **0**; the four
   CA fingerprints are unchanged; `doctor` says `PASS supervision`; and
   **`doctor --dial` says the cluster answers**. The first six are about the
   host and were all green, five separate times on 6 August 2026, over a
   cluster that could not serve a client.

`reachd service status` reports whether it is installed and loaded;
`reachd service uninstall` removes it. Output goes to
`~/Library/Logs/reachd.log`, because every line the daemon writes is `print`
or stderr and launchd sends those nowhere by default. `serve` line-buffers
stdout so that log is readable while the daemon is healthy — block buffering
would fill it only when the process died, which is the wrong way round.

### It starts at login, not at boot

This is a **LaunchAgent**, and the reason is where the cluster's keys live.

A `LaunchDaemon` would start at boot without anyone logging in, which is what
you actually want from a cluster. It cannot, for two reasons:

1. **The login keychain.** The listener's TLS identity is imported into it on
   every start. A root `LaunchDaemon` has no login keychain to import into,
   and without that identity there is no listener at all.
2. **The state directory.** It resolves the home directory through the
   password database, ignoring `HOME`. As root that is
   `/var/root/Library/Application Support`, where `serve` finds no CA and
   **mints a fresh one** — not a broken service but a *different cluster*,
   with every paired phone orphaned and every grant void. `REACH_STATE_DIR`
   can point the directory back; the keychain cannot be pointed anywhere.

So a Mac that has rebooted serves once somebody has logged in. Moving key
material off the login keychain is what would change that, and it has not
been done.

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

`wg-quick up reach0` wants a password, so it is not in the agent. Until it is
up, the daemon serves on the LAN and has nothing to fall to at a walk-out.
`reachd doctor` checks the interface.

## What a restart costs

Identity, grants, the CA and the mesh are on disk and survive. Sessions are
not, and do not need to be: the transcript rides the wire on every request, so
a client whose session the daemon has forgotten opens a fresh one and asks
again without anyone seeing it. The one real casualty is a generation actually
in flight, which ends saying so. `wire.md` has the detail.

The first generation after a restart is slower — the weights are paged in on
use rather than at load — and no supervisor shortens that.
