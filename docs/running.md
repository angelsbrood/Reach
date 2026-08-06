# Running the daemon

`reachd serve` in a terminal is a legitimate way to work and is how every
demo has been shot. What it is not is a service: when the process dies —
a crash, an update, a Mac that rebooted — nothing brings it back, and every
granted app on every device sees a cluster that is simply not there.

`reachd doctor` says which of the two you have, under **supervision**.

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
