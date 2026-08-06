# Running the daemon

`reachd serve` in a terminal is a legitimate way to work and is how every
demo has been shot. What it is not is a service: when the process dies —
a crash, an update, a Mac that rebooted — nothing brings it back, and every
granted app on every device sees a cluster that is simply not there.

`reachd doctor` says which of the two you have, under **supervision**.

## As a service

```
cp .build/release/reachd /usr/local/bin/reachd
reachd service install
```

Install refuses a binary inside a build directory. `~/Library/Caches` is
purgeable — macOS reclaims it under disk pressure without asking — so an
agent pointed there works until the day it silently does not, and then fails
at every login with a missing-file error that reads like nothing in this
project.

`reachd service status` reports whether it is installed and loaded;
`reachd service uninstall` removes it. Output goes to
`~/Library/Logs/reachd.log`, because every line the daemon writes is `print`
or stderr and launchd sends those nowhere by default.

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

### What it restarts, and what it will not

`KeepAlive` is `Crashed`, so launchd brings back a process that **died** — a
signal, a `kill -9`, a real fault. It deliberately does not restart a process
that **refused to start**: the daemon exits non-zero when it cannot take its
port, and restarting that on a loop would scroll the reason past ten seconds
at a time instead of leaving it where it can be read.

A held port is the likeliest bad start, because racing a dying process for
its port is what a restart is. The refusal names the port; `lsof -nP -iUDP:47337`
finds who has it.

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
