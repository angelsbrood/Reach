#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "purge requires root" >&2
  exit 1
fi
marker=/etc/reach-exo/.bundle-created
if [ ! -f "$marker" ] || [ -L "$marker" ]; then
  echo "bundle-created ownership marker absent" >&2
  exit 1
fi
tuple=$(stat -c '%u:%g:%a:%h' "$marker")
if [ "$tuple" != "0:0:600:1" ]; then
  echo "bundle-created ownership marker tuple invalid" >&2
  exit 1
fi
if [ "$(cat "$marker")" != "reach-exo-lifecycle/0.1.0" ]; then
  echo "bundle-created ownership marker content invalid" >&2
  exit 1
fi
rm -f -- /etc/reach-exo/node.json "$marker"
echo "purged only bundle-created node configuration; preserved TLS and model bytes"

