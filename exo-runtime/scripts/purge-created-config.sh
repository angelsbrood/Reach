#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "purge requires root" >&2
  exit 1
fi
if [ "${REACH_EXO_PACKAGE_LOCKED:-}" != 1 ]; then
  exec flock -n /run/lock/reach-exo-package.lock env REACH_EXO_PACKAGE_LOCKED=1 "$0" "$@"
fi
[ -x /opt/reach-exo/bin/reach-exo-package ] || { echo "package authority command absent" >&2; exit 1; }
/opt/reach-exo/bin/reach-exo-package assert-no-transaction
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
case "$(cat "$marker")" in
  reach-exo-lifecycle/0.1.0|reach-exo-lifecycle/0.2.0) ;;
  *) echo "bundle-created ownership marker content invalid" >&2; exit 1 ;;
esac
rm -f -- /etc/reach-exo/node.json "$marker"
echo "purged only bundle-created node configuration; preserved TLS and model bytes"
