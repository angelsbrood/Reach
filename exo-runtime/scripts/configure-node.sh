#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$(id -u)" -ne 0 ]; then
  echo "usage as root: configure-node.sh NODE_JSON" >&2
  exit 2
fi
if [ "${REACH_EXO_PACKAGE_LOCKED:-}" != 1 ]; then
  exec flock -n /run/lock/reach-exo-package.lock env REACH_EXO_PACKAGE_LOCKED=1 "$0" "$@"
fi
case "$1" in /*) ;; *) echo "NODE_JSON must be absolute" >&2; exit 2 ;; esac
[ -x /opt/reach-exo/bin/reach-exo-node ] || { echo "bundle is not installed" >&2; exit 1; }
[ -x /opt/reach-exo/bin/reach-exo-package ] || { echo "package authority command absent" >&2; exit 1; }
/opt/reach-exo/bin/reach-exo-package assert-no-transaction
[ ! -e /etc/reach-exo/node.json ] && [ ! -e /etc/reach-exo/.bundle-created ] || { echo "configuration already exists" >&2; exit 1; }

install -d -m 0750 -o root -g reach-exo /etc/reach-exo
install -m 0640 -o root -g reach-exo "$1" /etc/reach-exo/node.json
if ! /opt/reach-exo/bin/reach-exo-node validate /etc/reach-exo/node.json; then
  rm -f -- /etc/reach-exo/node.json
  exit 1
fi
printf '%s\n' 'reach-exo-lifecycle/0.2.0' > /etc/reach-exo/.bundle-created
chown root:root /etc/reach-exo/.bundle-created
chmod 0600 /etc/reach-exo/.bundle-created
echo "configuration installed; service remains disabled and stopped"
