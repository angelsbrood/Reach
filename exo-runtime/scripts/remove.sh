#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "remove requires root" >&2
  exit 1
fi

systemctl disable --now reach-exo-node.service >/dev/null 2>&1 || true
systemctl stop reach-exo-relay.service >/dev/null 2>&1 || true
if [ -e /run/reach-exo-peer-neighbor.json ]; then
  [ -x /opt/reach-exo/bin/reach-exo-node ] && [ -f /etc/reach-exo/node.json ] || { echo "owned peer-neighbor state cannot be authenticated" >&2; exit 1; }
  /opt/reach-exo/bin/reach-exo-node neighbor-remove /etc/reach-exo/node.json
fi
if [ -x /opt/reach-exo/bin/reach-exo-node ] && [ -f /etc/reach-exo/node.json ]; then
  /opt/reach-exo/bin/reach-exo-node netguard-remove /etc/reach-exo/node.json >/dev/null 2>&1 || true
fi
account_marker=/var/lib/reach-exo/.bundle-created-account
remove_account=false
if [ -f "$account_marker" ] && [ ! -L "$account_marker" ] && [ "$(stat -c '%u:%g:%a:%h' "$account_marker")" = '0:0:600:1' ]; then
  version=$(sed -n '1p' "$account_marker")
  uid=$(sed -n 's/^uid=//p' "$account_marker")
  gid=$(sed -n 's/^gid=//p' "$account_marker")
  case "$uid:$gid" in *[!0-9:]*|:*|*:) echo "invalid package account marker" >&2; exit 1 ;; esac
  [ "$version" = 'reach-exo-lifecycle/0.1.0' ] || { echo "invalid package account marker" >&2; exit 1; }
  [ "$(id -u reach-exo 2>/dev/null)" = "$uid" ] && [ "$(id -g reach-exo 2>/dev/null)" = "$gid" ] || { echo "package account identity drifted" >&2; exit 1; }
  [ "$(getent passwd reach-exo | cut -d: -f6-7)" = '/var/lib/reach-exo:/usr/sbin/nologin' ] || { echo "package account authority drifted" >&2; exit 1; }
  if pgrep -u "$uid" >/dev/null 2>&1; then
    echo "package account still owns a live process" >&2
    exit 1
  fi
  remove_account=true
fi
rm -rf -- /opt/reach-exo /var/lib/reach-exo /run/reach-exo
rm -f -- /usr/lib/systemd/system/reach-exo-node.service /usr/lib/systemd/system/reach-exo-relay.service /usr/lib/sysusers.d/reach-exo.conf /usr/lib/tmpfiles.d/reach-exo.conf
systemctl daemon-reload
if [ "$remove_account" = true ]; then
  userdel reach-exo
  if getent group reach-exo >/dev/null 2>&1; then
    groupdel reach-exo
  fi
fi
echo "removed package/runtime; preserved /etc/reach-exo and /srv/reach-exo-models"
