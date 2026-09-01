#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install requires root" >&2
  exit 1
fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != aarch64 ]; then
  echo "bundle supports Linux/arm64 only" >&2
  exit 1
fi
for command in getent groupdel ip pgrep systemctl systemd-sysusers systemd-tmpfiles nft sha256sum userdel; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing prerequisite: $command" >&2; exit 1; }
done

bundle=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$bundle"
sha256sum -c MANIFEST.sha256

if [ -e /opt/reach-exo ] || [ -e /usr/lib/systemd/system/reach-exo-node.service ] || [ -e /usr/lib/systemd/system/reach-exo-relay.service ]; then
  echo "existing Reach EXO package state refuses replacement" >&2
  exit 1
fi
if getent passwd reach-exo >/dev/null 2>&1 || getent group reach-exo >/dev/null 2>&1; then
  echo "pre-existing reach-exo account or group refuses package ownership" >&2
  exit 1
fi

install -d -m 0755 /opt/reach-exo
cp -a root/opt/reach-exo/. /opt/reach-exo/
install -m 0644 root/usr/lib/systemd/system/reach-exo-node.service /usr/lib/systemd/system/reach-exo-node.service
install -m 0644 root/usr/lib/systemd/system/reach-exo-relay.service /usr/lib/systemd/system/reach-exo-relay.service
install -m 0644 root/usr/lib/sysusers.d/reach-exo.conf /usr/lib/sysusers.d/reach-exo.conf
install -m 0644 root/usr/lib/tmpfiles.d/reach-exo.conf /usr/lib/tmpfiles.d/reach-exo.conf
systemd-sysusers /usr/lib/sysusers.d/reach-exo.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/reach-exo.conf
account_marker=/var/lib/reach-exo/.bundle-created-account
printf 'reach-exo-lifecycle/0.1.0\nuid=%s\ngid=%s\n' "$(id -u reach-exo)" "$(id -g reach-exo)" > "$account_marker"
chown root:root "$account_marker"
chmod 0600 "$account_marker"
chown -R root:root /opt/reach-exo
chmod -R a-w /opt/reach-exo
systemctl daemon-reload

if systemctl is-enabled reach-exo-node.service >/dev/null 2>&1 || systemctl is-active reach-exo-node.service >/dev/null 2>&1 || systemctl is-active reach-exo-relay.service >/dev/null 2>&1; then
  echo "inert-install invariant failed" >&2
  exit 1
fi
echo "installed inert; configure /etc/reach-exo and explicitly enable/start"
