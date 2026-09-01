#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
pycache="${TMPDIR:-/tmp}/reach-exo-static-pyc.$$"
mkdir -m 0700 "$pycache"
trap 'rm -rf -- "$pycache"' EXIT HUP INT TERM

for script in "$root"/scripts/*.sh; do
  sh -n "$script"
done
PYTHONPYCACHEPREFIX="$pycache" python3 -m py_compile "$root/scripts/license_inventory.py" "$root/scripts/payload_manifest.py" "$root/scripts/rust_license_inventory.py"

manifest_fixture="$pycache/payload-fixture"
manifest_output="$pycache/payload-manifest.tsv"
mkdir -p "$manifest_fixture/real-directory"
printf '%s\n' fixture > "$manifest_fixture/file-target"
ln -s real-directory "$manifest_fixture/directory-link"
ln -s file-target "$manifest_fixture/file-link"
python3 "$root/scripts/payload_manifest.py" "$manifest_fixture" "$manifest_output"
awk -F '\t' '$1 == "symlink" && $3 == "14" && $4 == "ef243382009b421c67b3707a210653ffbe3bc8f8b1a7ca275ebd135b904892b5" && $5 == "directory-link" { found = 1 } END { exit !found }' "$manifest_output"
awk -F '\t' '$1 == "symlink" && $3 == "11" && $4 == "37dddc834a9c265596a7b55c289df7fb9db11d3c231f4de26ca1dfce048e7521" && $5 == "file-link" { found = 1 } END { exit !found }' "$manifest_output"
[ "$(wc -l < "$manifest_output" | tr -d ' ')" -eq 4 ]

python3 -m json.tool "$root/schema/node.schema.json" >/dev/null
python3 -m json.tool "$root/schema/connector.schema.json" >/dev/null
python3 -m json.tool "$root/examples/coordinator.json" >/dev/null
python3 -m json.tool "$root/examples/worker.json" >/dev/null
python3 -m json.tool "$root/examples/connector.json" >/dev/null

grep -F 'b8bbc65028022f822f9234e04137470d7c6b56fa5bebe32285b7217e47d21629' "$root/scripts/materialize.sh" >/dev/null
grep -F '6c3094908c689789ac02b9bd126d05b6fe2f6baa74502a05446899a775266bb7' "$root/scripts/materialize.sh" >/dev/null
grep -F '"bundle_version":"0.2.0"' "$root/scripts/materialize.sh" >/dev/null
grep -F '"parent_bundle_version":"0.1.0"' "$root/scripts/materialize.sh" >/dev/null
grep -F 'fe3a5e334ea89f30487bba02bfbd749ad9a8c51736cda35699aedc7b1eb5e138' "$root/scripts/materialize.sh" "$root/internal/authority/authority.go" >/dev/null
grep -F 'reach-exo-lifecycle-0.2.0-linux-arm64.tar.gz' "$root/scripts/materialize.sh" >/dev/null
grep -F 'reach-exo-package' "$root/scripts/build-binaries.sh" "$root/scripts/materialize.sh" >/dev/null
grep -F 'systemctl is-enabled reach-exo-node.service' "$root/scripts/install.sh" >/dev/null
grep -F 'systemctl is-active reach-exo-node.service' "$root/scripts/install.sh" >/dev/null
grep -F 'pre-existing reach-exo account or group refuses package ownership' "$root/scripts/install.sh" >/dev/null
grep -F '.bundle-created-account' "$root/scripts/install.sh" "$root/scripts/remove.sh" >/dev/null
grep -F 'VerifyServiceRuntimeAuthority(packageupdate.DefaultPaths())' "$root/internal/lifecycle/node.go" >/dev/null
grep -F 'chmod 0600 "$account_marker"' "$root/scripts/install.sh" >/dev/null
grep -F "0:0:600:1" "$root/scripts/remove.sh" >/dev/null
grep -F 'package account marker absent or ambiguous' "$root/scripts/remove.sh" >/dev/null
grep -F 'ExecStartPre=+/opt/reach-exo/bin/reach-exo-package verify-installed' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'reach-exo-package verify-installed' "$root/scripts/install.sh" >/dev/null
for locked_script in configure-node.sh purge-created-config.sh remove.sh; do
  grep -F 'flock -n /run/lock/reach-exo-package.lock' "$root/scripts/$locked_script" >/dev/null
  grep -F 'assert-no-transaction' "$root/scripts/$locked_script" >/dev/null
done
grep -F 'PackageGeneration' "$root/internal/control/protocol.go" "$root/internal/status/status.go" "$root/internal/lifecycle/node.go" >/dev/null
grep -F 'ExecStartPre=/usr/bin/false' "$root/internal/packageupdate/transaction.go" >/dev/null
grep -F 'syscall.Flock' "$root/internal/packageupdate/transaction.go" >/dev/null
grep -F 'ParentPackageSHA256' "$root/internal/packageupdate/artifact.go" >/dev/null
grep -F 'candidate-payload-sha256' "$root/cmd/reach-exo-package/main.go" >/dev/null
grep -F 'candidate-metadata-sha256' "$root/cmd/reach-exo-package/main.go" >/dev/null
grep -F 'BindsTo=nftables.service' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'ConditionPathExists=/etc/reach-exo/node.json' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'BindsTo=reach-exo-relay.service' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'PartOf=reach-exo-node.service' "$root/packaging/root/usr/lib/systemd/system/reach-exo-relay.service" >/dev/null
grep -F 'systemctl --no-block stop reach-exo-relay.service' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'neighbor-apply /etc/reach-exo/node.json' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null
grep -F 'neighbor-remove /etc/reach-exo/node.json' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" "$root/scripts/remove.sh" >/dev/null
grep -F '[ -e /run/reach-exo-peer-neighbor.json ]' "$root/scripts/remove.sh" >/dev/null
grep -F 'missing prerequisite: $command' "$root/scripts/install.sh" >/dev/null
grep -F 'RestrictAddressFamilies=AF_PACKET AF_NETLINK' "$root/packaging/root/usr/lib/systemd/system/reach-exo-relay.service" >/dev/null
grep -F 'CapabilityBoundingSet=CAP_NET_RAW' "$root/packaging/root/usr/lib/systemd/system/reach-exo-relay.service" >/dev/null
grep -F 'AmbientCapabilities=CAP_NET_RAW' "$root/packaging/root/usr/lib/systemd/system/reach-exo-relay.service" >/dev/null
grep -F 'systemctl stop reach-exo-relay.service' "$root/scripts/remove.sh" >/dev/null
grep -F 'chmod 0555 "$stage/root/opt/reach-exo/provider/python/bin/python3.13"' "$root/scripts/materialize.sh" >/dev/null
grep -F 'chmod 0555 "$stage/root/opt/reach-exo/provider/.venv/bin/exo"' "$root/scripts/materialize.sh" >/dev/null
grep -F 'objcopy --strip-debug --remove-section=.note.gnu.build-id "$miniaudio"' "$root/scripts/materialize.sh" >/dev/null
grep -F 'find "$provider/python" -type d -name __pycache__ -prune -exec rm -rf -- {} +' "$root/scripts/materialize.sh" >/dev/null
grep -F 'umask 022' "$root/scripts/materialize.sh" >/dev/null
grep -F 'chmod 0644 "$stage/MANIFEST.sha256"' "$root/scripts/materialize.sh" >/dev/null
if grep -F 'ConditionPathIsRegular=' "$root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" >/dev/null; then
  echo "unit uses unsupported regular-file condition" >&2
  exit 1
fi
if grep -E 'systemctl (enable|start|restart)' "$root/scripts/install.sh" >/dev/null; then
  echo "install script activates the service" >&2
  exit 1
fi
grep -F 'preserved /etc/reach-exo and /srv/reach-exo-models' "$root/scripts/remove.sh" >/dev/null
grep -F '0:0:600:1' "$root/scripts/purge-created-config.sh" >/dev/null
grep -F 'rm -f -- /etc/reach-exo/node.json "$marker"' "$root/scripts/purge-created-config.sh" >/dev/null
if grep -E 'rm .*(/etc/reach-exo/tls|/srv/reach-exo-models)' "$root/scripts/remove.sh" "$root/scripts/purge-created-config.sh" >/dev/null; then
  echo "removal script targets operator-owned TLS or model bytes" >&2
  exit 1
fi

if find "$root" -type f \( -name '*.whl' -o -name '*.safetensors' -o -name '*.img' -o -name '*.qcow2' -o -name '*.tar.gz' -o -name '*.pem' -o -name '*-key.*' \) | grep . >/dev/null; then
  echo "repository subtree contains a generated payload, model, image, or credential" >&2
  exit 1
fi
if find "$root" -type l | grep . >/dev/null; then
  echo "repository subtree contains symlinks" >&2
  exit 1
fi

printf '%s\n' 'static lifecycle/package checks: 62 passed'
