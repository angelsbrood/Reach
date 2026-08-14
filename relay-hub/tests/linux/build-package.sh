#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: build-package.sh <source-root> <binary> <version> <architecture> <output.deb>" >&2
    exit 2
fi

source_root=$1
binary=$2
version=$3
architecture=$4
output=$5
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set}"

case "$version" in
    *[!0-9A-Za-z.+~:-]*|'') echo "invalid version" >&2; exit 2 ;;
esac
case "$architecture" in
    arm64|amd64) ;;
    *) echo "invalid architecture" >&2; exit 2 ;;
esac

for file in \
    "$binary" \
    "$source_root/package/reach-relay-hub.service" \
    "$source_root/package/reach-relay-hub.sysusers" \
    "$source_root/package/reach-relay-hub.tmpfiles" \
    "$source_root/package/route-inventory.md" \
    "$source_root/LICENSE" \
    "$source_root/NOTICE.md" \
    "$source_root/THIRD_PARTY_LICENSES.md"; do
    test -f "$file" || { echo "missing package input" >&2; exit 1; }
done

root=$(mktemp -d)
cleanup() { rm -rf "$root"; }
trap cleanup EXIT HUP INT TERM
chmod 0755 "$root"

install -D -m 0555 "$binary" "$root/usr/lib/reach-relay-hub/reach-relay-hub"
install -D -m 0644 "$source_root/package/reach-relay-hub.service" "$root/usr/lib/systemd/system/reach-relay-hub.service"
install -D -m 0644 "$source_root/package/reach-relay-hub.sysusers" "$root/usr/lib/sysusers.d/reach-relay-hub.conf"
install -D -m 0644 "$source_root/package/reach-relay-hub.tmpfiles" "$root/usr/lib/tmpfiles.d/reach-relay-hub.conf"
install -D -m 0444 "$source_root/LICENSE" "$root/usr/share/licenses/reach-relay-hub/LICENSE"
install -D -m 0444 "$source_root/NOTICE.md" "$root/usr/share/doc/reach-relay-hub/NOTICE.md"
install -D -m 0444 "$source_root/THIRD_PARTY_LICENSES.md" "$root/usr/share/doc/reach-relay-hub/THIRD_PARTY_LICENSES.md"
install -D -m 0444 "$source_root/package/route-inventory.md" "$root/usr/share/doc/reach-relay-hub/route-inventory.md"

mkdir -p "$root/DEBIAN"
chmod 0755 "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: reach-relay-hub
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Maintainer: Reach Project <noreply@invalid>
Description: Reach reference relay hub
 Scriptless, unprivileged WireGuard relay-hub runtime.
EOF
chmod 0644 "$root/DEBIAN/control"

find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$(dirname "$output")"
temporary="$output.tmp.$$"
rm -f "$temporary"
dpkg-deb --root-owner-group --build "$root" "$temporary" >/dev/null
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
cleanup
