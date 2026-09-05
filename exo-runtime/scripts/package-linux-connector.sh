#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo 'usage: package-linux-connector.sh ABSOLUTE_BUILD_DIRECTORY ABSOLUTE_OUTPUT_DIRECTORY' >&2; exit 2; }
binary_dir=$1
output=$2
for path in "$binary_dir" "$output"; do case "$path" in /*) ;; *) echo 'paths must be absolute' >&2; exit 2 ;; esac; done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
python3 - "$output" "$root/.." <<'CHECK_OUTPUT'
from pathlib import Path
import sys
output=Path(sys.argv[1]).resolve()
checkout=Path(sys.argv[2]).resolve()
if output.is_relative_to(checkout):
    sys.exit('generated output must be outside the checkout')
CHECK_OUTPUT
command -v dpkg-deb >/dev/null
python3 - "$binary_dir/reach-exo-connector" "$binary_dir/GO-NOTICES/LICENSE" <<'PY'
from pathlib import Path
import struct,sys
header=Path(sys.argv[1]).read_bytes()[:64]
assert header[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',header,18)[0]==183,'binary must be Linux ELF64 arm64'
assert Path(sys.argv[2]).is_file(),'Go notices are required'
PY
mkdir -p "$output"
chmod 0700 "$output"
stage=$(mktemp -d "$output/.connector-package.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
cp -R "$root/Linux/connector/package/." "$stage/"
mkdir -p "$stage/usr/lib/reach-exo-connector" "$stage/usr/share/doc/reach-exo-connector/go-notices"
cp "$binary_dir/reach-exo-connector" "$stage/usr/lib/reach-exo-connector/"
cp -R "$binary_dir/GO-NOTICES/." "$stage/usr/share/doc/reach-exo-connector/go-notices/"
cp "$root/../LICENSE" "$stage/usr/share/doc/reach-exo-connector/copyright"
cp "$root/Linux/connector/README.md" "$stage/usr/share/doc/reach-exo-connector/README.md"
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm" "$stage/usr/lib/reach-exo-connector/reach-exo-connector"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH
dpkg-deb --root-owner-group --build "$stage" "$output/reach-exo-connector_0.1.0_arm64.deb"
(cd "$output" && sha256sum reach-exo-connector_0.1.0_arm64.deb) > "$output/PACKAGE.sha256"
