#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo 'usage: build-linux-connector.sh ABSOLUTE_OUTPUT_DIRECTORY' >&2; exit 2; }
output=$1
case "$output" in /*) ;; *) echo 'output directory must be absolute' >&2; exit 2 ;; esac
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
[ "$(GOTOOLCHAIN=local go env GOVERSION)" = go1.26.5 ] || { echo 'Go 1.26.5 is required' >&2; exit 1; }
mkdir -p "$output"
chmod 0700 "$output"
cd "$root"
env GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "$output/reach-exo-connector" ./cmd/reach-exo-connector-linux
chmod 0755 "$output/reach-exo-connector"
go_root=$(GOTOOLCHAIN=local go env GOROOT)
python3 - "$go_root" "$output/GO-NOTICES" <<'PY'
from pathlib import Path
import shutil,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
files=[root/'LICENSE']
if (root/'PATENTS').is_file():files.append(root/'PATENTS')
files.extend(p for p in (root/'src/vendor').rglob('*') if p.is_file() and p.name in ('LICENSE','NOTICE','PATENTS','COPYING'))
assert files[0].is_file(),'Go license is unavailable'
for p in files:
 target=out/p.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target);target.chmod(0o644)
PY
(cd "$output" && shasum -a 256 reach-exo-connector) > "$output/BINARY.sha256"
