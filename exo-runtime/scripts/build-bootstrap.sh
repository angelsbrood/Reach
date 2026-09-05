#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo 'usage: build-bootstrap.sh (darwin|linux) ABSOLUTE_OUTPUT_DIRECTORY' >&2; exit 2; }
target=$1
case "$target" in darwin|linux) ;; *) echo 'target must be darwin or linux (arm64)' >&2; exit 2 ;; esac
output=$2
case "$output" in /*) ;; *) echo 'output directory must be absolute' >&2; exit 2 ;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
python3 - "$output" "$root/.." <<'CHECK_OUTPUT'
from pathlib import Path
import sys
if Path(sys.argv[1]).resolve().is_relative_to(Path(sys.argv[2]).resolve()):
    sys.exit('generated output must be outside the checkout')
CHECK_OUTPUT
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off CGO_ENABLED=0 GOOS="$target" GOARCH=arm64
[ "$(go env GOVERSION)" = go1.26.5 ] || { echo 'Go 1.26.5 is required' >&2; exit 1; }
mkdir -p "$output"
chmod 0700 "$output"
cd "$root"
go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "$output/reach-exo-bootstrap" ./cmd/reach-exo-bootstrap
chmod 0755 "$output/reach-exo-bootstrap"
python3 - "$root" "$output" "$target" <<'RECORD'
from pathlib import Path
import hashlib,json,shutil,subprocess,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);target=sys.argv[3]
go=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
files=[go/'LICENSE']
if (go/'PATENTS').is_file():files.append(go/'PATENTS')
files.extend(p for p in (go/'src/vendor').rglob('*') if p.is_file() and p.name in ('LICENSE','NOTICE','PATENTS','COPYING'))
assert files[0].is_file(),'Go license is unavailable'
for p in files:
 dest=out/'GO-NOTICES'/p.relative_to(go);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);dest.chmod(0o644)
shutil.copyfile(root.parent/'LICENSE',out/'LICENSE');(out/'LICENSE').chmod(0o644)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
raw=subprocess.check_output(['go','list','-deps','-json','./cmd/reach-exo-bootstrap'],text=True)
decoder=json.JSONDecoder();inputs={}
while raw.strip():
 package,end=decoder.raw_decode(raw.lstrip());raw=raw.lstrip()[end:]
 if package.get('Standard'):continue
 for name in package.get('GoFiles',[])+package.get('EmbedFiles',[]):
  p=Path(package['Dir'])/name;inputs[str(p.relative_to(root))]=sha(p)
for name in ['go.mod','scripts/build-bootstrap.sh']:inputs[name]=sha(root/name)
inputs['../LICENSE']=sha(root.parent/'LICENSE')
binary=sha(out/'reach-exo-bootstrap')
record={'target':target+'/arm64','go_version':'go1.26.5','cgo_enabled':False,'binary_sha256':binary,'source_sha256':dict(sorted(inputs.items()))}
(out/'BUILD.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
(out/'BINARY.sha256').write_text(binary+'  reach-exo-bootstrap\n')
print(json.dumps({'target':record['target'],'binary_sha256':binary}))
RECORD
