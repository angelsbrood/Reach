#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: build-binaries.sh OUTPUT_DIRECTORY" >&2
  exit 2
fi

output=$1
case "$output" in
  /*) ;;
  *) echo "output directory must be absolute" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
mkdir -p "$output/a" "$output/b"
chmod 700 "$output" "$output/a" "$output/b"

build_one() {
  destination=$1
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "$destination/reach-exo-node" ./cmd/reach-exo-node
  env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "$destination/reach-exo-package" ./cmd/reach-exo-package
  env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "$destination/reach-exo-connector" ./cmd/reach-exo-connector
  chmod 0755 "$destination/reach-exo-node" "$destination/reach-exo-package" "$destination/reach-exo-connector"
}

cd "$root"
build_one "$output/a"
build_one "$output/b"
cmp "$output/a/reach-exo-node" "$output/b/reach-exo-node"
cmp "$output/a/reach-exo-package" "$output/b/reach-exo-package"
cmp "$output/a/reach-exo-connector" "$output/b/reach-exo-connector"
(cd "$output/a" && shasum -a 256 reach-exo-node reach-exo-package reach-exo-connector) > "$output/BINARIES.sha256"
go_root=$(go env GOROOT)
go_license="$go_root/LICENSE"
if [ ! -f "$go_license" ]; then
  go_license=$(dirname "$go_root")/LICENSE
fi
[ -f "$go_license" ] || { echo "Go license text is unavailable" >&2; exit 1; }
cp "$go_license" "$output/GO-LICENSE"
chmod 0644 "$output/GO-LICENSE"
mv "$output/a/reach-exo-node" "$output/reach-exo-node"
mv "$output/a/reach-exo-package" "$output/reach-exo-package"
mv "$output/a/reach-exo-connector" "$output/reach-exo-connector"
rm -r "$output/a" "$output/b"
