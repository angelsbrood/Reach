#!/bin/sh
set -eu
umask 022

usage() {
  echo "usage: materialize.sh MODE SOURCE DERIVATIVE NORMALIZED_JSON MODEL_ROOT UV_CACHE PYTHON_ROOT BINARIES OUTPUT" >&2
  exit 2
}

[ "$#" -eq 9 ] || usage
mode=$1
source_root=$2
derivative=$3
normalized=$4
model_root=$5
uv_cache=$6
python_root=$7
binaries=$8
output=$9

[ "$mode" = connected ] || [ "$mode" = offline ] || usage
for path in "$source_root" "$derivative" "$normalized" "$model_root" "$uv_cache" "$python_root" "$binaries" "$output"; do
  case "$path" in /*) ;; *) echo "all paths must be absolute: $path" >&2; exit 2 ;; esac
done
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] || { echo "materialization requires Linux/arm64" >&2; exit 1; }
[ ! -e "$output" ] || { echo "output already exists" >&2; exit 1; }
[ "$(uv --version)" = "uv 0.8.22" ] || { echo "uv 0.8.22 is required" >&2; exit 1; }
[ "$($python_root/bin/python3.13 --version)" = "Python 3.13.7" ] || { echo "Python 3.13.7 is required" >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runtime_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
work="${TMPDIR:-/tmp}/reach-exo-materialize-fixed"
[ ! -e "$work" ] || { echo "fixed materialization workspace is busy" >&2; exit 1; }
mkdir -m 0700 "$work"
cleanup() {
  case "$work" in "${TMPDIR:-/tmp}"/reach-exo-materialize-fixed) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT HUP INT TERM

[ "$(git -C "$source_root" rev-parse HEAD)" = 21a54c5ea0230a3bec1e1a786d200126c7e34ec6 ]
[ "$(git -C "$source_root" rev-parse 'HEAD^{tree}')" = ff0204b2a02506a15cda8abbdcbed25663c89403 ]
[ -z "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)" ]
printf '%s  %s\n' 35b3e83937d745e1a6393932015a58b9c98046fcbe4b205631a617e66e5517aa "$derivative/pyproject.toml" | sha256sum -c -
printf '%s  %s\n' 564c3c0c8b00a5c463f7d3d1d9d89750e5dd1fd48ec014341758393626fabd3d "$derivative/uv.lock" | sha256sum -c -
printf '%s  %s\n' 6c3094908c689789ac02b9bd126d05b6fe2f6baa74502a05446899a775266bb7 "$normalized" | sha256sum -c -
printf '%s  %s\n' b8bbc65028022f822f9234e04137470d7c6b56fa5bebe32285b7217e47d21629 "$runtime_root/authority/model.MANIFEST.sha256" | sha256sum -c -
(cd "$runtime_root/licenses" && sha256sum -c MANIFEST.sha256)

model_dir="$model_root/mlx-community--Qwen3-0.6B-4bit"
[ -d "$model_dir" ] || { echo "selected model directory absent" >&2; exit 1; }
(cd "$model_dir" && sha256sum -c "$runtime_root/authority/model.MANIFEST.sha256")
[ "$(find "$model_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" -eq 11 ]
[ "$(find "$model_dir" -mindepth 1 -maxdepth 1 ! -type f | wc -l | tr -d ' ')" -eq 0 ]

stage="$work/stage"
provider="$stage/root/opt/reach-exo/provider"
mkdir -p "$provider" "$stage/root/opt/reach-exo/bin" "$stage/root/opt/reach-exo/host" "$stage/root/opt/reach-exo/share/licenses" "$stage/root/usr/lib/systemd/system" "$stage/root/usr/lib/sysusers.d" "$stage/root/usr/lib/tmpfiles.d" "$stage/scripts" "$stage/schema" "$stage/metadata"
cp -a "$derivative/." "$provider/"
rm -rf -- "$provider/.git" "$provider/.venv"
rm -rf -- "$provider/python"
cp -a "$python_root" "$provider/python"
cp "$binaries/reach-exo-node" "$stage/root/opt/reach-exo/bin/reach-exo-node"
cp "$binaries/reach-exo-package" "$stage/root/opt/reach-exo/bin/reach-exo-package"
cp "$binaries/reach-exo-connector" "$stage/root/opt/reach-exo/host/reach-exo-connector-darwin-arm64"
cp "$runtime_root/authority/model.MANIFEST.sha256" "$stage/root/opt/reach-exo/share/model.MANIFEST.sha256"
cp "$runtime_root/packaging/root/usr/lib/systemd/system/reach-exo-node.service" "$stage/root/usr/lib/systemd/system/"
cp "$runtime_root/packaging/root/usr/lib/systemd/system/reach-exo-relay.service" "$stage/root/usr/lib/systemd/system/"
cp "$runtime_root/packaging/root/usr/lib/sysusers.d/reach-exo.conf" "$stage/root/usr/lib/sysusers.d/"
cp "$runtime_root/packaging/root/usr/lib/tmpfiles.d/reach-exo.conf" "$stage/root/usr/lib/tmpfiles.d/"
cp "$runtime_root/scripts/install.sh" "$runtime_root/scripts/remove.sh" "$runtime_root/scripts/purge-created-config.sh" "$runtime_root/scripts/configure-node.sh" "$runtime_root/scripts/update.sh" "$runtime_root/scripts/recover.sh" "$runtime_root/scripts/rollback.sh" "$stage/scripts/"
cp "$runtime_root/schema/node.schema.json" "$runtime_root/schema/connector.schema.json" "$stage/schema/"

chmod -R u+rwX "$provider"
sync_args="--frozen --extra mlx-cpu --no-dev --python $provider/python/bin/python3.13"
if [ "$mode" = offline ]; then
  sync_args="$sync_args --offline"
fi
(cd "$provider" && env UV_CACHE_DIR="$uv_cache" UV_LINK_MODE=copy uv sync $sync_args)

site_packages="$provider/.venv/lib/python3.13/site-packages"
miniaudio="$site_packages/_miniaudio.abi3.so"
[ -f "$miniaudio" ] || { echo "required miniaudio extension absent" >&2; exit 1; }
objcopy --strip-debug --remove-section=.note.gnu.build-id "$miniaudio"

env CARGO_NET_OFFLINE=true cargo metadata --offline --locked --format-version=1 \
  --manifest-path "$provider/rust/exo_rs/Cargo.toml" > "$work/cargo-metadata.json"
"$python_root/bin/python3.13" "$runtime_root/scripts/rust_license_inventory.py" \
  "$work/cargo-metadata.json" "$stage/root/opt/reach-exo/share/licenses/rust" "$provider/LICENSE"

find "$provider" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$provider" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$provider" -type f -exec grep -Il "$provider" {} + | while IFS= read -r text_file; do
  sed -i "s|$provider|/opt/reach-exo/provider|g" "$text_file"
done
rm -f "$provider/.venv/bin/python" "$provider/.venv/bin/python3" "$provider/.venv/bin/python3.13"
ln -s ../../python/bin/python3.13 "$provider/.venv/bin/python3.13"
ln -s python3.13 "$provider/.venv/bin/python3"
ln -s python3.13 "$provider/.venv/bin/python"

find "$provider/.venv/lib/python3.13/site-packages" -type f \
  \( -name RECORD -o -name uv_cache.json -o -name uv_build.json \) -delete
rm -rf -- "$provider/.venv/lib/python3.13/site-packages/exo_rs-0.3.0.dist-info/sboms" "$provider/target"

rm -rf -- "$provider/.github" "$provider/.idea" "$provider/.vscode" "$provider/.zed" "$provider/.typings" "$provider/app" "$provider/bench" "$provider/dashboard" "$provider/docs" "$provider/nix" "$provider/packaging" "$provider/python" "$provider/rust" "$provider/tools"
mkdir -p "$provider/dashboard"
printf '%s\n' '<!doctype html><title>Reach EXO dashboard is not published</title>' > "$provider/dashboard/index.html"
cp -a "$python_root" "$provider/python"
find "$provider/python" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$provider/python" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

for local_dist in exo-0.3.70.dist-info exo_rs-0.3.0.dist-info; do
  [ -d "$site_packages/$local_dist" ] || { echo "required local distribution metadata absent: $local_dist" >&2; exit 1; }
  mkdir -p "$site_packages/$local_dist/licenses"
  cp "$provider/LICENSE" "$site_packages/$local_dist/licenses/EXO-LICENSE"
done
lockfile_dist="$site_packages/lockfile-0.12.2.dist-info"
[ -d "$lockfile_dist" ] || { echo "required lockfile distribution metadata absent" >&2; exit 1; }
mkdir -p "$lockfile_dist/licenses"
cp "$runtime_root/licenses/lockfile-0.12.2/LICENSE" "$lockfile_dist/licenses/LICENSE"
for identity in loguru-0.7.3 mflux-0.17.5 sentencepiece-0.2.1 tokenizers-0.22.2; do
  dist_name=$(printf '%s' "$identity" | sed 's/-\([^-]*\)$/-\1.dist-info/')
  dist="$site_packages/$dist_name"
  [ -d "$dist" ] || { echo "required distribution metadata absent: $dist_name" >&2; exit 1; }
  mkdir -p "$dist/licenses"
  cp "$runtime_root/licenses/$identity/"* "$dist/licenses/"
done
"$python_root/bin/python3.13" "$runtime_root/scripts/license_inventory.py" "$site_packages" "$stage/root/opt/reach-exo/share/licenses/python"
cp "$provider/LICENSE" "$stage/root/opt/reach-exo/share/licenses/EXO-LICENSE"
cp "$runtime_root/licenses/python-3.13.7/LICENSE" "$stage/root/opt/reach-exo/share/licenses/PYTHON-LICENSE"
cp "$binaries/GO-LICENSE" "$stage/root/opt/reach-exo/share/licenses/GO-LICENSE"

cat > "$stage/metadata/package.json" <<'EOF'
{"bundle_version":"0.2.0","architecture":"linux-arm64","exo_version":"0.3.70","exo_commit":"21a54c5ea0230a3bec1e1a786d200126c7e34ec6","exo_tree":"ff0204b2a02506a15cda8abbdcbed25663c89403","derivative_sha256":"6c3094908c689789ac02b9bd126d05b6fe2f6baa74502a05446899a775266bb7","model_id":"mlx-community/Qwen3-0.6B-4bit","model_snapshot":"73e3e38d981303bc594367cd910ea6eb48349da8","model_included":false,"install_starts_service":false,"package_generation":"reach-exo-lifecycle/0.2.0/linux-arm64/parent-0.1.0","parent_bundle_version":"0.1.0","parent_node_sha256":"e6d04335313d8949bec2362abc8701de0fe24f9547377a8d43024e8ea8bd033f","parent_connector_sha256":"53797f562dd5a8331d04b171b5b1fcb9fdb656a4f5193a68f2750b9026657e0e","parent_package_sha256":"fe3a5e334ea89f30487bba02bfbd749ad9a8c51736cda35699aedc7b1eb5e138","parent_payload_manifest_sha256":"2e8ac39eb950212dd6bb6200459ef15c16d94d88a5194556780f7e033b2a2e27","parent_metadata_sha256":"2549bb3dc7d368b7b6fd9fdb62b1c940f7166ba2c1648a56a67321e6b3a54ef4"}
EOF

find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/root/opt/reach-exo/bin/reach-exo-node" "$stage/root/opt/reach-exo/bin/reach-exo-package" "$stage/root/opt/reach-exo/host/reach-exo-connector-darwin-arm64" "$stage/scripts/install.sh" "$stage/scripts/remove.sh" "$stage/scripts/purge-created-config.sh" "$stage/scripts/configure-node.sh" "$stage/scripts/update.sh" "$stage/scripts/recover.sh" "$stage/scripts/rollback.sh"
chmod 0555 "$stage/root/opt/reach-exo/provider/python/bin/python3.13"
chmod 0555 "$stage/root/opt/reach-exo/provider/.venv/bin/exo"
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -exec touch -h -d '@0' {} +
"$python_root/bin/python3.13" "$runtime_root/scripts/payload_manifest.py" "$stage" "$stage/PAYLOAD-MANIFEST.tsv"
(cd "$stage" && find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256)
chmod 0644 "$stage/MANIFEST.sha256"
find "$stage" -exec touch -h -d '@0' {} +

mkdir -p "$output"
chmod 700 "$output"
(cd "$stage" && tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - . | gzip -n > "$output/reach-exo-lifecycle-0.2.0-linux-arm64.tar.gz")
cp "$stage/PAYLOAD-MANIFEST.tsv" "$stage/metadata/package.json" "$output/"
(cd "$output" && sha256sum reach-exo-lifecycle-0.2.0-linux-arm64.tar.gz PAYLOAD-MANIFEST.tsv package.json > OUTPUT.sha256)
