#!/bin/sh
set -eu

# DEVELOPMENT-ONLY: this convenience package is not the deterministic Reach
# product release. Release payloads and provenance are assembled and verified
# by Tools/ReleasePackage from a sealed dependency depot.

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT-DIRECTORY (development package only)" >&2
    exit 64
fi

echo "warning: building a development-only helper package; not a Reach release artifact" >&2

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT_DIR=$1
WORK_DIR=$(/usr/bin/mktemp -d /private/tmp/reach-mesh-package.XXXXXX)
cleanup() {
    # Go deliberately makes module-cache entries read-only. Restore only this
    # mktemp-owned tree to user-writable before removing it; otherwise a
    # successful package build exits nonzero and strands the cache.
    /bin/chmod -R u+w "$WORK_DIR" 2>/dev/null || true
    /bin/rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

/bin/mkdir -p "$OUTPUT_DIR"
/bin/mkdir -p "$WORK_DIR/root/Library/PrivilegedHelperTools"
/bin/mkdir -p "$WORK_DIR/root/Library/LaunchDaemons"
/bin/mkdir -p "$WORK_DIR/component"
/bin/mkdir -p "$WORK_DIR/cache/modules" "$WORK_DIR/cache/build" "$WORK_DIR/cache/path"

/usr/bin/env \
    GOMODCACHE="$WORK_DIR/cache/modules" \
    GOCACHE="$WORK_DIR/cache/build" \
    GOPATH="$WORK_DIR/cache/path" \
    /opt/homebrew/bin/go build \
    -mod=readonly \
    -trimpath \
    -o "$WORK_DIR/reach-meshd" \
    "$SOURCE_DIR/cmd/reach-meshd"

/usr/bin/codesign --force --sign - --timestamp=none --identifier systems.reach.meshd "$WORK_DIR/reach-meshd"
/usr/bin/codesign --verify --strict "$WORK_DIR/reach-meshd"
/usr/bin/install -m 0555 "$WORK_DIR/reach-meshd" "$WORK_DIR/root/Library/PrivilegedHelperTools/systems.reach.meshd"
/usr/bin/install -m 0644 "$SOURCE_DIR/package/systems.reach.meshd.plist" "$WORK_DIR/root/Library/LaunchDaemons/systems.reach.meshd.plist"
/usr/bin/plutil -lint "$WORK_DIR/root/Library/LaunchDaemons/systems.reach.meshd.plist"

(
    cd "$WORK_DIR/root"
    /usr/bin/tar \
        --format cpio \
        --no-recursion \
        --no-xattrs \
        --no-acls \
        --uid 0 \
        --gid 0 \
        --uname root \
        --gname wheel \
        -cf "$WORK_DIR/Payload.raw" \
        . \
        ./Library \
        ./Library/PrivilegedHelperTools \
        ./Library/PrivilegedHelperTools/systems.reach.meshd \
        ./Library/LaunchDaemons \
        ./Library/LaunchDaemons/systems.reach.meshd.plist
)
/usr/bin/gzip -9 -n "$WORK_DIR/Payload.raw"
/bin/mv "$WORK_DIR/Payload.raw.gz" "$WORK_DIR/component/Payload"

HELPER_CKSUM=$(/usr/bin/cksum "$WORK_DIR/root/Library/PrivilegedHelperTools/systems.reach.meshd")
HELPER_CRC=$(printf '%s\n' "$HELPER_CKSUM" | /usr/bin/awk '{print $1}')
HELPER_SIZE=$(printf '%s\n' "$HELPER_CKSUM" | /usr/bin/awk '{print $2}')
PLIST_CKSUM=$(/usr/bin/cksum "$WORK_DIR/root/Library/LaunchDaemons/systems.reach.meshd.plist")
PLIST_CRC=$(printf '%s\n' "$PLIST_CKSUM" | /usr/bin/awk '{print $1}')
PLIST_SIZE=$(printf '%s\n' "$PLIST_CKSUM" | /usr/bin/awk '{print $2}')
INSTALL_KB=$(( (HELPER_SIZE + PLIST_SIZE + 1023) / 1024 ))

/usr/bin/printf '.\t40755\t0/0\n' > "$WORK_DIR/BomInput"
/usr/bin/printf './Library\t40755\t0/0\n' >> "$WORK_DIR/BomInput"
/usr/bin/printf './Library/LaunchDaemons\t40755\t0/0\n' >> "$WORK_DIR/BomInput"
/usr/bin/printf './Library/LaunchDaemons/systems.reach.meshd.plist\t100644\t0/0\t%s\t%s\n' "$PLIST_SIZE" "$PLIST_CRC" >> "$WORK_DIR/BomInput"
/usr/bin/printf './Library/PrivilegedHelperTools\t40755\t0/0\n' >> "$WORK_DIR/BomInput"
/usr/bin/printf './Library/PrivilegedHelperTools/systems.reach.meshd\t100555\t0/0\t%s\t%s\n' "$HELPER_SIZE" "$HELPER_CRC" >> "$WORK_DIR/BomInput"
/usr/bin/mkbom -i "$WORK_DIR/BomInput" "$WORK_DIR/component/Bom"

/usr/bin/printf '%s\n' \
    '<?xml version="1.0" encoding="utf-8"?>' \
    '<pkg-info overwrite-permissions="true" relocatable="false" identifier="systems.reach.meshd" postinstall-action="none" version="1.0.0" format-version="2" generator-version="Reach" auth="root">' \
    "    <payload numberOfFiles=\"6\" installKBytes=\"$INSTALL_KB\"/>" \
    '    <bundle-version/>' \
    '    <upgrade-bundle/>' \
    '    <update-bundle/>' \
    '    <atomic-update-bundle/>' \
    '    <strict-identifier/>' \
    '    <relocate/>' \
    '</pkg-info>' \
    > "$WORK_DIR/component/PackageInfo"

PACKAGE="$OUTPUT_DIR/systems.reach.meshd.pkg"
(
    cd "$WORK_DIR/component"
    /usr/bin/xar \
        -cf "$PACKAGE" \
        --distribution \
        --no-compress '^Payload$' \
        Bom Payload PackageInfo
)

/usr/bin/printf '%s\n' \
    '.' \
    './Library' \
    './Library/PrivilegedHelperTools' \
    './Library/PrivilegedHelperTools/systems.reach.meshd' \
    './Library/LaunchDaemons' \
    './Library/LaunchDaemons/systems.reach.meshd.plist' \
    > "$WORK_DIR/expected-payload"
/usr/sbin/pkgutil --payload-files "$PACKAGE" > "$WORK_DIR/actual-payload"
/usr/bin/diff -u "$WORK_DIR/expected-payload" "$WORK_DIR/actual-payload"

/usr/bin/install -m 0555 "$WORK_DIR/root/Library/PrivilegedHelperTools/systems.reach.meshd" "$OUTPUT_DIR/reach-meshd"
/usr/bin/install -m 0644 "$WORK_DIR/root/Library/LaunchDaemons/systems.reach.meshd.plist" "$OUTPUT_DIR/systems.reach.meshd.plist"
(
    cd "$OUTPUT_DIR"
    /usr/bin/shasum -a 256 reach-meshd systems.reach.meshd.plist systems.reach.meshd.pkg > systems.reach.meshd.sha256
)

echo "built $PACKAGE"
