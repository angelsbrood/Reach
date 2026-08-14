#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: host-capacity-addendum.sh <lima-instance> <absolute-guest-runner>" >&2
    exit 2
fi

instance=$1
guest_runner=$2
limactl=/opt/homebrew/bin/limactl
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
local_guest_runner=${script_directory}/guest-acceptance.sh
guest_stage=/tmp/reach-relay-guest-acceptance.sh

case "$guest_runner" in
    /*) ;;
    *) echo "guest runner must be absolute" >&2; exit 2 ;;
esac

test -f "$local_guest_runner" || {
    echo "local guest runner is missing: $local_guest_runner" >&2
    exit 2
}

local_hash=$(/usr/bin/shasum -a 256 "$local_guest_runner" | /usr/bin/awk '{print $1}')
"$limactl" copy "$local_guest_runner" "${instance}:${guest_stage}"
"$limactl" shell "$instance" -- /usr/bin/sudo /bin/mkdir -p "$(dirname -- "$guest_runner")"
"$limactl" shell "$instance" -- /usr/bin/sudo /usr/bin/install -m 0755 "$guest_stage" "$guest_runner"
guest_hash=$("$limactl" shell "$instance" -- /usr/bin/sha256sum "$guest_runner" | /usr/bin/awk '{print $1}')
if [ "$guest_hash" != "$local_hash" ]; then
    echo "guest runner hash mismatch" >&2
    exit 1
fi

"$limactl" shell "$instance" -- /usr/bin/sudo "$guest_runner" offline
"$limactl" shell "$instance" -- /usr/bin/sudo "$guest_runner" capacity-addendum
