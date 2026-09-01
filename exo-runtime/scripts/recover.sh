#!/bin/sh
set -eu

bundle=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$bundle/root/opt/reach-exo/bin/reach-exo-package" recover "$@"
