#!/bin/sh
# Rebuild docs/brand marks, wordmarks, lockups, and public rasters from the Brand Mark.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

command -v resvg >/dev/null 2>&1 || {
    echo "resvg is required to rasterize Brand Kit assets" >&2
    exit 1
}

python3 "$ROOT/packaging/brand/render_kit.py"
