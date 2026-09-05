#!/bin/sh
# Rasterize packaging/icons/syncplus.svg into committed hicolor PNGs.
# build-deb.sh installs those PNGs; re-run this script after editing the SVG.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SVG="$ROOT/packaging/icons/syncplus.svg"
MASTER="$ROOT/packaging/icons/hicolor/512x512/apps/syncplus.png"

command -v magick >/dev/null 2>&1 || {
    echo "ImageMagick magick is required to size Brand Mark rasters" >&2
    exit 1
}

mkdir -p "$(dirname -- "$MASTER")"

if command -v resvg >/dev/null 2>&1; then
    resvg --width 512 --height 512 "$SVG" "$MASTER"
elif command -v google-chrome >/dev/null 2>&1; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    cp "$SVG" "$work/syncplus.svg"
    cat >"$work/icon.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  html, body { margin: 0; padding: 0; background: transparent; width: 512px; height: 512px; overflow: hidden; }
  img { width: 512px; height: 512px; display: block; }
</style>
</head>
<body>
  <img src="syncplus.svg" alt="">
</body>
</html>
EOF
    google-chrome \
        --headless \
        --disable-gpu \
        --hide-scrollbars \
        --force-device-scale-factor=1 \
        --default-background-color=00000000 \
        --window-size=512,512 \
        --screenshot="$work/icon.png" \
        "file://$work/icon.html" \
        >/dev/null 2>&1
    magick "$work/icon.png" -resize 512x512 "PNG32:$MASTER"
    rm -rf "$work"
    trap - EXIT HUP INT TERM
else
    echo "resvg or google-chrome is required to rasterize the Brand Mark SVG" >&2
    exit 1
fi

for size in 16 22 24 32 48 64 128 256 512; do
    dest="$ROOT/packaging/icons/hicolor/${size}x${size}/apps/syncplus.png"
    mkdir -p "$(dirname -- "$dest")"
    magick "$MASTER" -resize "${size}x${size}" "PNG32:$dest"
done
