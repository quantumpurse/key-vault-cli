#!/usr/bin/env bash
# Regenerate Quantum Purse app-icon artifacts FROM icon.svg.
#
# The SVG is the single source of truth (dark instrument tile, #232a2d
# hairline border, cyan accent glow, qp∞ mark). This script renders the
# SVG itself — so every raster matches it exactly — then derives the
# platform formats.
#
# Renderer: qlmanage (the macOS WebKit QuickLook engine) handles nested
# <svg>, gradients and the mark faithfully. Its one quirk is that it
# flattens the transparent canvas to white, so we re-apply the icon's own
# rounded-tile shape — read straight from the SVG's <rect>, so it always
# matches the art — as the alpha channel to restore transparent corners.
# (A portable alternative if you have it: rsvg-convert -w 1024 -h 1024.)
#
# Requires macOS: qlmanage, sips, iconutil, plus ImageMagick (magick).
# Outputs: icon-1024.png, icon-512.png, icon-256.png, AppIcon.icns, icon.ico
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SVG="$DIR/icon.svg"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Tile rectangle, read from the SVG so the mask stays in lockstep with it.
read -r X Y X2 Y2 RX < <(python3 - "$SVG" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r'<rect[^>]*x="([\d.]+)"[^>]*y="([\d.]+)"[^>]*width="([\d.]+)"[^>]*height="([\d.]+)"[^>]*rx="([\d.]+)"', s)
x, y, w, h, rx = map(float, m.groups())
print(int(x), int(y), int(x + w), int(y + h), int(rx))
PY
)

# 1) Render the SVG at 1024 with WebKit.
qlmanage -t -s 1024 -o "$TMP" "$SVG" >/dev/null 2>&1
SRC="$TMP/$(basename "$SVG").png"
[ -f "$SRC" ] || { echo "ERROR: qlmanage did not render $SVG"; exit 1; }
[ "$(magick identify -format '%wx%h' "$SRC")" = "1024x1024" ] \
  || { echo "ERROR: expected a 1024x1024 render"; exit 1; }

# 2) Restore transparency by masking to the rounded tile shape.
magick -size 1024x1024 xc:black -fill white \
  -draw "roundrectangle $X,$Y,$X2,$Y2,$RX,$RX" "$TMP/mask.png"
magick "$SRC" "$TMP/mask.png" -alpha off -compose CopyOpacity -composite "$DIR/icon-1024.png"
echo "==> icon-1024.png"

# 3) Derived rasters (256 feeds the runtime ViewportBuilder::with_icon).
for s in 512 256; do
  magick "$DIR/icon-1024.png" -resize ${s}x${s} "$DIR/icon-${s}.png"
  echo "==> icon-${s}.png"
done

# 4) macOS .icns.
ICONSET="$TMP/AppIcon.iconset"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s                 "$DIR/icon-1024.png" --out "$ICONSET/icon_${s}x${s}.png"     >/dev/null
  sips -z $((s * 2)) $((s * 2)) "$DIR/icon-1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$DIR/AppIcon.icns"
echo "==> AppIcon.icns"

# 5) Windows multi-resolution .ico.
magick "$DIR/icon-1024.png" -define icon:auto-resize=16,32,48,64,128,256 "$DIR/icon.ico"
echo "==> icon.ico"

echo "Done."
