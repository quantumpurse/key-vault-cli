#!/usr/bin/env bash
# Build and package the QPV2 GUI app for Linux.
#
# Mirrors the build-gui-linux release job: builds the GUI, the vendored
# ckb-light-client and ckb node, and pinentry-gtk-2, then stages them
# into a folder (plus a .tar.gz) under target/{debug,release}/. The
# .desktop entry and icon are included so a launcher can show the app
# once installed (see assets/icon/org.quantumpurse.wallet.desktop).
#
# Prerequisites:
#   - Rust toolchain (rustup).
#   - Build deps: gettext libgtk2.0-dev libdbus-1-dev libtss2-dev libudev-dev
#   - Submodules: git submodule update --init --recursive
#
# Usage:
#   ./crates/qpv2-gui/scripts/bundle-linux.sh [--release]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUI_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(cd "$GUI_DIR/../.." && pwd)"

source "$SCRIPT_DIR/config.sh"
cd "$PROJECT_ROOT"

# Parse arguments.
BUILD_TYPE="debug"
CARGO_FLAGS=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		--release) BUILD_TYPE="release"; CARGO_FLAGS="--release"; shift ;;
		*)
			echo "Unknown argument: $1"
			echo "Usage: $0 [--release]"
			exit 1
			;;
	esac
done

TARGET_DIR="$PROJECT_ROOT/target/$BUILD_TYPE"
PKG_NAME="qpv2-gui-linux-$(uname -m)"
PKG_DIR="$TARGET_DIR/$PKG_NAME"

# ── Build pinentry-gtk-2 (the default password dialog; always bundled) ──
PINENTRY_BIN="$PROJECT_ROOT/vendor/pinentry-build/$(uname -s)-$(uname -m)/pinentry-gtk-2"
if [ -f "$PINENTRY_BIN" ]; then
	echo "==> pinentry-gtk-2 already built: $PINENTRY_BIN"
else
	echo "==> Building pinentry-gtk-2..."
	"$PROJECT_ROOT/vendor/build-pinentry.sh"
	if [ ! -f "$PINENTRY_BIN" ]; then
		echo "ERROR: pinentry-gtk-2 not found at $PINENTRY_BIN"
		exit 1
	fi
fi

# ── Build binaries ────────────────────────────────────────────────
echo "==> Building $BINARY_NAME ($BUILD_TYPE)..."
cargo build -p qpv2-gui $CARGO_FLAGS

echo "==> Building ckb-light-client ($BUILD_TYPE)..."
cargo build -p ckb-light-client $CARGO_FLAGS \
	--manifest-path "$PROJECT_ROOT/vendor/ckb-light-client/Cargo.toml"

echo "==> Building ckb ($BUILD_TYPE)..."
cargo build -p ckb $CARGO_FLAGS \
	--manifest-path "$PROJECT_ROOT/vendor/ckb/Cargo.toml"

LIGHT_CLIENT_BIN="$PROJECT_ROOT/vendor/ckb-light-client/target/$BUILD_TYPE/ckb-light-client"
FULL_NODE_BIN="$PROJECT_ROOT/vendor/ckb/target/$BUILD_TYPE/ckb"
for bin in "$TARGET_DIR/$BINARY_NAME" "$LIGHT_CLIENT_BIN" "$FULL_NODE_BIN"; do
	if [ ! -f "$bin" ]; then
		echo "ERROR: expected binary not found: $bin"
		exit 1
	fi
done

# ── Stage the package folder ──────────────────────────────────────
echo "==> Packaging $PKG_DIR..."
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

cp "$TARGET_DIR/$BINARY_NAME" "$PKG_DIR/"
cp "$LIGHT_CLIENT_BIN" "$PKG_DIR/"
cp "$FULL_NODE_BIN" "$PKG_DIR/"
cp "$PINENTRY_BIN" "$PKG_DIR/"

# Launcher entry + themeable icon (install into ~/.local/share to use).
cp "$PROJECT_ROOT/assets/icon/$BUNDLE_ID.desktop" "$PKG_DIR/" 2>/dev/null \
	|| echo "    (note: $BUNDLE_ID.desktop not found — skipping)"
cp "$PROJECT_ROOT/assets/icon/icon-256.png" "$PKG_DIR/$BUNDLE_ID.png" 2>/dev/null \
	|| echo "    (note: icon-256.png not found — skipping)"

# Strip ELF binaries on release builds.
if [ "$BUILD_TYPE" = "release" ] && command -v strip >/dev/null 2>&1; then
	strip "$PKG_DIR/$BINARY_NAME" "$PKG_DIR/ckb-light-client" "$PKG_DIR/ckb" "$PKG_DIR/pinentry-gtk-2" 2>/dev/null || true
fi

# ── Tarball ───────────────────────────────────────────────────────
( cd "$TARGET_DIR" && tar -czf "$PKG_NAME.tar.gz" "$PKG_NAME" )

echo ""
echo "==> Done: $PKG_DIR"
echo "    Archive: $TARGET_DIR/$PKG_NAME.tar.gz"
