#!/usr/bin/env bash
# Build and bundle the QPV2 GUI app for macOS (unsigned).
#
# Produces target/{debug,release}/qpv2.app with all binaries and
# Info.plist. Run sign.sh afterwards for code signing.
#
# Usage:
#   ./crates/qpv2-gui/scripts/bundle-macos.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUI_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(cd "$GUI_DIR/../.." && pwd)"

source "$SCRIPT_DIR/config.sh"

# Parse arguments.
BUILD_TYPE="debug"
CARGO_FLAGS=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		--release)
			BUILD_TYPE="release"
			CARGO_FLAGS="--release"
			shift
			;;
		*)
			echo "Unknown argument: $1"
			echo "Usage: $0 [--release]"
			exit 1
			;;
	esac
done

TARGET_DIR="$PROJECT_ROOT/target/$BUILD_TYPE"
APP_BUNDLE="$TARGET_DIR/$APP_NAME.app"

# ── Build pinentry ────────────────────────────────────────────────

if [ "$BUNDLE_PINENTRY" = "true" ]; then
	PINENTRY_VENDOR="$PROJECT_ROOT/vendor/pinentry-build/$(uname -s)-$(uname -m)/pinentry-mac.app"
	PINENTRY_VENDOR_BIN="$PINENTRY_VENDOR/Contents/MacOS/pinentry-mac"
	if [ ! -f "$PINENTRY_VENDOR_BIN" ]; then
		echo "==> pinentry-mac not found, building from source..."
		"$PROJECT_ROOT/vendor/build-pinentry.sh"
		if [ ! -f "$PINENTRY_VENDOR_BIN" ]; then
			echo "ERROR: vendor/build-pinentry.sh did not produce $PINENTRY_VENDOR_BIN"
			exit 1
		fi
	fi
fi

# ── Build binaries ────────────────────────────────────────────────

echo "==> Building $BINARY_NAME ($BUILD_TYPE)..."
# Force build.rs to re-run so pinentry-mac.app is freshly staged from
# vendor/pinentry-build/. Cost: ~20s qpv2-gui recompile per release.
cargo clean -p qpv2-gui $CARGO_FLAGS
rm -rf "$TARGET_DIR/pinentry-mac.app"
cargo build -p qpv2-gui $CARGO_FLAGS

LIGHT_CLIENT_NAME="ckb-light-client"
LIGHT_CLIENT_SRC="$PROJECT_ROOT/vendor/ckb-light-client"
LIGHT_CLIENT_BIN="$LIGHT_CLIENT_SRC/target/$BUILD_TYPE/$LIGHT_CLIENT_NAME"
echo "==> Building $LIGHT_CLIENT_NAME ($BUILD_TYPE)..."
cargo build -p $LIGHT_CLIENT_NAME $CARGO_FLAGS \
    --manifest-path "$LIGHT_CLIENT_SRC/Cargo.toml"

if [ ! -f "$LIGHT_CLIENT_BIN" ]; then
    echo "ERROR: $LIGHT_CLIENT_NAME binary not found at $LIGHT_CLIENT_BIN"
    exit 1
fi

FULL_NODE_NAME="ckb"
FULL_NODE_SRC="$PROJECT_ROOT/vendor/ckb"
FULL_NODE_BIN="$FULL_NODE_SRC/target/$BUILD_TYPE/$FULL_NODE_NAME"
echo "==> Building $FULL_NODE_NAME ($BUILD_TYPE)..."
cargo build -p $FULL_NODE_NAME $CARGO_FLAGS \
    --manifest-path "$FULL_NODE_SRC/Cargo.toml"

if [ ! -f "$FULL_NODE_BIN" ]; then
    echo "ERROR: $FULL_NODE_NAME binary not found at $FULL_NODE_BIN"
    exit 1
fi

if [ "$BUNDLE_PINENTRY" = "true" ]; then
    PINENTRY_NAME="pinentry-mac"
    PINENTRY_APP_NAME="pinentry-mac.app"
    PINENTRY_APP_SRC="$TARGET_DIR/$PINENTRY_APP_NAME"
    if [ ! -d "$PINENTRY_APP_SRC" ]; then
        echo "ERROR: $PINENTRY_APP_NAME not found at $PINENTRY_APP_SRC"
        echo "       qpv2-gui's build.rs is responsible for staging it."
        echo "       Run: vendor/build-pinentry.sh && cargo clean -p qpv2-gui && cargo build -p qpv2-gui $CARGO_FLAGS"
        exit 1
    fi
    echo "==> Using $PINENTRY_APP_NAME from $PINENTRY_APP_SRC (staged by build.rs)"
else
    echo "==> Skipping pinentry-mac.app bundling (BUNDLE_PINENTRY=false)"
fi

# ── Create app bundle ─────────────────────────────────────────────

echo "==> Creating app bundle at $APP_BUNDLE..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$TARGET_DIR/$BINARY_NAME" "$APP_BUNDLE/Contents/MacOS/$BINARY_NAME"
cp "$LIGHT_CLIENT_BIN" "$APP_BUNDLE/Contents/MacOS/$LIGHT_CLIENT_NAME"
cp "$FULL_NODE_BIN" "$APP_BUNDLE/Contents/MacOS/$FULL_NODE_NAME"

# App icon (the Dock / Finder / Launchpad icon). Must be in place before
# sign.sh runs, since codesign seals the Resources directory.
cp "$PROJECT_ROOT/assets/icon/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
if [ "$BUNDLE_PINENTRY" = "true" ]; then
    cp -R "$PINENTRY_APP_SRC" "$APP_BUNDLE/Contents/MacOS/$PINENTRY_APP_NAME"
fi

cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>${APP_NAME}</string>
	<key>CFBundleExecutable</key>
	<string>${BINARY_NAME}</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>${BUNDLE_ID}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${APP_NAME}</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>15.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PLIST

echo ""
echo "==> Bundle created: $APP_BUNDLE"
echo "    Run sign.sh to code sign, or use as-is for testing."
