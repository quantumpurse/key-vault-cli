#!/usr/bin/env bash
# Code sign the QPV2 GUI app bundle for macOS.
#
# Expects bundle-macos.sh to have already produced the .app at
# target/{debug,release}/qpv2.app. Signs inner binaries first,
# then the bundle (Apple recommends against --deep).
#
# Prerequisites:
#   1. Apple Developer identity: "Developer ID Application: Pham Tung (KPSL53752R)"
#   2. The apple-app-site-association file deployed to:
#      https://quantumpurse.org/.well-known/apple-app-site-association
#
# Usage:
#   ./crates/qpv2-gui/scripts/sign.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUI_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(cd "$GUI_DIR/../.." && pwd)"

source "$SCRIPT_DIR/config.sh"

ENTITLEMENTS="$GUI_DIR/entitlements.plist"

# Parse arguments.
BUILD_TYPE="debug"
while [[ $# -gt 0 ]]; do
	case "$1" in
		--release)
			BUILD_TYPE="release"
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

if [ ! -d "$APP_BUNDLE" ]; then
	echo "ERROR: App bundle not found at $APP_BUNDLE"
	echo "       Run bundle-macos.sh first."
	exit 1
fi

echo "==> Signing with identity: $SIGNING_IDENTITY"

# The light client and full node are standalone TCP/HTTP daemons
# with no keychain or passkey access, so they get hardened-runtime
# but no entitlements.
codesign --force --sign "$SIGNING_IDENTITY" \
	--options runtime \
	"$APP_BUNDLE/Contents/MacOS/ckb-light-client"
codesign --force --sign "$SIGNING_IDENTITY" \
	--options runtime \
	"$APP_BUNDLE/Contents/MacOS/ckb"
if [ "$BUNDLE_PINENTRY" = "true" ]; then
	PINENTRY_APP_DST="$APP_BUNDLE/Contents/MacOS/pinentry-mac.app"
	PINENTRY_BIN="$PINENTRY_APP_DST/Contents/MacOS/pinentry-mac"
	if [ -d "$PINENTRY_APP_DST" ]; then
		codesign --force --sign "$SIGNING_IDENTITY" \
			--options runtime \
			"$PINENTRY_BIN"
		codesign --force --sign "$SIGNING_IDENTITY" \
			--options runtime \
			"$PINENTRY_APP_DST"
	fi
fi
codesign --force --sign "$SIGNING_IDENTITY" \
	--entitlements "$ENTITLEMENTS" \
	--options runtime \
	"$APP_BUNDLE/Contents/MacOS/$BINARY_NAME"
codesign --force --sign "$SIGNING_IDENTITY" \
	--entitlements "$ENTITLEMENTS" \
	--options runtime \
	"$APP_BUNDLE"

echo "==> Verifying signature..."
codesign --verify --strict "$APP_BUNDLE"
echo "==> Signature valid."

echo ""
echo "==> Done! App bundle: $APP_BUNDLE"
echo "    Run with: open \"$APP_BUNDLE\""
echo ""
echo "==> To check entitlements:"
echo "    codesign -d --entitlements - \"$APP_BUNDLE\""
