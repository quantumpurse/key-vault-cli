#!/usr/bin/env bash
# Build QPV2 CLI or GUI.
#
# Usage:
#   ./build.sh <cli|gui> [--release] [--sign] [--clean]
#
# Flags:
#   --release   Build in release mode.
#   --sign      Code sign the output (macOS only). Signing will make final build not reproduceable.
#   --clean     Clean workspace and all vendor build artifacts before building.
set -euo pipefail

TARGET="${1:-}"

CLEAN=false
RELEASE=false
SIGN=false
for arg in "${@:2}"; do
	case "$arg" in
		--clean) CLEAN=true ;;
		--release) RELEASE=true ;;
		--sign) SIGN=true ;;
		*) echo "Unknown flag: $arg"; exit 1 ;;
	esac
done

if [ "$CLEAN" = true ]; then
	echo "==> Cleaning workspace..."
	cargo clean
	echo "==> Cleaning vendor/ckb..."
	cargo clean --manifest-path vendor/ckb/Cargo.toml
	echo "==> Cleaning vendor/ckb-light-client..."
	cargo clean --manifest-path vendor/ckb-light-client/Cargo.toml
	echo "==> Cleaning vendor/pinentry-build..."
	rm -rf vendor/pinentry-build
	for dir in vendor/libgpg-error vendor/libassuan vendor/pinentry; do
		if [ -f "$dir/Makefile" ]; then
			echo "==> Cleaning $dir..."
			make -C "$dir" distclean 2>/dev/null || true
		fi
	done
	echo "==> Clean complete."
fi

# Reproducible builds: pin the build timestamp.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

SIGN_IDENTITY="Developer ID Application: Pham Tung (KPSL53752R)"
ENTITLEMENTS="crates/qpv2-gui/entitlements.plist"

case "$TARGET" in
	cli)
		if [ "$RELEASE" = true ]; then
			cargo build -p qpv2-cli --release
			if [ "$SIGN" = true ]; then
				codesign -s "$SIGN_IDENTITY" --entitlements "$ENTITLEMENTS" --force target/release/qpv2-cli
				echo "Built and signed: target/release/qpv2-cli"
			else
				echo "Built: target/release/qpv2-cli"
			fi
		else
			cargo build -p qpv2-cli
			if [ "$SIGN" = true ]; then
				codesign -s "$SIGN_IDENTITY" --entitlements "$ENTITLEMENTS" --force target/debug/qpv2-cli
				echo "Built and signed: target/debug/qpv2-cli"
			else
				echo "Built: target/debug/qpv2-cli"
			fi
		fi
		;;
	gui)
		if [ "$RELEASE" = true ]; then
			./crates/qpv2-gui/scripts/bundle-macos.sh --release
			if [ "$SIGN" = true ]; then
				./crates/qpv2-gui/scripts/sign.sh --release
			fi
		else
			./crates/qpv2-gui/scripts/bundle-macos.sh
			if [ "$SIGN" = true ]; then
				./crates/qpv2-gui/scripts/sign.sh
			fi
		fi
		;;
	*)
		echo "Usage: ./build.sh <cli|gui> [--release] [--sign] [--clean]"
		exit 1
		;;
esac
