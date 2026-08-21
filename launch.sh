#!/usr/bin/env bash
# For macos only!
#
# Launch QPV2 CLI or GUI.
#
# Usage:
#   ./launch.sh cli              # Run CLI (debug)
#   ./launch.sh cli --release    # Run CLI (release)
#   ./launch.sh gui              # Run GUI (debug)
#   ./launch.sh gui --release    # Run GUI (release)

TARGET="${1:-}"
RELEASE="${2:-}"

launch_gui() {
	local build_type="$1"
	local app_path="target/$build_type/qpv2.app"
	local exe_path="$app_path/Contents/MacOS/qpv2-gui"

	if [[ ! -x "$exe_path" ]]; then
		echo "GUI app bundle not found at $app_path."
		echo "Build it first with:"
		if [[ "$build_type" == "release" ]]; then
			echo "  ./build.sh gui --release"
		else
			echo "  ./build.sh gui"
		fi
		echo ""
		echo "If this is a fresh clone, initialize submodules first:"
		echo "  git submodule update --init --recursive"
		exit 1
	fi

	if [[ "$build_type" == "release" ]]; then
		open "$app_path"
	else
		"$exe_path"
	fi
}

case "$TARGET" in
	cli)
		if [[ "$RELEASE" == "--release" ]]; then
			./target/release/qpv2-cli "${@:3}"
		else
			./target/debug/qpv2-cli "${@:3}"
		fi
		;;
	gui)
		if [[ "$RELEASE" == "--release" ]]; then
			launch_gui release
		else
			launch_gui debug
		fi
		;;
	*)
		echo "Usage: ./launch.sh <cli|gui> [--release] [-- args...]"
		exit 1
		;;
esac
