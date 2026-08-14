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
			open "target/release/qpv2.app"
		else
			./target/debug/qpv2.app/Contents/MacOS/qpv2-gui
		fi
		;;
	*)
		echo "Usage: ./launch.sh <cli|gui> [--release] [-- args...]"
		exit 1
		;;
esac
