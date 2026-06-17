#!/usr/bin/env bash
# Shared configuration for bundle-macos.sh, bundle-linux.sh and sign.sh.

BINARY_NAME="qpv2-gui"
BUNDLE_ID="org.quantumpurse.wallet"
APP_NAME="qpv2"
SIGNING_IDENTITY="Developer ID Application: Pham Tung (KPSL53752R)"
TEAM_ID="KPSL53752R"
# Toggle: when "false", the pinentry-mac.app sub-bundle is NOT
# copied/signed into qpv2.app. The password flow will surface a
# runtime error pointing at the missing path; Touch ID is unaffected.
BUNDLE_PINENTRY="true"
