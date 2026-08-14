#!/usr/bin/env bash
# Validate a macOS provisioning profile before it is embedded and signed.
#
# Covers the four ways a profile can look fine and still ship a wallet
# whose Touch ID fails with -34018 for every user: it is expired, it is
# the wrong kind of profile or for the wrong app, it does not authorise
# the signing certificate, or it does not grant an entitlement the app
# requests. None of these are caught by codesign or notarization.
#
# Usage:
#   ./crates/qpv2-gui/scripts/validate-profile.sh <profile-path>

# Abort on any failure, unset variable or failed pipeline stage, so a check
# that never ran is never mistaken for a check that passed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUI_DIR="$(dirname "$SCRIPT_DIR")"

source "$SCRIPT_DIR/config.sh"

PROFILE="${1:-}"
if [ -z "$PROFILE" ]; then
	echo "Usage: $0 <profile-path>"
	exit 1
fi
if [ ! -f "$PROFILE" ]; then
	echo "ERROR: Provisioning profile not found: $PROFILE"
	exit 1
fi

PLIST="$(mktemp)"

# When this script exits, remove the temp file.
trap 'rm -f "$PLIST"' EXIT

# Extract plist and put it in a temp file.
if ! security cms -D -i "$PROFILE" -o "$PLIST" 2>/dev/null; then
	echo "ERROR: Not a readable provisioning profile: $PROFILE"
	exit 1
fi

# Read one key from the profile, empty if absent, so `set -e` cannot abort
# before the check below reports which key was missing.
get() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null || true; }

# ── 1. Expiry ─────────────────────────────────────────────────────
# Reject an expired profile, which stops the app launching at all.
EXPIRES="$(plutil -extract ExpirationDate raw -o - "$PLIST" 2>/dev/null || true)"
EXPIRES_EPOCH="$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$EXPIRES" "+%s" 2>/dev/null || true)"
if [ -z "$EXPIRES_EPOCH" ]; then
	echo "ERROR: Could not read the profile's ExpirationDate (got '$EXPIRES')."
	exit 1
fi
if [ "$EXPIRES_EPOCH" -le "$(date -u "+%s")" ]; then
	echo "ERROR: Provisioning profile expired at $EXPIRES."
	exit 1
fi

# ── 2. Right kind of profile, for the right app ───────────────────
# Reject anything but a Developer ID profile for this exact app.
if [ "$(get ProvisionsAllDevices)" != "true" ]; then
	echo "ERROR: Not a Developer ID profile. Mac Development and Mac App Store"
	echo "       profiles cannot authorise a notarized outside-the-store app."
	exit 1
fi
PROFILE_APP_ID="$(get Entitlements:com.apple.application-identifier)"
if [ "$PROFILE_APP_ID" != "$TEAM_ID.$BUNDLE_ID" ]; then
	echo "ERROR: Profile App ID is '$PROFILE_APP_ID', expected '$TEAM_ID.$BUNDLE_ID'."
	exit 1
fi

# ── 3. Unauthorized entitlements ──────────────────────────────────
# Reject a profile missing any entitlement the app requests.
for KEY in $(plutil -convert xml1 -o - "$GUI_DIR/entitlements.plist" \
	| grep -o '<key>[^<]*' | sed 's/<key>//'); do
	if [ -z "$(get "Entitlements:$KEY")" ]; then
		echo "ERROR: entitlements.plist requests '$KEY', which this profile"
		echo "       does not authorise. macOS would ignore it at runtime."
		exit 1
	fi
done

# ── 4. Certificate mismatch ───────────────────────────────────────
# Reject a profile that does not authorise the signing certificate.
# A PEM body is base64 DER, which is exactly how the profile stores its
# certificates, so the two compare directly as strings.
WANT="$(security find-certificate -c "$SIGNING_IDENTITY" -p 2>/dev/null \
	| sed '/CERTIFICATE/d' | tr -d '\n' || true)"
if [ -z "$WANT" ]; then
	echo "ERROR: Signing certificate '$SIGNING_IDENTITY' is not in the keychain."
	exit 1
fi
INDEX=0
MATCHED=false
while B64="$(plutil -extract "DeveloperCertificates.$INDEX" raw -o - "$PLIST" 2>/dev/null)"; do
	if [ "$(printf %s "$B64" | tr -d '\n')" = "$WANT" ]; then
		MATCHED=true
		break
	fi
	INDEX=$((INDEX + 1))
done
if [ "$MATCHED" != "true" ]; then
	echo "ERROR: This profile does not authorise '$SIGNING_IDENTITY'."
	echo "       Regenerate the profile against the current certificate."
	exit 1
fi

echo "==> Provisioning profile valid: $(get Name)"
echo "    App ID:  $PROFILE_APP_ID"
echo "    Expires: $EXPIRES"
