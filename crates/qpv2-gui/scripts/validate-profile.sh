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

TMP="$(mktemp -d "${TMPDIR:-/tmp}/qpv2-profile.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# `security cms -D` verifies Apple's signature on the profile as it decodes.
if ! security cms -D -i "$PROFILE" -o "$TMP/profile.plist" 2>/dev/null; then
	echo "ERROR: Not a valid Apple-signed provisioning profile: $PROFILE"
	exit 1
fi

# `|| true` on every read: PlistBuddy and plutil exit non-zero on a missing
# key, which under `set -e` would abort on the assignment itself and skip
# the descriptive check below.
get() { /usr/libexec/PlistBuddy -c "Print :$1" "$TMP/profile.plist" 2>/dev/null || true; }

# ── 1. Expiry ─────────────────────────────────────────────────────
# macOS evaluates an embedded Developer ID profile at every launch, so an
# expired one stops the app starting at all, not just Touch ID.
EXPIRES="$(plutil -extract ExpirationDate raw -o - "$TMP/profile.plist" 2>/dev/null || true)"
EXPIRES_AT="$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$EXPIRES" "+%s" 2>/dev/null || true)"
if [ -z "$EXPIRES_AT" ]; then
	echo "ERROR: Could not read the profile's ExpirationDate (got '$EXPIRES')."
	exit 1
fi
if [ "$EXPIRES_AT" -le "$(date -u "+%s")" ]; then
	echo "ERROR: Provisioning profile expired at $EXPIRES."
	exit 1
fi

# ── 2. Right kind of profile, for the right app ───────────────────
# ProvisionsAllDevices marks a Developer ID profile; Mac Development and
# Mac App Store profiles lack the key entirely and do not work here.
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
# codesign will happily sign entitlements the profile does not grant; macOS
# then ignores them at runtime. entitlements.plist is a flat dict, so its
# top-level <key> elements are exactly what the app requests.
for KEY in $(plutil -convert xml1 -o - "$GUI_DIR/entitlements.plist" \
	| grep -o '<key>[^<]*' | sed 's/<key>//'); do
	if [ -z "$(get "Entitlements:$KEY")" ]; then
		echo "ERROR: entitlements.plist requests '$KEY', which this profile"
		echo "       does not authorise. macOS would ignore it at runtime."
		exit 1
	fi
done

# ── 4. Certificate mismatch ───────────────────────────────────────
# The profile authorises specific certificates. Renewing the Developer ID
# certificate without regenerating the profile breaks the app at launch.
if ! security find-certificate -c "$SIGNING_IDENTITY" -p > "$TMP/cert.pem" 2>/dev/null; then
	echo "ERROR: Signing certificate '$SIGNING_IDENTITY' is not in the keychain."
	exit 1
fi
openssl x509 -in "$TMP/cert.pem" -outform DER -out "$TMP/cert.der"
WANT="$(shasum -a 256 "$TMP/cert.der" | awk '{print $1}')"
INDEX=0
MATCHED=false
while plutil -extract "DeveloperCertificates.$INDEX" raw -o "$TMP/pc.b64" \
	"$TMP/profile.plist" 2>/dev/null; do
	base64 -D -i "$TMP/pc.b64" -o "$TMP/pc.der"
	if [ "$(shasum -a 256 "$TMP/pc.der" | awk '{print $1}')" = "$WANT" ]; then
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
