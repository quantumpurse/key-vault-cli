#!/usr/bin/env bash
# Build pinentry from source for the current platform.
#
# Builds libgpg-error and libassuan as static libraries first, then
# links them into the pinentry binary so it has no external dylib
# dependencies beyond system frameworks.
#
# Outputs the platform-appropriate binary to:
#   vendor/pinentry-build/{OS}-{ARCH}/
#
# Prerequisites (macOS):
#   automake, gettext (for m4 macros)
#   Xcode CLI tools (for ibtool and Obj-C compiler)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PINENTRY_SRC="$SCRIPT_DIR/pinentry"
LIBGPG_ERROR_SRC="$SCRIPT_DIR/libgpg-error"
LIBASSUAN_SRC="$SCRIPT_DIR/libassuan"
OS="$(uname -s)"
ARCH="$(uname -m)"
BUILD_DIR="$SCRIPT_DIR/pinentry-build/${OS}-${ARCH}"
DEPS_PREFIX="$BUILD_DIR/deps"

if [ "$OS" = "Darwin" ]; then
	for opt in gettext autoconf automake libtool; do
		if [ -d "/opt/homebrew/opt/$opt/bin" ]; then
			export PATH="/opt/homebrew/opt/$opt/bin:$PATH"
		fi
		if [ -d "/usr/local/opt/$opt/bin" ]; then
			export PATH="/usr/local/opt/$opt/bin:$PATH"
		fi
	done
fi

missing_tools=()
for tool in autoconf automake gettext make; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		missing_tools+=("$tool")
	fi
done

if [ "$OS" = "Darwin" ] && ! command -v ibtool >/dev/null 2>&1; then
	missing_tools+=("ibtool")
fi

if [ "${#missing_tools[@]}" -gt 0 ]; then
	echo "Error: missing build tool(s): ${missing_tools[*]}" >&2
	if [ "$OS" = "Darwin" ]; then
		echo "" >&2
		echo "Install the macOS GUI build prerequisites:" >&2
		echo "  brew install autoconf automake gettext libtool" >&2
		echo "  xcode-select --install" >&2
		echo "" >&2
		echo "If Homebrew is installed but not on PATH, add it first:" >&2
		echo "  eval \"\$(/opt/homebrew/bin/brew shellenv)\"" >&2
	fi
	exit 1
fi

for dir in "$PINENTRY_SRC" "$LIBGPG_ERROR_SRC" "$LIBASSUAN_SRC"; do
	if [ ! -d "$dir" ]; then
		echo "Error: $(basename "$dir") submodule not found at $dir" >&2
		echo "Run: git submodule update --init --recursive" >&2
		exit 1
	fi
done

echo "==> Building pinentry for ${OS}-${ARCH}"
echo "    Output: $BUILD_DIR"

mkdir -p "$BUILD_DIR" "$DEPS_PREFIX"

# Ensure aclocal can find gettext's m4 macros (keg-only on Homebrew).
if [ "$OS" = "Darwin" ] && [ -d /opt/homebrew/Cellar/gettext ]; then
	GETTEXT_M4="$(find /opt/homebrew/Cellar/gettext -path "*/share/gettext/m4" -type d | head -1)"
	if [ -n "$GETTEXT_M4" ]; then
		export ACLOCAL_FLAGS="-I $GETTEXT_M4 ${ACLOCAL_FLAGS:-}"
	fi
fi

NPROC="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"

if [ "$OS" = "Darwin" ]; then
	export LDFLAGS="${LDFLAGS:-} -Wl,-reproducible"
fi

# ─── Step 1: Build libgpg-error (static) ──────────────────────────

echo "==> [1/3] Building libgpg-error..."
cd "$LIBGPG_ERROR_SRC"

if [ ! -f configure ]; then
	./autogen.sh
fi

./configure \
	--enable-static \
	--disable-shared \
	--disable-doc \
	--disable-tests \
	--prefix="$DEPS_PREFIX"

make -j"$NPROC"
make install
cd "$SCRIPT_DIR"

# ─── Step 2: Build libassuan (static) ─────────────────────────────

echo "==> [2/3] Building libassuan..."
cd "$LIBASSUAN_SRC"

if [ ! -f configure ]; then
	./autogen.sh
fi

./configure \
	--enable-static \
	--disable-shared \
	--disable-doc \
	--with-libgpg-error-prefix="$DEPS_PREFIX" \
	--prefix="$DEPS_PREFIX"

make -j"$NPROC"
make install
cd "$SCRIPT_DIR"

# ─── Step 3: Build pinentry ───────────────────────────────────────

# Prepend our deps bin so configure finds our gpgrt-config instead of any
# system-installed version.
export PATH="$DEPS_PREFIX/bin:$PATH"

echo "==> [3/3] Building pinentry..."
cd "$PINENTRY_SRC"

if [ ! -f configure ]; then
	./autogen.sh
fi

case "$OS" in
	Darwin)
		echo "    Configuring for macOS (pinentry-mac)..."
		./configure \
			--disable-pinentry-curses \
			--disable-fallback-curses \
			--disable-pinentry-tty \
			--disable-pinentry-gtk2 \
			--disable-pinentry-gnome3 \
			--disable-pinentry-qt \
			--disable-pinentry-qt5 \
			--disable-pinentry-fltk \
			--disable-pinentry-efl \
			--disable-doc \
			--with-libgpg-error-prefix="$DEPS_PREFIX" \
			--with-libassuan-prefix="$DEPS_PREFIX" \
			--prefix="$BUILD_DIR/install"

		make -j"$NPROC"

		if [ -d macosx/pinentry-mac.app ]; then
			rm -rf "$BUILD_DIR/pinentry-mac.app"
			cp -R macosx/pinentry-mac.app "$BUILD_DIR/pinentry-mac.app"
			echo "==> Output: $BUILD_DIR/pinentry-mac.app"
		else
			echo "Error: pinentry-mac.app not found after build." >&2
			exit 1
		fi
		;;

	Linux)
		echo "    Configuring for Linux (pinentry-gtk-2)..."
		./configure \
			--enable-pinentry-gtk2 \
			--disable-pinentry-curses \
			--disable-fallback-curses \
			--disable-pinentry-tty \
			--disable-pinentry-gnome3 \
			--disable-pinentry-qt \
			--disable-pinentry-qt5 \
			--disable-pinentry-fltk \
			--disable-pinentry-efl \
			--disable-doc \
			--with-libgpg-error-prefix="$DEPS_PREFIX" \
			--with-libassuan-prefix="$DEPS_PREFIX" \
			--prefix="$BUILD_DIR/install"

		make -j"$NPROC"
		make install

		if [ -f "$BUILD_DIR/install/bin/pinentry-gtk-2" ]; then
			cp "$BUILD_DIR/install/bin/pinentry-gtk-2" "$BUILD_DIR/pinentry-gtk-2"
			echo "==> Output: $BUILD_DIR/pinentry-gtk-2"
		else
			echo "Error: pinentry-gtk-2 not found after build." >&2
			exit 1
		fi
		;;

	MINGW*|MSYS*)
		echo "    Configuring for Windows (pinentry-w32)..."
		export LIBS="${LIBS:-} -lws2_32"
		./configure \
			--disable-pinentry-curses \
			--disable-fallback-curses \
			--disable-pinentry-tty \
			--disable-pinentry-gtk2 \
			--disable-pinentry-gnome3 \
			--disable-pinentry-qt \
			--disable-pinentry-qt5 \
			--disable-pinentry-fltk \
			--disable-pinentry-efl \
			--disable-doc \
			--with-libgpg-error-prefix="$DEPS_PREFIX" \
			--with-libassuan-prefix="$DEPS_PREFIX" \
			--prefix="$BUILD_DIR/install"

		make -j"$NPROC"
		make install

		if [ -f "$BUILD_DIR/install/bin/pinentry-w32.exe" ]; then
			cp "$BUILD_DIR/install/bin/pinentry-w32.exe" "$BUILD_DIR/pinentry-w32.exe"
			echo "==> Output: $BUILD_DIR/pinentry-w32.exe"
		else
			echo "Error: pinentry-w32.exe not found after build." >&2
			exit 1
		fi
		;;

	*)
		echo "Error: unsupported platform '$OS'." >&2
		exit 1
		;;
esac

echo "==> Done."
