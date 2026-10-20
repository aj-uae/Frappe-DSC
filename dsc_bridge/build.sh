#!/bin/bash
# ============================================================
# Build script for dsc-bridge
# ============================================================
# Builds the Go binary for the current platform or cross-compiles
# for Windows / macOS. Optionally creates a Windows MSI installer.
#
# Usage:
#   ./build.sh                  # Build for current OS
#   ./build.sh linux            # Build the native Linux binary
#   ./build.sh linux-package    # Build the Linux .tar.gz (binary + install.sh)
#   ./build.sh deb              # Build the Debian/Ubuntu .deb (needs dpkg-deb)
#   ./build.sh windows          # Cross-compile for Windows x64 (needs mingw-w64)
#   ./build.sh windows-x86      # Cross-compile for Windows x86 (needs mingw-w64-i686)
#   ./build.sh darwin-amd64     # Build for macOS Intel (must run on a Mac)
#   ./build.sh darwin-arm64     # Build for macOS Apple Silicon (must run on a Mac)
#   ./build.sh darwin-universal # Build a universal Mac binary (must run on a Mac)
#   ./build.sh all              # Build everything possible on the current host
#   ./build.sh msi              # Build Windows MSI (requires go-msi + WiX)
#
# IMPORTANT — macOS:
#   Mac binaries must be built ON A MAC because the bridge links against
#   PKCS#11 via CGO and Apple does not legally redistribute its toolchain.
#   If you don't have a Mac, see the GitHub Actions workflow at
#   .github/workflows/build-bridge.yml — it builds all platforms in CI.
# ============================================================

set -e

APP_NAME="dsc-bridge"
VERSION="1.0.0"
BUILD_DIR="build"

mkdir -p "$BUILD_DIR"

build_local() {
    echo "Building $APP_NAME v$VERSION for $(go env GOOS)/$(go env GOARCH)..."
    go mod tidy
    go build -ldflags "-s -w" -o "$BUILD_DIR/$APP_NAME" .
    echo "Built: $BUILD_DIR/$APP_NAME"
}

build_windows_amd64() {
    echo "Cross-compiling $APP_NAME v$VERSION for windows/amd64..."
    if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        echo "ERROR: x86_64-w64-mingw32-gcc not found. Install with:"
        echo "  sudo apt install gcc-mingw-w64-x86-64    # Debian/Ubuntu"
        echo "  brew install mingw-w64                    # macOS (no PKCS#11 there anyway)"
        return 1
    fi
    go mod tidy
    GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
        CC=x86_64-w64-mingw32-gcc \
        go build -ldflags "-s -w -H windowsgui" -o "$BUILD_DIR/$APP_NAME.exe" .
    echo "Built: $BUILD_DIR/$APP_NAME.exe"
}

build_windows_x86() {
    echo "Cross-compiling $APP_NAME v$VERSION for windows/386..."
    if ! command -v i686-w64-mingw32-gcc &> /dev/null; then
        echo "ERROR: i686-w64-mingw32-gcc not found. Install with:"
        echo "  sudo apt install gcc-mingw-w64-i686       # Debian/Ubuntu"
        return 1
    fi
    go mod tidy
    GOOS=windows GOARCH=386 CGO_ENABLED=1 \
        CC=i686-w64-mingw32-gcc \
        go build -ldflags "-s -w -H windowsgui" -o "$BUILD_DIR/$APP_NAME-x86.exe" .
    echo "Built: $BUILD_DIR/$APP_NAME-x86.exe"
}

# darwin builds — only valid when running on a Mac. CGO + PKCS#11 means
# we need Apple's clang/SDK, which can't be cross-compiled cleanly from Linux.
build_darwin_amd64() {
    if [ "$(go env GOHOSTOS)" != "darwin" ]; then
        echo "ERROR: darwin-amd64 must be built on a Mac (CGO + PKCS#11 needs Apple's clang)."
        echo "       Use the GitHub Actions workflow instead — it has a macos-13 runner."
        return 1
    fi
    echo "Building $APP_NAME v$VERSION for darwin/amd64..."
    go mod tidy
    GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
        go build -ldflags "-s -w" -o "$BUILD_DIR/$APP_NAME-darwin-amd64" .
    echo "Built: $BUILD_DIR/$APP_NAME-darwin-amd64"
}

build_darwin_arm64() {
    if [ "$(go env GOHOSTOS)" != "darwin" ]; then
        echo "ERROR: darwin-arm64 must be built on a Mac (Apple Silicon or Intel Mac)."
        echo "       Use the GitHub Actions workflow instead — it has a macos-14 runner."
        return 1
    fi
    echo "Building $APP_NAME v$VERSION for darwin/arm64..."
    go mod tidy
    GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
        go build -ldflags "-s -w" -o "$BUILD_DIR/$APP_NAME-darwin-arm64" .
    echo "Built: $BUILD_DIR/$APP_NAME-darwin-arm64"
}

build_darwin_pkg() {
    # Wrap the universal binary into a proper .app bundle, then use Apple's
    # pkgbuild to produce a draggable .pkg installer that:
    #   - drops the .app into /Applications
    #   - runs `dsc-bridge --post-install` from the postinstall script
    # The .pkg requires macOS (pkgbuild is Mac-only). Without an Apple
    # Developer ID, signers see a one-time Gatekeeper warning on first launch
    # — System Settings > Privacy & Security > "Open Anyway".
    if [ "$(go env GOHOSTOS)" != "darwin" ]; then
        echo "ERROR: darwin-pkg must be built on a Mac (pkgbuild is Apple's tool)."
        echo "       Use the macOS GitHub Actions runner instead."
        return 1
    fi
    if ! command -v pkgbuild &> /dev/null; then
        echo "ERROR: pkgbuild not found. Install Xcode Command Line Tools:"
        echo "       xcode-select --install"
        return 1
    fi

    build_darwin_universal

    STAGE="$BUILD_DIR/macos-pkg-stage"
    APP="$STAGE/Applications/DSC Bridge.app"
    rm -rf "$STAGE"
    mkdir -p "$APP/Contents/MacOS"
    cp "$BUILD_DIR/$APP_NAME-darwin-universal" "$APP/Contents/MacOS/dsc-bridge"
    chmod +x "$APP/Contents/MacOS/dsc-bridge"

    cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>DSC Bridge</string>
    <key>CFBundleDisplayName</key><string>DSC Bridge</string>
    <key>CFBundleExecutable</key><string>dsc-bridge</string>
    <key>CFBundleIdentifier</key><string>com.esign.dsc-bridge</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>10.15</string>
</dict>
</plist>
EOF

    SCRIPTS="$BUILD_DIR/macos-pkg-scripts"
    rm -rf "$SCRIPTS"
    mkdir -p "$SCRIPTS"
    cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/bash
# The .pkg runs this as root, but the bridge must run as the signer: its TLS cert and
# LaunchAgent live in the logged-in user's home, and launchd must start it in their session.
BIN="/Applications/DSC Bridge.app/Contents/MacOS/dsc-bridge"
CONSOLE_USER=$(stat -f %Su /dev/console)
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ] || [ "$CONSOLE_USER" = "loginwindow" ]; then
    echo "dsc-bridge: no logged-in user; open DSC Bridge from Applications after logging in"
    exit 0
fi
CONSOLE_UID=$(id -u "$CONSOLE_USER")
USER_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')

# Stop any copy left over from an earlier install (older .pkg versions loaded it as root,
# where it holds port 4645 with a cert macOS rejects), then set up and start as the user.
launchctl bootout system/com.esign.dsc-bridge 2>/dev/null || true
launchctl unload /var/root/Library/LaunchAgents/com.esign.dsc-bridge.plist 2>/dev/null || true
rm -f /var/root/Library/LaunchAgents/com.esign.dsc-bridge.plist
pkill -u root -f "DSC Bridge.app/Contents/MacOS/dsc-bridge" 2>/dev/null || true
launchctl bootout "gui/$CONSOLE_UID/com.esign.dsc-bridge" 2>/dev/null || true
launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" "$BIN" --post-install || true

# Trusting a cert in the System keychain needs root, so do it here for the user's cert.
CERT="$USER_HOME/Library/Application Support/dsc-bridge/tls_cert.pem"
if [ -f "$CERT" ]; then
    security delete-certificate -c dsc-bridge /Library/Keychains/System.keychain 2>/dev/null || true
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT" || true
fi
exit 0
EOF
    chmod +x "$SCRIPTS/postinstall"

    cat > "$SCRIPTS/preremove" <<'EOF'
#!/bin/bash
"/Applications/DSC Bridge.app/Contents/MacOS/dsc-bridge" --pre-uninstall || true
pkill -f "DSC Bridge.app/Contents/MacOS/dsc-bridge" || true
exit 0
EOF
    chmod +x "$SCRIPTS/preremove"

    PKG="$BUILD_DIR/$APP_NAME-$VERSION.pkg"
    pkgbuild \
        --identifier com.esign.dsc-bridge \
        --version "$VERSION" \
        --root "$STAGE" \
        --scripts "$SCRIPTS" \
        --install-location / \
        "$PKG"
    echo "Built: $PKG"
    echo
    echo "NOTE: This .pkg is unsigned. Mac signers will see a one-time"
    echo "      'unidentified developer' warning. To allow it:"
    echo "      System Settings > Privacy & Security > 'Open Anyway'."
    echo "      To remove the warning, codesign with an Apple Developer ID."
}

build_darwin_universal() {
    # Produces a single fat binary that runs on both Intel and Apple Silicon.
    # Most user-friendly distribution format for Mac signers.
    if [ "$(go env GOHOSTOS)" != "darwin" ]; then
        echo "ERROR: darwin-universal must be built on a Mac."
        return 1
    fi
    if ! command -v lipo &> /dev/null; then
        echo "ERROR: lipo not found. It ships with Xcode Command Line Tools:"
        echo "       xcode-select --install"
        return 1
    fi
    build_darwin_amd64
    build_darwin_arm64
    echo "Combining into universal binary with lipo..."
    lipo -create \
        -output "$BUILD_DIR/$APP_NAME-darwin-universal" \
        "$BUILD_DIR/$APP_NAME-darwin-amd64" \
        "$BUILD_DIR/$APP_NAME-darwin-arm64"
    echo "Built: $BUILD_DIR/$APP_NAME-darwin-universal"
    echo
    echo "NOTE: Apple Gatekeeper will block unsigned binaries. To distribute:"
    echo "  1. Sign with: codesign --force --options=runtime --sign 'Developer ID Application: <Your Name>' $BUILD_DIR/$APP_NAME-darwin-universal"
    echo "  2. Notarise: xcrun notarytool submit ..."
    echo "  Or document the right-click → Open workaround for unsigned binaries."
}

# Windows packaging — cross-compile the .exe and zip it with the one-click
# install.bat (which runs --post-install: cert trust + firewall + auto-start).
# Produces a working installer WITHOUT needing WiX/MSI or a Windows machine.
build_windows_package() {
    build_windows_amd64
    if ! command -v zip &> /dev/null; then
        echo "ERROR: zip not found. Install with: sudo apt install zip"
        return 1
    fi
    STAGE="$BUILD_DIR/windows-zip/dsc-bridge"
    rm -rf "$BUILD_DIR/windows-zip"
    mkdir -p "$STAGE"
    cp "$BUILD_DIR/$APP_NAME.exe" "$STAGE/dsc-bridge.exe"
    cp windows-package/dsc-bridge.json windows-package/install.bat \
       windows-package/uninstall.bat windows-package/start-dsc-bridge.bat \
       windows-package/README-windows.txt "$STAGE/"
    ZIP="$BUILD_DIR/${APP_NAME}-${VERSION}-windows.zip"
    rm -f "$ZIP"
    (cd "$BUILD_DIR/windows-zip" && zip -r -q "$(basename "$ZIP")" dsc-bridge && mv "$(basename "$ZIP")" ..)
    echo "Built: $ZIP"
    echo "Install: unzip, then double-click install.bat"
}

# 32-bit Windows package — same as build_windows_package but with the x86 .exe.
# Needed for tokens whose PKCS#11 driver is 32-bit only (e.g. Hypersecu HYP2003):
# a 64-bit process cannot load a 32-bit DLL, so those users need this build.
build_windows_package_x86() {
    build_windows_x86
    if ! command -v zip &> /dev/null; then
        echo "ERROR: zip not found. Install with: sudo apt install zip"
        return 1
    fi
    STAGE="$BUILD_DIR/win-x86-zip/dsc-bridge"
    rm -rf "$BUILD_DIR/win-x86-zip"
    mkdir -p "$STAGE"
    cp "$BUILD_DIR/$APP_NAME-x86.exe" "$STAGE/dsc-bridge.exe"
    cp windows-package/dsc-bridge.json windows-package/install.bat \
       windows-package/uninstall.bat windows-package/README-windows.txt "$STAGE/"
    ZIP="$BUILD_DIR/${APP_NAME}-${VERSION}-windows-x86.zip"
    rm -f "$ZIP"
    (cd "$BUILD_DIR/win-x86-zip" && zip -r -q "$(basename "$ZIP")" dsc-bridge && mv "$(basename "$ZIP")" ..)
    echo "Built: $ZIP"
    echo "For tokens with a 32-bit driver (e.g. Hypersecu HYP2003)."
}

# Linux packaging — assemble the distro-agnostic tarball (binary + install.sh +
# uninstall.sh + config + README). No root needed to install it for a user.
build_linux_package() {
    build_local
    STAGE="$BUILD_DIR/linux-tarball/$APP_NAME"
    rm -rf "$BUILD_DIR/linux-tarball"
    mkdir -p "$STAGE"
    cp "$BUILD_DIR/$APP_NAME" "$STAGE/"
    cp linux-package/install.sh linux-package/uninstall.sh \
       linux-package/dsc-bridge.json linux-package/README-linux.txt "$STAGE/"
    chmod +x "$STAGE/$APP_NAME" "$STAGE/install.sh" "$STAGE/uninstall.sh"
    TARBALL="$BUILD_DIR/${APP_NAME}-${VERSION}-linux-amd64.tar.gz"
    tar -czf "$TARBALL" -C "$BUILD_DIR/linux-tarball" "$APP_NAME"
    echo "Built: $TARBALL"
    echo "Install with: tar -xzf $(basename "$TARBALL") && ./$APP_NAME/install.sh"
}

# Debian/Ubuntu package. Installs the binary to /usr/bin and a system-wide
# autostart entry; per-user browser trust happens on first login.
build_deb() {
    if ! command -v dpkg-deb &> /dev/null; then
        echo "ERROR: dpkg-deb not found. Install with: sudo apt install dpkg-dev"
        return 1
    fi
    build_local
    ARCH="amd64"
    STAGE="$BUILD_DIR/deb-stage"
    rm -rf "$STAGE"
    mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin"
    install -m 0755 "$BUILD_DIR/$APP_NAME" "$STAGE/usr/bin/$APP_NAME"
    # Stamp the current version into control; copy maintainer scripts.
    sed "s/^Version: .*/Version: $VERSION/" debian/control > "$STAGE/DEBIAN/control"
    install -m 0755 debian/postinst debian/prerm "$STAGE/DEBIAN/"
    DEB="$BUILD_DIR/${APP_NAME}_${VERSION}_${ARCH}.deb"
    if dpkg-deb --build --root-owner-group "$STAGE" "$DEB" 2>/dev/null; then
        :
    else
        # Older dpkg-deb without --root-owner-group.
        dpkg-deb --build "$STAGE" "$DEB"
    fi
    echo "Built: $DEB"
    echo "Install with: sudo apt install ./$(basename "$DEB")"
}

build_all() {
    # Build everything that this host can produce.
    HOST_OS="$(go env GOHOSTOS)"
    if [ "$HOST_OS" = "linux" ]; then
        build_local
        build_linux_package
        build_deb || true
        build_windows_amd64 || true
        build_windows_x86 || true
        echo
        echo "Skipped: darwin-amd64, darwin-arm64 — must build on a Mac."
        echo "        Push to trigger .github/workflows/build-bridge.yml for those."
    elif [ "$HOST_OS" = "darwin" ]; then
        build_local
        build_darwin_universal
        echo
        echo "Skipped: windows builds — install mingw-w64 via brew if you need them."
    else
        build_local
    fi
}

case "${1:-local}" in
    local)              build_local ;;
    linux)              build_local ;;
    linux-package)      build_linux_package ;;
    deb)                build_deb ;;
    windows)            build_windows_amd64 ;;
    windows-package)    build_windows_package ;;
    windows-package-x86) build_windows_package_x86 ;;
    windows-x86)        build_windows_x86 ;;
    darwin-amd64)       build_darwin_amd64 ;;
    darwin-arm64)       build_darwin_arm64 ;;
    darwin-universal)   build_darwin_universal ;;
    darwin-pkg)         build_darwin_pkg ;;
    all)                build_all ;;

    msi)
        echo "Building Windows MSI installer..."
        if ! command -v go-msi &> /dev/null; then
            echo "ERROR: go-msi not found. Install with:"
            echo "  go install github.com/mh-cbon/go-msi@latest"
            exit 1
        fi
        GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
            CC=x86_64-w64-mingw32-gcc \
            go build -ldflags "-s -w -H windowsgui" -o "$BUILD_DIR/$APP_NAME.exe" .
        go-msi make --msi "$BUILD_DIR/$APP_NAME-$VERSION.msi" --version "$VERSION"
        echo "Built: $BUILD_DIR/$APP_NAME-$VERSION.msi"
        ;;

    test)
        echo "Running unit tests..."
        go mod tidy
        go test -v ./...
        ;;

    integration)
        echo "Running SoftHSM2 integration tests..."
        if [ ! -f /usr/lib/softhsm/libsofthsm2.so ]; then
            echo "ERROR: SoftHSM2 not installed. Run: sudo apt install softhsm2 opensc"
            exit 1
        fi
        echo "Tip: run ./test_setup.sh first if you haven't initialised the test token."
        go mod tidy
        go test -tags softhsm -v ./...
        ;;

    *)
        echo "Usage: ./build.sh [local|linux|linux-package|deb|windows|windows-x86|darwin-amd64|darwin-arm64|darwin-universal|darwin-pkg|all|msi|test|integration]"
        exit 1
        ;;
esac
