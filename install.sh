#!/bin/bash
# Install the Goodix 53x5 driver into a libfprint source tree.
#
# Usage: ./install.sh /path/to/libfprint
#
# After running this script, configure and build libfprint:
#   cd /path/to/libfprint
#   meson setup builddir --prefix=/usr -Ddrivers=goodix53x5 -Dudev_hwdb=disabled -Dudev_rules=disabled -Dintrospection=false -Dinstalled-tests=false -Ddoc=false
#   ninja -C builddir && sudo ninja -C builddir install

set -euo pipefail

LIBFPRINT_DIR="${1:?Usage: $0 /path/to/libfprint}"

if [ ! -f "$LIBFPRINT_DIR/libfprint/meson.build" ]; then
    echo "Error: $LIBFPRINT_DIR does not look like a libfprint source tree."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Goodix 53x5 driver into $LIBFPRINT_DIR ..."

# Copy driver sources. Remove the target directory first so files deleted or
# renamed by driver updates (e.g. the old goodix53x5-device.c) do not linger.
rm -rf "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5"
mkdir -p "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5"
cp -v "$SCRIPT_DIR/drivers/goodix53x5/"* "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5/"

# Copy SIGFM library
rm -rf "$LIBFPRINT_DIR/libfprint/sigfm"
mkdir -p "$LIBFPRINT_DIR/libfprint/sigfm"
cp -v "$SCRIPT_DIR/sigfm/"* "$LIBFPRINT_DIR/libfprint/sigfm/"

MESON="$LIBFPRINT_DIR/libfprint/meson.build"
ROOT_MESON="$LIBFPRINT_DIR/meson.build"

DRIVER_SOURCES="[ 'drivers/goodix53x5/goodix53x5.c', 'drivers/goodix53x5/goodix53x5-proto.c', 'drivers/goodix53x5/goodix53x5-crypto.c', 'drivers/goodix53x5/goodix53x5-transport.c', 'drivers/goodix53x5/goodix53x5-commands.c', 'drivers/goodix53x5/goodix53x5-session.c', 'drivers/goodix53x5/goodix53x5-scan.c', 'drivers/goodix53x5/goodix53x5-enroll.c', 'drivers/goodix53x5/goodix53x5-auth.c', 'drivers/goodix53x5/goodix53x5-match.c', 'drivers/goodix53x5/goodix53x5-calibration.c', 'drivers/goodix53x5/goodix53x5-image.c' ],"

# Canonical SIGFM/OpenCV meson block. Keep in sync with meson-integration.patch.
read -r -d '' SIGFM_MESON_BLOCK <<'EOF' || true
# SIGFM: SIFT-based fingerprint matching for small sensors
# Use pkg-config only for the include path; link only the OpenCV modules we
# need (the full opencv pkg-config pulls modules like viz/hdf that have
# missing transitive deps).
opencv_pc = dependency('opencv5', required: false)
if not opencv_pc.found()
    opencv_pc = dependency('opencv4')
endif
opencv_includes = opencv_pc.partial_dependency(compile_args: true, includes: true)
opencv_core = cc.find_library('opencv_core')
# OpenCV 5 renamed the features2d module to features
opencv_features2d = cc.find_library('opencv_features2d', required: false)
if not opencv_features2d.found()
    opencv_features2d = cc.find_library('opencv_features')
endif
opencv_flann = cc.find_library('opencv_flann')
opencv_imgproc = cc.find_library('opencv_imgproc')
opencv_dep = declare_dependency(
    dependencies: [opencv_includes, opencv_core, opencv_features2d, opencv_flann, opencv_imgproc],
)
libsigfm = static_library('sigfm',
    'sigfm/sigfm.cpp',
    dependencies: [opencv_dep],
    cpp_args: ['-std=c++17'],
    install: false)
EOF

# Trees integrated before OpenCV 5 support hardcode the OpenCV 4 include path,
# which fails to configure once the distro ships OpenCV 5. Replace the whole
# SIGFM/OpenCV block (start marker through libsigfm) with the current version.
migrate_sigfm_block() {
    if ! grep -q "include_directories('/usr/include/opencv4')" "$MESON"; then
        return 0
    fi
    if grep -q "^# SIGFM: SIFT-based fingerprint matching for small sensors$" "$MESON"; then
        echo "Updating OpenCV 4-only SIGFM block for OpenCV 4/5 ..."
        awk -v newblock="$SIGFM_MESON_BLOCK" '
            /^# SIGFM: SIFT-based fingerprint matching for small sensors$/ && !done {
                print newblock
                skipping = 1
                done = 1
                next
            }
            skipping {
                if ($0 ~ /^    install: false\)$/) skipping = 0
                next
            }
            { print }
        ' "$MESON" > "$MESON.tmp"
        mv "$MESON.tmp" "$MESON"
        echo "SIGFM block updated. Reconfigure your build directory before rebuilding."
    else
        echo ""
        echo "========================================="
        echo "MANUAL UPDATE REQUIRED"
        echo "========================================="
        echo ""
        echo "Your libfprint tree was set up when this driver only supported"
        echo "OpenCV 4. It needs a small edit so it also builds against OpenCV 5,"
        echo "otherwise the build will fail with an error like:"
        echo ""
        echo "    ERROR: Include dir /usr/include/opencv4 does not exist."
        echo ""
        echo "This script could not make the edit automatically because the file"
        echo "differs from the layout it expects. To fix it by hand:"
        echo ""
        echo "1. Open this file in a text editor:"
        echo ""
        echo "       $MESON"
        echo ""
        echo "2. Find the line containing:"
        echo ""
        echo "       include_directories('/usr/include/opencv4')"
        echo ""
        echo "3. Delete the section of the file that sets up OpenCV and sigfm."
        echo "   It starts a couple of lines above that line (at a comment"
        echo "   mentioning SIGFM) and ends with these lines:"
        echo ""
        echo "       libsigfm = static_library('sigfm',"
        echo "           'sigfm/sigfm.cpp',"
        echo "           dependencies: [opencv_dep],"
        echo "           cpp_args: ['-std=c++17'],"
        echo "           install: false)"
        echo ""
        echo "4. Paste this in its place (without the leading spaces):"
        echo ""
        echo "$SIGFM_MESON_BLOCK" | sed 's/^/       /'
        echo ""
        echo "5. Save the file, then re-run this install script. If it prints"
        echo "   no warnings, continue with the normal build steps in README.md."
        echo ""
    fi
}

print_manual_steps() {
    echo ""
    echo "========================================="
    echo "MANUAL STEPS REQUIRED"
    echo "========================================="
    echo ""
    echo "Add the following to $MESON:"
    echo ""
    echo "1. In the driver_sources dictionary, add:"
    echo "   'goodix53x5' :"
    echo "       $DRIVER_SOURCES"
    echo ""
    echo "2. Before the libfprint_drivers static_library() call, add the SIGFM build:"
    echo "$SIGFM_MESON_BLOCK" | sed 's/^/   /'
    echo ""
    echo "3. Add libsigfm to the link_with for libfprint_drivers and libfprint."
    echo "4. Add opencv_dep to the dependencies for libfprint."
    echo ""
    echo "5. In the root meson.build, add 'goodix53x5' to the default_drivers list"
    echo "   and add: 'goodix53x5' : [ 'openssl' ] to the driver_helpers dict."
    echo ""
}

# Check if the driver is registered, and whether the registration matches the
# current module layout. goodix53x5-commands.c only exists in the current
# layout, so its absence from an existing entry means the source list is stale.
if grep -q "'goodix53x5'" "$MESON" && grep -q "goodix53x5-commands.c" "$MESON"; then
    echo "Driver already registered in libfprint/meson.build"
    migrate_sigfm_block
elif grep -q "'goodix53x5'" "$MESON"; then
    migrate_sigfm_block
    echo ""
    echo "========================================="
    echo "MANUAL UPDATE REQUIRED"
    echo "========================================="
    echo ""
    echo "An older goodix53x5 entry was found in $MESON."
    echo "The driver module layout has changed; building with the old source"
    echo "list will fail. Replace the existing 'goodix53x5' driver_sources"
    echo "entry with:"
    echo ""
    echo "   'goodix53x5' :"
    echo "       $DRIVER_SOURCES"
    echo ""
else
    echo "Applying Meson integration patch ..."
    if patch --dry-run -d "$LIBFPRINT_DIR" -p1 < "$SCRIPT_DIR/meson-integration.patch" >/dev/null; then
        patch -d "$LIBFPRINT_DIR" -p1 < "$SCRIPT_DIR/meson-integration.patch"
        echo "Meson integration patch applied."
    else
        echo "Could not apply meson-integration.patch automatically."
        print_manual_steps
    fi
fi

echo ""
echo "Done. Now configure and build libfprint. See README.md for distro-specific commands."
