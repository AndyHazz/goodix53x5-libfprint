#!/bin/bash
# Install the Goodix 53x5 driver into a libfprint source tree.
#
# Usage: ./install.sh /path/to/libfprint
#
# After running this script, reconfigure and build libfprint:
#   cd /path/to/libfprint/builddir
#   meson setup --reconfigure ..
#   ninja && sudo ninja install

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

# Check if the driver is registered, and whether the registration matches the
# current module layout. goodix53x5-commands.c only exists in the current
# layout, so its absence from an existing entry means the source list is stale.
if grep -q "'goodix53x5'" "$MESON" && grep -q "goodix53x5-commands.c" "$MESON"; then
    echo "Driver already registered in libfprint/meson.build"
elif grep -q "'goodix53x5'" "$MESON"; then
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
    echo "   opencv_inc = include_directories('/usr/include/opencv4')"
    echo "   opencv_core = cc.find_library('opencv_core')"
    echo "   opencv_features2d = cc.find_library('opencv_features2d')"
    echo "   opencv_flann = cc.find_library('opencv_flann')"
    echo "   opencv_imgproc = cc.find_library('opencv_imgproc')"
    echo "   opencv_dep = declare_dependency("
    echo "       include_directories: opencv_inc,"
    echo "       dependencies: [opencv_core, opencv_features2d, opencv_flann, opencv_imgproc],"
    echo "   )"
    echo "   libsigfm = static_library('sigfm',"
    echo "       'sigfm/sigfm.cpp',"
    echo "       dependencies: [opencv_dep],"
    echo "       cpp_args: ['-std=c++17'],"
    echo "       install: false)"
    echo ""
    echo "3. Add libsigfm to the link_with for libfprint_drivers and libfprint."
    echo "4. Add opencv_dep to the dependencies for libfprint."
    echo ""
    echo "5. In the root meson.build, add 'goodix53x5' to the default_drivers list"
    echo "   and add: 'goodix53x5' : [ 'openssl' ] to the driver_helpers dict."
    echo ""
fi

echo ""
echo "Done. Now reconfigure and rebuild libfprint."
