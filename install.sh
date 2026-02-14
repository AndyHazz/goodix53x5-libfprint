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

# Copy driver sources
mkdir -p "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5"
cp -v "$SCRIPT_DIR/drivers/goodix53x5/"* "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5/"

# Copy SIGFM library
mkdir -p "$LIBFPRINT_DIR/libfprint/sigfm"
cp -v "$SCRIPT_DIR/sigfm/"* "$LIBFPRINT_DIR/libfprint/sigfm/"

MESON="$LIBFPRINT_DIR/libfprint/meson.build"
ROOT_MESON="$LIBFPRINT_DIR/meson.build"

# Check if driver is already registered
if grep -q "'goodix53x5'" "$MESON"; then
    echo "Driver already registered in libfprint/meson.build"
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
    echo "       [ 'drivers/goodix53x5/goodix53x5.c', 'drivers/goodix53x5/goodix53x5-proto.c', 'drivers/goodix53x5/goodix53x5-crypto.c', 'drivers/goodix53x5/goodix53x5-device.c' ],"
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

# Install udev rule to prevent cdc_acm from claiming the device
if [ ! -f /etc/udev/rules.d/91-goodix-fingerprint.rules ]; then
    echo "Installing udev rule to prevent cdc_acm from claiming the sensor..."
    sudo cp -v "$SCRIPT_DIR/91-goodix-fingerprint.rules" /etc/udev/rules.d/
    sudo udevadm control --reload-rules
else
    echo "udev rule already installed"
fi

echo ""
echo "Done. Now reconfigure and rebuild libfprint."
