#!/bin/bash
# Remove the Goodix 53x5 driver files from a libfprint source tree.
#
# Usage: ./uninstall.sh [--dry-run] /path/to/libfprint
#
# This script removes only the files copied by install.sh. It does not edit
# Meson files automatically because those edits are currently manual and may
# differ between libfprint versions or user trees.

set -euo pipefail

usage() {
    echo "Usage: $0 [--dry-run] /path/to/libfprint"
}

DRY_RUN=0
LIBFPRINT_DIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -n "$LIBFPRINT_DIR" ]; then
                echo "Error: expected exactly one libfprint path." >&2
                usage >&2
                exit 1
            fi
            LIBFPRINT_DIR="$1"
            shift
            ;;
    esac
done

if [ "$#" -gt 0 ]; then
    if [ -n "$LIBFPRINT_DIR" ] || [ "$#" -ne 1 ]; then
        echo "Error: expected exactly one libfprint path." >&2
        usage >&2
        exit 1
    fi
    LIBFPRINT_DIR="$1"
fi

if [ -z "$LIBFPRINT_DIR" ]; then
    usage >&2
    exit 1
fi

if [ ! -f "$LIBFPRINT_DIR/meson.build" ] || [ ! -f "$LIBFPRINT_DIR/libfprint/meson.build" ]; then
    echo "Error: $LIBFPRINT_DIR does not look like a libfprint source tree." >&2
    exit 1
fi

remove_dir() {
    local label="$1"
    local path="$2"

    if [ ! -d "$path" ]; then
        echo "Not found, skipping $label: $path"
        return
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "Would remove $label: $path"
        return
    fi

    rm -rf -- "$path"
    echo "Removed $label: $path"
}

echo "Uninstalling Goodix 53x5 driver files from $LIBFPRINT_DIR ..."

remove_dir "driver sources" "$LIBFPRINT_DIR/libfprint/drivers/goodix53x5"
remove_dir "SIGFM library" "$LIBFPRINT_DIR/libfprint/sigfm"

cat <<EOF

Manual Meson cleanup required:

1. In $LIBFPRINT_DIR/libfprint/meson.build:
   - Remove the 'goodix53x5' entry from the driver_sources dictionary.
   - Remove the SIGFM/OpenCV block that defines opencv_pc, opencv_includes,
     opencv_core, opencv_features2d, opencv_flann, opencv_imgproc, opencv_dep,
     and libsigfm.
   - Remove libsigfm from any link_with lists.
   - Remove opencv_dep from any dependencies lists if it was only added for this driver.

2. In $LIBFPRINT_DIR/meson.build:
   - Remove 'goodix53x5' from the default_drivers list.
   - Remove the 'goodix53x5' : [ 'openssl' ] driver helper mapping.

After cleanup, reconfigure and rebuild libfprint:

  meson setup --reconfigure builddir
  ninja -C builddir
  sudo ninja -C builddir install
  sudo systemctl restart fprintd
EOF

if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    echo "Dry run complete. No files were removed."
else
    echo ""
    echo "Done. Review the manual Meson cleanup steps above."
fi
