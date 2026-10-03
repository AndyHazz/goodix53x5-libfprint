#!/usr/bin/env bash
# Build a Debian/Ubuntu package of libfprint + the goodix53x5 driver.
#
# The result is libfprint-goodix53x5_<version>_<arch>.deb in ./dist. It installs
# libfprint into /usr/lib/libfprint-goodix53x5 and a systemd drop-in that makes
# fprintd load it, so the distribution's libfprint-2-2 stays untouched.
#
# Usage (from a clean Debian/Ubuntu machine or container):
#   ./packaging/build-deb.sh [--install-deps]            # binary .deb for this host
#   ./packaging/build-deb.sh --source --series noble     # unsigned source package
#                                                        # for a Launchpad PPA upload
#
# Environment:
#   LIBFPRINT_REF   libfprint tag to build against (default: v1.94.10)
#   LIBFPRINT_REPO  libfprint git URL
#   WORKDIR         scratch dir (default: ./.build/deb)
#   DIST_DIR        where to put the .deb (default: ./dist)
#   PPA_REVISION    suffix for --source versions (default: 1)
set -euo pipefail

MODE=binary
SERIES=""
INSTALL_DEPS=no
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=yes ;;
        --source) MODE=source ;;
        --series) SERIES="${2:?--series needs a codename, e.g. noble}"; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBFPRINT_REF="${LIBFPRINT_REF:-v1.94.10}"
LIBFPRINT_REPO="${LIBFPRINT_REPO:-https://gitlab.freedesktop.org/libfprint/libfprint.git}"
WORKDIR="${WORKDIR:-$REPO_DIR/.build/deb}"
DIST_DIR="${DIST_DIR:-$REPO_DIR/dist}"
SRC="$WORKDIR/libfprint"

log() { printf '\n==> %s\n' "$*"; }

if [[ $INSTALL_DEPS == yes ]]; then
    log "Installing build dependencies"
    deps=$(sed -n 's/^Build-Depends: //p' "$REPO_DIR/packaging/debian/control")
    if [[ $EUID -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi
    $SUDO apt-get update
    $SUDO apt-get satisfy -y "$deps, git, ca-certificates"
fi

log "Fetching libfprint $LIBFPRINT_REF"
rm -rf "$SRC"
mkdir -p "$WORKDIR"
git clone -q --depth 1 --branch "$LIBFPRINT_REF" "$LIBFPRINT_REPO" "$SRC"

log "Adding the goodix53x5 driver"
"$REPO_DIR/install.sh" "$SRC" >/dev/null
rm -f "$SRC/libfprint/meson.build.orig"

log "Preparing debian/"
cp -r "$REPO_DIR/packaging/debian" "$SRC/debian"

driver_sha=$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
driver_date=$(git -C "$REPO_DIR" log -1 --format=%cd --date=format:%Y%m%d 2>/dev/null || date +%Y%m%d)
. /etc/os-release
base_version="${LIBFPRINT_REF#v}+git${driver_date}.${driver_sha}"
if [[ $MODE == source ]]; then
    # Launchpad needs a distinct version per series within one PPA.
    codename="${SERIES:-${VERSION_CODENAME:?--series is required when the host has no VERSION_CODENAME}}"
    version="${base_version}~${codename}${PPA_REVISION:-1}"
else
    codename="${VERSION_CODENAME:-unstable}"
    version="${base_version}~${ID}${VERSION_ID:-}"
fi

cat > "$SRC/debian/changelog" <<CHANGELOG
libfprint-goodix53x5 ($version) $codename; urgency=medium

  * libfprint $LIBFPRINT_REF with goodix53x5 driver $driver_sha.

 -- goodix53x5-libfprint CI <noreply@github.com>  $(date -R)
CHANGELOG

mkdir -p "$DIST_DIR"
if [[ $MODE == source ]]; then
    log "Building source package $version for $codename"
    # The libfprint tree is a git checkout; drop VCS metadata so it is not
    # shipped in the native tarball.
    rm -rf "$SRC/.git"
    (cd "$SRC" && dpkg-buildpackage -S -us -uc -d)
    mv "$WORKDIR"/libfprint-goodix53x5_"$version"* "$DIST_DIR/"
    log "Built (unsigned). Sign and upload with:"
    echo "  debsign $DIST_DIR/libfprint-goodix53x5_${version}_source.changes"
    echo "  dput ppa:<owner>/<ppa> $DIST_DIR/libfprint-goodix53x5_${version}_source.changes"
else
    log "Building $version"
    (cd "$SRC" && dpkg-buildpackage -b -us -uc)
    mv "$WORKDIR"/libfprint-goodix53x5_*.deb "$DIST_DIR/"
    log "Built:"
    ls -1 "$DIST_DIR"/libfprint-goodix53x5_*.deb
fi
