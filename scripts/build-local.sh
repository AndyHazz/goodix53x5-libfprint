#!/usr/bin/env bash
# Build libfprint with this driver from inside the driver repository.

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="${GOODIX_LOCAL_BUILD_DIR:-$repo_dir/.build}"
libfprint_dir="$work_dir/libfprint"
libfprint_ref="${GOODIX_LIBFPRINT_REF:-v1.94.10}"
build_dir="${GOODIX_MESON_BUILDDIR:-builddir}"
meson_options=(
  --prefix=/usr
  -Ddrivers=goodix53x5
  -Dudev_hwdb=disabled
  -Dudev_rules=disabled
  -Dintrospection=false
  -Dinstalled-tests=false
  -Ddoc=false
)

mkdir -p "$work_dir"

if [ ! -d "$libfprint_dir/.git" ]; then
  git clone https://gitlab.freedesktop.org/libfprint/libfprint.git "$libfprint_dir"
fi

git -C "$libfprint_dir" fetch --tags --quiet
git -C "$libfprint_dir" reset --hard --quiet
git -C "$libfprint_dir" checkout --quiet "$libfprint_ref"
git -C "$libfprint_dir" reset --hard --quiet "$libfprint_ref"

rm -rf "$libfprint_dir/libfprint/drivers/goodix53x5"
mkdir -p "$libfprint_dir/libfprint/drivers/goodix53x5"
cp -R "$repo_dir/drivers/goodix53x5/." "$libfprint_dir/libfprint/drivers/goodix53x5/"

rm -rf "$libfprint_dir/libfprint/sigfm"
mkdir -p "$libfprint_dir/libfprint/sigfm"
cp -R "$repo_dir/sigfm/." "$libfprint_dir/libfprint/sigfm/"

if ! grep -q "'goodix53x5'" "$libfprint_dir/libfprint/meson.build"; then
  patch -d "$libfprint_dir" -p1 < "$repo_dir/meson-integration.patch"
fi

if [ -d "$libfprint_dir/$build_dir" ]; then
  meson setup "$libfprint_dir/$build_dir" "$libfprint_dir" --reconfigure "${meson_options[@]}"
else
  meson setup "$libfprint_dir/$build_dir" "$libfprint_dir" "${meson_options[@]}"
fi

ninja -C "$libfprint_dir/$build_dir"
