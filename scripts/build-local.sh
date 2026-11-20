#!/usr/bin/env bash
# Build libfprint with this driver from inside the driver repository.

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="${GOODIX_LOCAL_BUILD_DIR:-$repo_dir/.build}"
libfprint_dir="$work_dir/libfprint"
libfprint_ref="${GOODIX_LIBFPRINT_REF:-v1.94.10}"
build_dir="${GOODIX_MESON_BUILDDIR:-builddir}"
debug_enabled=false
debug_build_id=
debug_source_id=
command -v pkg-config >/dev/null 2>&1 || {
  printf 'error: pkg-config is required to build the Goodix driver\n' >&2
  exit 1
}
pkg-config --exists libdeflate || {
  printf '%s\n' \
    'error: libdeflate development files are required' \
    'install libdeflate-dev on Debian/Ubuntu, libdeflate on Arch, or libdeflate-devel on Fedora' >&2
  exit 1
}
if [[ "${GOODIX53X5_DEBUG:-0}" == 1 ]]; then
  if [[ ${GOODIX53X5_INTERNAL_BUILD_ID+x} == x ]] &&
     [[ ! ${GOODIX53X5_INTERNAL_BUILD_ID} =~ ^[0-9a-f]{64}$ ]]; then
    printf 'internal Goodix debug build ID must be exactly 64 lowercase hex characters\n' >&2
    exit 1
  fi
  if [[ ${GOODIX53X5_INTERNAL_SOURCE_ID+x} == x ]] &&
     [[ ! ${GOODIX53X5_INTERNAL_SOURCE_ID} =~ ^[0-9a-f]{64}$ ]]; then
    printf 'internal Goodix debug source ID must be exactly 64 lowercase hex characters\n' >&2
    exit 1
  fi
  debug_enabled=true
  debug_build_id="${GOODIX53X5_INTERNAL_BUILD_ID:-$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')}"
  debug_source_id="$(python3 "$repo_dir/scripts/lib/milan_source_identity.py" "$repo_dir")"
  if [[ ! $debug_build_id =~ ^[0-9a-f]{64}$ ||
        ! $debug_source_id =~ ^[0-9a-f]{64}$ ]]; then
    printf 'failed to produce valid Goodix debug build provenance\n' >&2
    exit 1
  fi
  if [[ -n ${GOODIX53X5_INTERNAL_SOURCE_ID:-} &&
        ${GOODIX53X5_INTERNAL_SOURCE_ID} != "$debug_source_id" ]]; then
    printf 'internal Goodix debug source ID differs from the deterministic source identity\n' >&2
    exit 1
  fi
fi
meson_options=(
  --prefix=/usr
  -Ddrivers=goodix53x5
  -Dudev_hwdb=disabled
  -Dudev_rules=disabled
  -Dintrospection=false
  -Dinstalled-tests=false
  -Ddoc=false
  -Dgoodix53x5_debug="$debug_enabled"
  -Dgoodix53x5_debug_build_id="$debug_build_id"
  -Dgoodix53x5_debug_source_id="$debug_source_id"
)

mkdir -p "$work_dir"

if [ ! -d "$libfprint_dir/.git" ] &&
   [[ "${GOODIX_LIBFPRINT_OFFLINE:-0}" == 1 ]]; then
  printf 'offline build requires an existing checkout at %s\n' \
    "$libfprint_dir" >&2
  exit 1
elif [ ! -d "$libfprint_dir/.git" ]; then
  git clone https://gitlab.freedesktop.org/libfprint/libfprint.git "$libfprint_dir"
fi

if [[ "${GOODIX_LIBFPRINT_OFFLINE:-0}" != 1 ]]; then
  git -C "$libfprint_dir" fetch --tags --quiet
fi
git -C "$libfprint_dir" reset --hard --quiet
git -C "$libfprint_dir" checkout --quiet "$libfprint_ref"
git -C "$libfprint_dir" reset --hard --quiet "$libfprint_ref"

# Patch A is revision-pinned and must be checked against a pristine checkout.
# The verifier rejects both the wrong commit and any context drift.
"$repo_dir/patches/libfprint/verify-update-result-patch.sh" "$libfprint_dir"
"$repo_dir/patches/libfprint/verify-goodix53x5-usb-persist-patch.sh" "$libfprint_dir"
"$repo_dir/patches/libfprint/verify-idle-suspend-notify-patch.sh" "$libfprint_dir"
git -C "$libfprint_dir" apply \
  "$repo_dir/patches/libfprint/libfprint-update-result.patch"
git -C "$libfprint_dir" apply \
  "$repo_dir/patches/libfprint/libfprint-goodix53x5-usb-persist.patch"
git -C "$libfprint_dir" apply \
  "$repo_dir/patches/libfprint/libfprint-idle-suspend-notify.patch"

rm -rf "$libfprint_dir/libfprint/drivers/goodix53x5"
mkdir -p "$libfprint_dir/libfprint/drivers/goodix53x5"
cp -R "$repo_dir/drivers/goodix53x5/." "$libfprint_dir/libfprint/drivers/goodix53x5/"
rm -rf "$libfprint_dir/libfprint/sigfm"

for test_source in "$repo_dir"/tests/test-goodix53x5-milan-*.{c,h}; do
  destination="$libfprint_dir/tests/$(basename "$test_source")"
  if ! cmp -s "$test_source" "$destination"; then
    cp "$test_source" "$destination"
  fi
done

mkdir -p "$libfprint_dir/tests/native-study"
cp -R "$repo_dir/tests/native-study/fixtures" "$libfprint_dir/tests/native-study/"
mkdir -p "$libfprint_dir/tests/native-preprocess"
cp -R "$repo_dir/tests/native-preprocess/fixtures" "$libfprint_dir/tests/native-preprocess/"
mkdir -p "$libfprint_dir/tests/native-match"
cp -R "$repo_dir/tests/native-match/fixtures" "$libfprint_dir/tests/native-match/"

if ! grep -q "'goodix53x5'" "$libfprint_dir/libfprint/meson.build"; then
  git -C "$libfprint_dir" apply "$repo_dir/meson-integration.patch"
fi

if [ -d "$libfprint_dir/$build_dir" ]; then
  # Register new overlay options without evaluating stale cached debug settings.
  meson setup "$libfprint_dir/$build_dir" "$libfprint_dir" --reconfigure \
    -Dgoodix53x5_debug=false
  meson setup "$libfprint_dir/$build_dir" "$libfprint_dir" --reconfigure "${meson_options[@]}"
else
  meson setup "$libfprint_dir/$build_dir" "$libfprint_dir" "${meson_options[@]}"
fi

if [[ -n "${GOODIX_LIBFPRINT_NINJA_TARGET:-}" ]]; then
  ninja -C "$libfprint_dir/$build_dir" "$GOODIX_LIBFPRINT_NINJA_TARGET"
else
  ninja -C "$libfprint_dir/$build_dir"
fi
