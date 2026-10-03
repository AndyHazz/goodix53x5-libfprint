#!/usr/bin/env bash
# Build and stage paired libfprint and fprintd for the distribution's system paths.
#
# With --package-root DIR the verified payload is copied into DIR for a
# distribution package instead of being published for install-milan-stack-local.sh.
# That layout keeps libfprint in a private directory that only the daemon uses.

set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s [--package-root DIR]\n' "$0"
}

package_root=
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --package-root)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 1; }
      package_root="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$script_dir/lib/milan-stack-common.sh"

milan_detect_layout
# Package builds only use the stack root as scratch space, so makepkg and
# friends may build below /tmp.
if [[ -z "$package_root" ]]; then
  milan_reject_ephemeral_root "GOODIX_MILAN_STACK_ROOT" "$MILAN_STACK_ROOT"
else
  milan_require_absolute "GOODIX_MILAN_STACK_ROOT" "$MILAN_STACK_ROOT"
fi
for command in git flock meson ninja sha256sum python3 install strings od tr; do
  milan_require_command "$command"
done
milan_verify_repo_inputs "$repo_dir"

case "${GOODIX53X5_DEBUG:-0}" in
  0) debug_enabled=false; debug_manifest=0; build_kind=release ;;
  1) debug_enabled=true; debug_manifest=1; build_kind=debug ;;
  *) milan_die "GOODIX53X5_DEBUG must be 0 or 1" ;;
esac

libfprint_libdir="$MILAN_LIBDIR"
fprintd_env=()
if [[ -n "$package_root" ]]; then
  milan_require_absolute "--package-root" "$package_root"
  milan_require_command readelf
  [[ "$debug_manifest" == 0 ]] || milan_die "distribution packages are release builds; unset GOODIX53X5_DEBUG"
  [[ ! -e "$package_root" || -z "$(ls -A "$package_root")" ]] ||
    milan_die "package root is not empty: $package_root"
  libfprint_libdir="$MILAN_LIBDIR/$MILAN_PACKAGE_LIBRARY_NAME"
  MILAN_LIBRARY_PATH="$libfprint_libdir/libfprint-2.so.2.0.0"
  fprintd_env=(env "LDFLAGS=${LDFLAGS:+$LDFLAGS }-Wl,-rpath,$libfprint_libdir")
fi
debug_build_id=
debug_source_id=
if [[ "$debug_manifest" == 1 ]]; then
  debug_build_id="$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')"
  debug_source_id="$(python3 "$repo_dir/scripts/lib/milan_source_identity.py" "$repo_dir")"
  [[ $debug_build_id =~ ^[0-9a-f]{64}$ && $debug_source_id =~ ^[0-9a-f]{64}$ ]] ||
    milan_die "failed to produce valid Goodix debug build provenance"
fi

# Use an existing pinned checkout, or clone one below the stack root.
ensure_source() {
  local label="$1" dir="$2" url="$3" revision="$4" staging

  if [[ ! -e "$dir" ]]; then
    staging="$dir.fetch.$$"
    milan_run_stage "clone pinned $label" git clone --no-checkout "$url" "$staging"
    git -C "$staging" checkout --detach "$revision"
    mv "$staging" "$dir"
  fi
  milan_verify_git_pristine "$dir" "$revision" "$label"
}

source_root="$MILAN_STACK_ROOT/sources"
mkdir -p "$source_root"
# Release source archives carry the pinned checkouts below sources/.
default_libfprint="$source_root/libfprint-v1.94.10"
default_fprintd="$source_root/fprintd-v1.94.5"
[[ ! -d "$repo_dir/sources/libfprint" ]] || default_libfprint="$repo_dir/sources/libfprint"
[[ ! -d "$repo_dir/sources/fprintd" ]] || default_fprintd="$repo_dir/sources/fprintd"
libfprint_pristine="${GOODIX_MILAN_LIBFPRINT_SOURCE:-$default_libfprint}"
fprintd_pristine="${GOODIX_MILAN_FPRINTD_SOURCE:-$default_fprintd}"
ensure_source libfprint "$libfprint_pristine" "$MILAN_LIBFPRINT_URL" "$MILAN_LIBFPRINT_REVISION"
ensure_source fprintd "$fprintd_pristine" "$MILAN_FPRINTD_URL" "$MILAN_FPRINTD_REVISION"
"$repo_dir/patches/libfprint/verify-update-result-patch.sh" "$libfprint_pristine"
"$repo_dir/patches/libfprint/verify-goodix53x5-usb-persist-patch.sh" "$libfprint_pristine"
"$repo_dir/patches/libfprint/verify-idle-suspend-notify-patch.sh" "$libfprint_pristine"
"$repo_dir/patches/fprintd/verify-update-save-patch.sh" "$fprintd_pristine"
"$repo_dir/patches/fprintd/verify-serviced-session-patch.sh" "$fprintd_pristine"

mkdir -p "$MILAN_STACK_ROOT/builds"
exec 9>"$MILAN_STACK_ROOT/.build.lock"
flock -n 9 || milan_die "another Milan stack build or install is active"
staging="$MILAN_STACK_ROOT/builds/.staging.$$"
mkdir "$staging"
cleanup() {
  [[ ! -e "$staging" ]] || milan_safe_remove_tree "$staging" "$MILAN_STACK_ROOT/builds"
}
trap cleanup EXIT

mkdir "$staging/libfprint-overlay"
milan_run_stage "seed pinned libfprint checkout" git clone --local --no-hardlinks \
  "$libfprint_pristine" "$staging/libfprint-overlay/libfprint"
milan_run_stage "apply repository libfprint and driver overlay" env \
  GOODIX_LOCAL_BUILD_DIR="$staging/libfprint-overlay" \
  GOODIX_LIBFPRINT_REF="$MILAN_LIBFPRINT_REVISION" \
  GOODIX_LIBFPRINT_OFFLINE=1 \
  GOODIX_MESON_BUILDDIR=builddir \
  GOODIX53X5_DEBUG="$debug_manifest" \
  GOODIX53X5_INTERNAL_BUILD_ID="$debug_build_id" \
  GOODIX53X5_INTERNAL_SOURCE_ID="$debug_source_id" \
  "$script_dir/build-local.sh"

libfprint_source="$staging/libfprint-overlay/libfprint"
libfprint_build="$libfprint_source/builddir"
for patch in libfprint-update-result libfprint-goodix53x5-usb-persist libfprint-idle-suspend-notify; do
  git -C "$libfprint_source" apply --reverse --check "$repo_dir/patches/libfprint/$patch.patch"
done
milan_run_stage "configure libfprint" meson setup "$libfprint_build" "$libfprint_source" \
  --reconfigure --prefix=/usr --libdir="$libfprint_libdir" --sysconfdir=/etc --localstatedir=/var \
  -Ddrivers=goodix53x5 -Dudev_hwdb=disabled -Dudev_rules=disabled \
  -Dintrospection=false -Dinstalled-tests=false -Ddoc=false \
  -Dgoodix53x5_debug="$debug_enabled" \
  -Dgoodix53x5_debug_build_id="$debug_build_id" \
  -Dgoodix53x5_debug_source_id="$debug_source_id"
milan_run_stage "build libfprint" ninja -C "$libfprint_build"
milan_run_stage "test libfprint and Milan suites" meson test -C "$libfprint_build" --print-errorlogs \
  fpi-device goodix53x5-milan-synthetic goodix53x5-milan-state \
  goodix53x5-milan-runtime goodix53x5-milan-transport

fprintd_source="$staging/fprintd-source"
fprintd_build="$staging/fprintd-build"
milan_run_stage "clone pinned fprintd checkout" git clone --local --no-hardlinks \
  "$fprintd_pristine" "$fprintd_source"
git -C "$fprintd_source" apply "$repo_dir/patches/fprintd/1.94.5-milan-update-save.patch"
git -C "$fprintd_source" apply "$repo_dir/patches/fprintd/1.94.5-serviced-session.patch"
git -C "$fprintd_source" apply --reverse --check "$repo_dir/patches/fprintd/1.94.5-serviced-session.patch"
milan_run_stage "configure fprintd against paired libfprint" "${fprintd_env[@]}" meson devenv -C "$libfprint_build" \
  meson setup "$fprintd_build" "$fprintd_source" --prefix=/usr \
  --libdir="$MILAN_LIBDIR" --libexecdir="$(dirname "$MILAN_DAEMON_PATH")" \
  --sysconfdir=/etc --localstatedir=/var \
  -Dpam=true -Dpam_modules_dir="$MILAN_LIBDIR/security" \
  -Dman=true -Dsystemd=true -Dsystemd_system_unit_dir=/usr/lib/systemd/system \
  -Ddbus_service_dir=/usr/share/dbus-1/system-services -Dgtk_doc=false
milan_run_stage "build fprintd" meson devenv -C "$libfprint_build" ninja -C "$fprintd_build"

payload="$staging/payload"
mkdir -p "$payload$MILAN_METADATA_DIR" "$payload$(dirname "$MILAN_UDEV_RULE")"
milan_run_stage "stage libfprint" env DESTDIR="$payload" ninja -C "$libfprint_build" install
milan_run_stage "stage fprintd" env DESTDIR="$payload" ninja -C "$fprintd_build" install
install -m 0644 "$repo_dir/udev/$(basename "$MILAN_UDEV_RULE")" "$payload$MILAN_UDEV_RULE"

if [[ -n "$package_root" ]]; then
  # Development files and AppStream metadata would collide with the
  # distribution's libfprint packages; packages keep no source-install metadata.
  rm -rf -- "$payload/usr/include" "$payload$libfprint_libdir/pkgconfig" "$payload$libfprint_libdir/libfprint-2.so" \
    "$payload/usr/share/metainfo" "$payload$MILAN_METADATA_DIR"
  milan_verify_runtime_files "$payload" 0
  readelf -d "$payload$MILAN_DAEMON_PATH" | grep -Eq "\((RUNPATH|RPATH)\).*\[$libfprint_libdir\]" ||
    milan_die "packaged daemon does not load the private libfprint"
  mkdir -p "$package_root"
  cp -a "$payload/." "$package_root/"
  milan_note "staged verified package payload: $package_root"
  exit 0
fi

if [[ "$debug_manifest" == 1 ]]; then
  install -d -m 0755 "$payload$(dirname "$MILAN_DEBUG_LOGGING_DROPIN")"
  cat > "$payload$MILAN_DEBUG_LOGGING_DROPIN" <<'EOF'
[Service]
Environment=G_MESSAGES_DEBUG=libfprint-goodix53x5
Environment=GOODIX53X5_LOG_TIMING=1
Environment=GOODIX53X5_LOG_DIAGNOSTICS=1
EOF
fi

cat > "$payload$MILAN_BUILD_ENV" <<EOF
FORMAT=3
VERSION=$(milan_source_version "$repo_dir")
LIBDIR=$MILAN_LIBDIR
LIBRARY_PATH=$MILAN_LIBRARY_PATH
DAEMON_PATH=$MILAN_DAEMON_PATH
GOODIX53X5_DEBUG=$debug_manifest
GOODIX53X5_DEBUG_BUILD_ID=$debug_build_id
GOODIX53X5_DEBUG_SOURCE_ID=$debug_source_id
LIBFPRINT_REVISION=$MILAN_LIBFPRINT_REVISION
FPRINTD_REVISION=$MILAN_FPRINTD_REVISION
OVERLAY_REVISION=$(milan_source_revision "$repo_dir")
OVERLAY_INPUT_SHA256=$(milan_overlay_input_sha256 "$repo_dir")
BUILT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
milan_files inventory "$payload"
milan_verify_payload "$payload" "$repo_dir"

for intermediate in "$staging/libfprint-overlay" "$fprintd_source" "$fprintd_build"; do
  milan_safe_remove_tree "$intermediate" "$staging"
done

published="$MILAN_STACK_ROOT/builds/$(date -u +%Y%m%dT%H%M%SZ)-$build_kind-$$"
mv "$staging" "$published"
trap - EXIT
link_tmp="$MILAN_STACK_ROOT/builds/.current.$$"
ln -s "$(basename "$published")" "$link_tmp"
mv -Tf "$link_tmp" "$MILAN_STACK_ROOT/builds/current"
shopt -s dotglob
for obsolete in "$MILAN_STACK_ROOT/builds"/*; do
  [[ "$obsolete" != "$published" && "$obsolete" != "$MILAN_STACK_ROOT/builds/current" ]] || continue
  if [[ -L "$obsolete" ]]; then
    rm -- "$obsolete"
  elif [[ -d "$obsolete" ]]; then
    milan_safe_remove_tree "$obsolete" "$MILAN_STACK_ROOT/builds"
  fi
done
milan_note "published verified $build_kind Milan stack: $published"
