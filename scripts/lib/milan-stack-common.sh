#!/usr/bin/env bash

MILAN_LIBFPRINT_REVISION="0c97a47d8ef405cd577b87058c1e89cae9d242e7"
MILAN_FPRINTD_REVISION="b54a007ccf58ac0ae074c7151b223f35cbd17306"
MILAN_LIBFPRINT_PATCH_SHA256="fa9a4a89df02894a01013dc787d06cdbb74a4908b8e3cdc5da745e0265fb2f72"
MILAN_LIBFPRINT_USB_PERSIST_PATCH_SHA256="743c13782228869b8b5ea834caa096abadd38e5542303d7af8bc7acb4c925ae0"
MILAN_LIBFPRINT_IDLE_SUSPEND_NOTIFY_PATCH_SHA256="7bbdb229e0de58e6b454d5117e517143fc78043beab3bae5596021c21fba67fc"
MILAN_FPRINTD_PATCH_SHA256="5d87cd806587fa5f035847a38ba3155b38f9a612a3070d9abfa6f83114e58db8"
MILAN_FPRINTD_SESSION_PATCH_SHA256="e8b3acd37fb490e1542c9599bdeed485266c4ab2fdfbda304600ca828f75ef69"
MILAN_LIBFPRINT_URL="${GOODIX_MILAN_LIBFPRINT_URL:-https://gitlab.freedesktop.org/libfprint/libfprint.git}"
MILAN_FPRINTD_URL="${GOODIX_MILAN_FPRINTD_URL:-https://gitlab.freedesktop.org/libfprint/fprintd.git}"
# Distribution packages keep this libfprint in a private directory of this name.
MILAN_PACKAGE_LIBRARY_NAME="libfprint-goodix53x5"
MILAN_METADATA_DIR="/usr/share/goodix53x5-milan"
MILAN_BUILD_ENV="$MILAN_METADATA_DIR/build.env"
MILAN_INVENTORY="$MILAN_METADATA_DIR/inventory.json"
MILAN_UDEV_RULE="/usr/lib/udev/rules.d/99-goodix53x5-milan-persist.rules"
MILAN_DEBUG_LOGGING_DROPIN="/usr/lib/systemd/system/fprintd.service.d/90-goodix53x5-debug-logging.conf"
MILAN_FILES_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/milan-stack-files.py"

milan_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

milan_note() {
  printf '%s\n' "$*"
}

milan_require_command() {
  command -v "$1" >/dev/null 2>&1 || milan_die "required command not found: $1"
}

milan_require_absolute() {
  case "$2" in
    /*) ;;
    *) milan_die "$1 must be an absolute path: $2" ;;
  esac
}

milan_reject_ephemeral_root() {
  milan_require_absolute "$1" "$2"
  case "$2/" in
    /tmp/|/tmp/*|/var/tmp/|/var/tmp/*|/run/|/run/*)
      milan_die "$1 must be persistent, not $2"
      ;;
  esac
}

milan_invoking_home() {
  local entry

  if [[ "${EUID:-$(id -u)}" == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    milan_require_command getent
    entry="$(getent passwd "$SUDO_USER")"
    [[ -n "$entry" ]] || milan_die "cannot resolve home for $SUDO_USER"
    printf '%s\n' "$(cut -d: -f6 <<<"$entry")"
  else
    [[ -n "${HOME:-}" ]] || milan_die "HOME is not set"
    printf '%s\n' "$HOME"
  fi
}

milan_default_stack_root() {
  local home state_home

  home="$(milan_invoking_home)"
  if [[ "${EUID:-$(id -u)}" != 0 && -n "${XDG_STATE_HOME:-}" ]]; then
    state_home="$XDG_STATE_HOME"
  else
    state_home="$home/.local/state"
  fi
  printf '%s\n' "$state_home/goodix53x5-milan"
}

MILAN_STACK_ROOT="${GOODIX_MILAN_STACK_ROOT:-$(milan_default_stack_root)}"

# Select the distribution's library directory and fprintd executable path.
milan_detect_layout() {
  local ID= ID_LIKE= multiarch
  [[ ! -r /etc/os-release ]] || source /etc/os-release
  MILAN_LIBDIR=/usr/lib
  MILAN_DAEMON_PATH=/usr/libexec/fprintd
  case " $ID $ID_LIKE " in
    *" arch "*) MILAN_DAEMON_PATH=/usr/lib/fprintd ;;
    *" debian "*|*" ubuntu "*)
      multiarch="$("${CC:-cc}" -print-multiarch 2>/dev/null || true)"
      [[ -n "$multiarch" ]] || multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
      [[ "$multiarch" =~ ^[a-zA-Z0-9_-]+$ ]] || milan_die "cannot determine Debian multiarch tuple"
      MILAN_LIBDIR="/usr/lib/$multiarch" ;;
    *" fedora "*|*" rhel "*|*" centos "*|*" suse "*)
      milan_require_command rpm
      MILAN_LIBDIR="$(rpm --eval '%{_libdir}')" ;;
  esac
  MILAN_LIBRARY_PATH="$MILAN_LIBDIR/libfprint-2.so.2.0.0"
}

# Read the layout recorded by the build that produced $1 (payload dir or /).
milan_load_layout() {
  local manifest="${1%/}$MILAN_BUILD_ENV"
  [[ "$(milan_manifest_value "$manifest" FORMAT)" == 3 ]] || milan_die "unsupported build manifest: $manifest"
  MILAN_LIBDIR="$(milan_manifest_value "$manifest" LIBDIR)"
  MILAN_LIBRARY_PATH="$(milan_manifest_value "$manifest" LIBRARY_PATH)"
  MILAN_DAEMON_PATH="$(milan_manifest_value "$manifest" DAEMON_PATH)"
}

milan_sha256() {
  sha256sum "$1" | cut -d ' ' -f 1
}

milan_overlay_input_sha256() {
  (
    cd "$1"
    find drivers/goodix53x5 tests udev -type f -print0 |
      LC_ALL=C sort -z |
      xargs -0 sha256sum
    sha256sum meson-integration.patch scripts/build-local.sh \
      patches/libfprint/libfprint-update-result.patch \
      patches/libfprint/libfprint-goodix53x5-usb-persist.patch \
      patches/libfprint/libfprint-idle-suspend-notify.patch \
      patches/fprintd/1.94.5-milan-update-save.patch \
      patches/fprintd/1.94.5-serviced-session.patch
  ) | sha256sum | cut -d ' ' -f 1
}

milan_manifest_value() {
  local manifest="$1" key="$2" line

  line="$(grep -E "^${key}=" "$manifest" || true)"
  [[ -n "$line" && "$line" != *$'\n'* ]] || milan_die "missing or duplicate $key in $manifest"
  printf '%s\n' "${line#*=}"
}

# Release archives record their version in release.env; checkouts use tags.
milan_source_version() {
  local repo_dir="$1" described

  if [[ -f "$repo_dir/release.env" ]]; then
    milan_manifest_value "$repo_dir/release.env" VERSION
  elif described="$(git -C "$repo_dir" describe --tags --match 'v[0-9]*' --dirty 2>/dev/null)"; then
    printf '%s\n' "${described#v}"
  else
    printf '0.0.0+g%s\n' "$(git -C "$repo_dir" rev-parse --short HEAD)"
  fi
}

# Builds from before version recording have no VERSION entry.
milan_recorded_version() {
  local version
  version="$(sed -n 's/^VERSION=//p' "${1%/}$MILAN_BUILD_ENV")"
  printf '%s\n' "${version:-unknown}"
}

milan_source_revision() {
  if [[ -f "$1/release.env" ]]; then
    milan_manifest_value "$1/release.env" REVISION
  else
    git -C "$1" rev-parse HEAD
  fi
}

milan_verify_repo_inputs() {
  local repo_dir="$1"

  [[ "$(milan_sha256 "$repo_dir/patches/libfprint/libfprint-update-result.patch")" == "$MILAN_LIBFPRINT_PATCH_SHA256" ]] ||
    milan_die "libfprint patch digest mismatch"
  [[ "$(milan_sha256 "$repo_dir/patches/libfprint/libfprint-goodix53x5-usb-persist.patch")" == "$MILAN_LIBFPRINT_USB_PERSIST_PATCH_SHA256" ]] ||
    milan_die "libfprint USB persist patch digest mismatch"
  [[ "$(milan_sha256 "$repo_dir/patches/libfprint/libfprint-idle-suspend-notify.patch")" == "$MILAN_LIBFPRINT_IDLE_SUSPEND_NOTIFY_PATCH_SHA256" ]] ||
    milan_die "libfprint idle suspend notification patch digest mismatch"
  [[ "$(milan_sha256 "$repo_dir/patches/fprintd/1.94.5-milan-update-save.patch")" == "$MILAN_FPRINTD_PATCH_SHA256" ]] ||
    milan_die "fprintd patch digest mismatch"
  [[ "$(milan_sha256 "$repo_dir/patches/fprintd/1.94.5-serviced-session.patch")" == "$MILAN_FPRINTD_SESSION_PATCH_SHA256" ]] ||
    milan_die "fprintd serviced-session patch digest mismatch"
}

milan_verify_git_pristine() {
  local source_dir="$1" expected="$2" label="$3" actual

  [[ -d "$source_dir/.git" ]] || milan_die "$label is not a git checkout: $source_dir"
  actual="$(git -C "$source_dir" rev-parse HEAD)"
  [[ "$actual" == "$expected" ]] || milan_die "$label revision mismatch: expected $expected, got $actual"
  [[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]] ||
    milan_die "$label checkout is dirty: $source_dir"
}

milan_run_stage() {
  milan_note "==> $1"
  shift
  "$@"
}

milan_files() {
  python3 "$MILAN_FILES_HELPER" "$@"
}

# Locate builds/current and hold it shared so the builder cannot prune it.
milan_open_publication() {
  local current="$MILAN_STACK_ROOT/builds/current"
  [[ -L "$current" && -f "$MILAN_STACK_ROOT/.build.lock" ]] ||
    milan_die "no published stack; run build-milan-stack-local.sh"
  exec 8<"$MILAN_STACK_ROOT/.build.lock"
  flock -sn 8 || milan_die "a Milan build is publishing; retry when it finishes"
  MILAN_PAYLOAD="$(readlink -f "$current")/payload"
}

# Check a staged payload against this checkout and its own inventory.
milan_verify_payload() {
  local payload="$1" repo_dir="$2" manifest="$1$MILAN_BUILD_ENV" debug

  milan_files verify-build "$payload"
  milan_load_layout "$payload"
  [[ "$(milan_manifest_value "$manifest" LIBFPRINT_REVISION)" == "$MILAN_LIBFPRINT_REVISION" ]] || milan_die "libfprint revision mismatch"
  [[ "$(milan_manifest_value "$manifest" FPRINTD_REVISION)" == "$MILAN_FPRINTD_REVISION" ]] || milan_die "fprintd revision mismatch"
  [[ "$(milan_manifest_value "$manifest" OVERLAY_INPUT_SHA256)" == "$(milan_overlay_input_sha256 "$repo_dir")" ]] ||
    milan_die "published build does not match this checkout; rebuild"
  debug="$(milan_manifest_value "$manifest" GOODIX53X5_DEBUG)"
  [[ "$debug" == 0 || "$debug" == 1 ]] || milan_die "invalid debug manifest value"
  milan_verify_runtime_files "$payload" "$debug"
}

# Check the runtime files staged below $1; $2 is the expected debug flag.
milan_verify_runtime_files() {
  local payload="$1" debug="$2" path

  milan_verify_debug_census "$payload" "$debug"
  for path in "$MILAN_DAEMON_PATH" "$MILAN_LIBRARY_PATH" "$MILAN_LIBDIR/security/pam_fprintd.so" \
      /usr/bin/fprintd-enroll /usr/bin/fprintd-verify /usr/bin/fprintd-list /usr/bin/fprintd-delete \
      /usr/share/dbus-1/system-services/net.reactivated.Fprint.service "$MILAN_UDEV_RULE"; do
    [[ -f "$payload$path" ]] || milan_die "incomplete runtime payload: $path"
  done
  [[ "$(readlink "$payload$(dirname "$MILAN_LIBRARY_PATH")/libfprint-2.so.2")" == libfprint-2.so.2.0.0 ]] ||
    milan_die "invalid soname symlink"
  grep -Fxq "ExecStart=$MILAN_DAEMON_PATH" "$payload/usr/lib/systemd/system/fprintd.service" ||
    milan_die "staged service selects wrong daemon"
  if [[ "$debug" == 1 ]]; then
    [[ -f "$payload$MILAN_DEBUG_LOGGING_DROPIN" ]] ||
      milan_die "debug payload lacks fprintd logging configuration"
    grep -Fxq 'Environment=G_MESSAGES_DEBUG=libfprint-goodix53x5' "$payload$MILAN_DEBUG_LOGGING_DROPIN" ||
      milan_die "debug payload does not enable Goodix debug messages"
    grep -Fxq 'Environment=GOODIX53X5_LOG_TIMING=1' "$payload$MILAN_DEBUG_LOGGING_DROPIN" ||
      milan_die "debug payload does not enable timing logs"
    grep -Fxq 'Environment=GOODIX53X5_LOG_DIAGNOSTICS=1' "$payload$MILAN_DEBUG_LOGGING_DROPIN" ||
      milan_die "debug payload does not enable diagnostic logs"
  elif [[ -e "$payload$MILAN_DEBUG_LOGGING_DROPIN" ]]; then
    milan_die "release payload contains debug logging configuration"
  fi
}

# $1 is the root holding the library (payload dir or /); $2 is the expected debug flag.
milan_verify_debug_census() {
  if grep -Fq GOODIX53X5_DUMP_DIR < <(strings "${1%/}$MILAN_LIBRARY_PATH"); then
    [[ "$2" == 1 ]] || milan_die "release payload contains debug diagnostics"
  else
    [[ "$2" == 0 ]] || milan_die "debug payload lacks debug diagnostics"
  fi
}

milan_verify_ldd() {
  local output resolved

  output="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD ldd "$MILAN_DAEMON_PATH")" ||
    milan_die "ldd failed for installed daemon"
  resolved="$(awk '$1 == "libfprint-2.so.2" && $2 == "=>" {print $3}' <<<"$output")"
  [[ -n "$resolved" && "$(readlink -f "$resolved")" == "$(readlink -f "$MILAN_LIBRARY_PATH")" ]] ||
    milan_die "daemon resolves wrong libfprint: ${resolved:-none}"
  [[ "$output" != *"not found"* ]] || milan_die "daemon has unresolved dependencies"
}

milan_verify_active_system() {
  local shown

  shown="$(systemctl show fprintd.service --property=ExecStart --no-pager)" || milan_die "cannot query fprintd.service"
  [[ "$shown" == *"path=$MILAN_DAEMON_PATH ;"* ]] || milan_die "installed daemon is not selected"
  milan_verify_ldd
}

milan_require_root() {
  [[ "${EUID:-$(id -u)}" == 0 ]] || milan_die "run as root: sudo $0"
}

milan_lock_install() {
  exec 9>/run/goodix53x5-milan-install.lock
  flock -n 9 || milan_die "another Milan install/remove is active"
}

milan_check_admin_mask() {
  [[ "$(systemctl is-enabled fprintd.service 2>/dev/null || true)" != masked ]] ||
    milan_die "fprintd is permanently masked; unmask it before installing"
}

# Block D-Bus activation while files change. Runtime masks never touch /etc.
milan_mask_runtime() {
  systemctl mask --runtime --now fprintd.service || return
  [[ "$(systemctl show fprintd.service --property=LoadState --value)" == masked ]] || {
    printf 'error: fprintd is still activatable; check for an overriding unit in /etc/systemd/system\n' >&2
    return 1
  }
}

milan_unmask_runtime() {
  systemctl unmask --runtime fprintd.service
}

# Apply the persistence rule to Milan sensors that are already attached.
milan_trigger_udev() {
  udevadm control --reload-rules
  udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --action=add
}

milan_safe_remove_tree() {
  local path="$1" parent="$2" resolved_path resolved_parent

  resolved_path="$(readlink -m "$path")"
  resolved_parent="$(readlink -m "$parent")"
  [[ "$resolved_path" != "$resolved_parent" && "$(dirname "$resolved_path")" == "$resolved_parent" ]] ||
    milan_die "refusing unsafe tree removal: $path"
  rm -rf -- "$resolved_path"
}
