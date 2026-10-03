#!/usr/bin/env bash
# Install the published build into the system paths recorded by the builder.

set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$script_dir/lib/milan-stack-common.sh"

milan_require_root
milan_reject_ephemeral_root "GOODIX_MILAN_STACK_ROOT" "$MILAN_STACK_ROOT"
for command in python3 flock udevadm systemctl ldconfig ldd; do
  milan_require_command "$command"
done
milan_lock_install
milan_open_publication
milan_verify_payload "$MILAN_PAYLOAD" "$repo_dir"
milan_files preflight / "$MILAN_PAYLOAD"
milan_check_admin_mask

install_failed() {
  local rc=$?
  trap - EXIT
  if milan_mask_runtime; then
    printf 'error: install incomplete; fprintd stays runtime-masked. Fix the reported problem and rerun the installer to resume.\n' >&2
  else
    printf 'error: install incomplete and fprintd could not be masked; keep it stopped while you inspect the installation.\n' >&2
  fi
  exit "$rc"
}
trap install_failed EXIT
# A plain stop is not enough: D-Bus would reactivate a half-replaced pair.
milan_mask_runtime
milan_files install / "$MILAN_PAYLOAD"
ldconfig
milan_trigger_udev
systemctl daemon-reload
milan_unmask_runtime
# Enumeration eagerly opens the sensor, including on installs without a reboot.
systemctl restart fprintd.service
milan_verify_active_system
trap - EXIT
milan_note "installed paired Milan libfprint and fprintd $(milan_recorded_version /) under /usr"
milan_note "print state under /var/lib/fprint was not touched"
