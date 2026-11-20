#!/usr/bin/env bash
# Remove the files recorded by the installer; print state is never touched.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$script_dir/lib/milan-stack-common.sh"

milan_require_root
for command in python3 flock udevadm systemctl ldconfig; do
  milan_require_command "$command"
done
milan_lock_install

if [[ ! -e "$MILAN_INVENTORY" ]]; then
  milan_unmask_runtime
  milan_note "manual Milan installation is already absent"
  exit 0
fi

milan_mask_runtime
milan_files remove / ||
  milan_die "file removal incomplete; fprintd stays runtime-masked. Fix the reported problem and rerun."
ldconfig
udevadm control --reload-rules
systemctl daemon-reload
milan_unmask_runtime
milan_note "removed the recorded Milan files; no daemon was restarted"
milan_note "print state under /var/lib/fprint was not touched"
