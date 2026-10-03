#!/usr/bin/env bash
set -euo pipefail

source_dir="${1:?usage: $0 PRISTINE_FPRINTD_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$script_dir/verify-update-save-patch.sh" "$source_dir"
(
  cd "$script_dir"
  sha256sum --check 1.94.5-serviced-session.patch.sha256
)
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
git -C "$source_dir" archive HEAD | tar -x -C "$scratch"
git -C "$scratch" apply "$script_dir/1.94.5-milan-update-save.patch"
git -C "$scratch" apply --check "$script_dir/1.94.5-serviced-session.patch"
git -C "$scratch" apply "$script_dir/1.94.5-serviced-session.patch"
git -C "$scratch" apply --reverse --check "$script_dir/1.94.5-serviced-session.patch"
git -C "$scratch" apply --reverse "$script_dir/1.94.5-serviced-session.patch"
git -C "$scratch" apply --reverse --check "$script_dir/1.94.5-milan-update-save.patch"
printf 'serviced-session overlays compose and reverse cleanly\n'
