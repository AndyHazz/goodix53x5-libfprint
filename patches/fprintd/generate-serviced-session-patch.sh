#!/usr/bin/env bash
set -euo pipefail

expected_revision=b54a007ccf58ac0ae074c7151b223f35cbd17306
source_dir="${1:?usage: $0 MODIFIED_FPRINTD_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/1.94.5-serviced-session.patch"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$expected_revision" ]]

# Diff against the preceding overlay without modifying the source's index.
index="$(mktemp)"
trap 'rm -f "$index"' EXIT
export GIT_INDEX_FILE="$index"
git -C "$source_dir" read-tree HEAD
git -C "$source_dir" apply --cached "$script_dir/1.94.5-milan-update-save.patch"
git -C "$source_dir" diff --check
{
  printf 'Fprintd-Serviced-Session-Patch: 1\nBase-Revision: %s\n' "$expected_revision"
  printf 'Requires: 1.94.5-milan-update-save.patch\n\n'
  git -C "$source_dir" diff --binary --full-index --no-ext-diff -- \
    src/device.c src/manager.c src/main.c src/fprintd.h
} > "$patch_path"
(
  cd "$script_dir"
  sha256sum "$(basename "$patch_path")" > "$(basename "$patch_path").sha256"
)
