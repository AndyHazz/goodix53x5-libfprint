#!/usr/bin/env bash

set -euo pipefail

expected_revision="b54a007ccf58ac0ae074c7151b223f35cbd17306"
source_dir="${1:?usage: $0 MODIFIED_FPRINTD_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/1.94.5-milan-update-save.patch"
hash_path="$patch_path.sha256"

actual_revision="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  printf 'refusing to generate: expected %s, got %s\n' \
    "$expected_revision" "$actual_revision" >&2
  exit 1
fi

git -C "$source_dir" diff --check
{
  printf 'Fprintd-Milan-Update-Save-Patch: 1\n'
  printf 'Base-Revision: %s\n' "$expected_revision"
  printf 'Base-Tag: v1.94.5\n\n'
  git -C "$source_dir" diff --binary --full-index --no-ext-diff --
} > "$patch_path"

(
  cd "$script_dir"
  sha256sum "$(basename "$patch_path")" > "$(basename "$hash_path")"
)

printf '%s\n' "$patch_path"
