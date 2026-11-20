#!/usr/bin/env bash

set -euo pipefail

expected_revision="0c97a47d8ef405cd577b87058c1e89cae9d242e7"
source_dir="${1:?usage: $0 MODIFIED_LIBFPRINT_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/libfprint-update-result.patch"

actual_revision="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  printf 'refusing to generate: expected %s, got %s\n' \
    "$expected_revision" "$actual_revision" >&2
  exit 1
fi

git -C "$source_dir" diff --check

{
  printf 'Libfprint-Update-Result-Patch: 1\n'
  printf 'Base-Revision: %s\n' "$expected_revision"
  printf 'Base-Tag: v1.94.10\n\n'
  git -C "$source_dir" diff --binary --full-index --no-ext-diff --
} > "$patch_path"

printf '%s\n' "$patch_path"
