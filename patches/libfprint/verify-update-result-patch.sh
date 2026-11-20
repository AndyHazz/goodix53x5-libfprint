#!/usr/bin/env bash

set -euo pipefail

expected_revision="0c97a47d8ef405cd577b87058c1e89cae9d242e7"
expected_sha256="fa9a4a89df02894a01013dc787d06cdbb74a4908b8e3cdc5da745e0265fb2f72"
source_dir="${1:?usage: $0 PRISTINE_LIBFPRINT_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/libfprint-update-result.patch"

actual_revision="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  printf 'refusing to apply: expected %s, got %s\n' \
    "$expected_revision" "$actual_revision" >&2
  exit 1
fi

if [[ -n "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ]]; then
  printf 'refusing to check patch against tracked source changes\n' >&2
  exit 1
fi

grep -Fxq "Base-Revision: $expected_revision" "$patch_path"
actual_sha256="$(sha256sum "$patch_path" | cut -d ' ' -f 1)"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  printf 'refusing to apply: expected patch SHA-256 %s, got %s\n' \
    "$expected_sha256" "$actual_sha256" >&2
  exit 1
fi
git -C "$source_dir" apply --check "$patch_path"

printf 'patch applies cleanly to %s\n' "$expected_revision"
