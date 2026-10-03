#!/usr/bin/env bash

set -euo pipefail

expected_revision="0c97a47d8ef405cd577b87058c1e89cae9d242e7"
source_dir="${1:?usage: $0 MODIFIED_LIBFPRINT_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/libfprint-idle-suspend-notify.patch"

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$expected_revision" ]] || {
  printf 'refusing to generate: unexpected libfprint revision\n' >&2
  exit 1
}
git -C "$source_dir" diff --check
{
  printf 'Libfprint-Idle-Suspend-Notify-Patch: 4\n'
  printf 'Base-Revision: %s\n' "$expected_revision"
  printf 'Base-Tag: v1.94.10\n\n'
  git -C "$source_dir" diff --binary --full-index --no-ext-diff -- \
    libfprint/fp-device.c libfprint/fpi-device.c libfprint/fpi-device.h \
    tests/test-fpi-device.c
} > "$patch_path"

printf '%s\n' "$patch_path"
