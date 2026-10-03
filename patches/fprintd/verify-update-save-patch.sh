#!/usr/bin/env bash

set -euo pipefail

expected_revision="b54a007ccf58ac0ae074c7151b223f35cbd17306"
source_dir="${1:?usage: $0 PRISTINE_FPRINTD_SOURCE}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patch_path="$script_dir/1.94.5-milan-update-save.patch"
hash_path="$patch_path.sha256"

actual_revision="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  printf 'refusing to apply: expected %s, got %s\n' \
    "$expected_revision" "$actual_revision" >&2
  exit 1
fi

if [[ -n "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]]; then
  printf 'refusing to check patch against a non-pristine source tree\n' >&2
  exit 1
fi

grep -Fxq "Base-Revision: $expected_revision" "$patch_path"
grep -Fq 'fp_device_verify_finish_with_update' "$patch_path"
grep -Fq 'fp_device_identify_finish_with_update' "$patch_path"
grep -Fq 'store.print_data_save' "$patch_path"
if grep -Eiq 'compare.and.replace|storage.transaction|adaptive.storage|flock|INDETERMINATE' "$patch_path"; then
  printf 'refusing patch containing removed transaction/CAS machinery\n' >&2
  exit 1
fi
forbidden_pattern="$(printf '%b' 'persistence[-_]\x63apture|GOODIX53X5_NATIVE_\x43APTURE|\x43APTURE_ID|DUMP_DIR|\x63ampaign|/home/|re/|research/|results/')"
if grep -Eiq "$forbidden_pattern" "$patch_path"; then
  printf 'refusing patch containing private or non-production material\n' >&2
  exit 1
fi
(
  cd "$script_dir"
  sha256sum --check "$(basename "$hash_path")"
)
git -C "$source_dir" apply --check "$patch_path"

printf 'patch applies cleanly to %s\n' "$expected_revision"
