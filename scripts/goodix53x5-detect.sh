#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_file=$script_dir/goodix53x5-detect.c
binary=
restart_fprintd=0

cleanup() {
  local status=$?

  trap - EXIT
  if [[ -n "$binary" ]]; then
    if ! rm -f -- "$binary"; then
      printf 'warning: could not remove temporary probe binary\n' >&2
      status=2
    fi
  fi
  if [[ "$restart_fprintd" == 1 ]]; then
    if ! systemctl start fprintd.service; then
      printf 'warning: could not restart fprintd.service\n' >&2
      status=2
    fi
  fi
  exit "$status"
}

[[ "${EUID:-$(id -u)}" == 0 ]] || {
  printf 'error: this probe needs direct USB access; run it with sudo:\n' >&2
  printf '       sudo %s\n' "$0" >&2
  exit 2
}
trap cleanup EXIT
if command -v systemctl >/dev/null 2>&1 &&
   systemctl is-active --quiet fprintd.service 2>/dev/null; then
  restart_fprintd=1
  systemctl stop fprintd.service
fi

for command in cc pkg-config; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command not found: %s\n' "$command" >&2
    exit 2
  }
done
pkg-config --exists gusb || {
  printf 'error: GUsb development files are required (pkg-config module gusb)\n' >&2
  exit 2
}
[[ -f "$source_file" ]] || {
  printf 'error: missing probe source: %s\n' "$source_file" >&2
  exit 2
}

binary=$(mktemp /tmp/goodix53x5-detect.XXXXXX)
# Word splitting is intentional for pkg-config compiler and linker flags.
# shellcheck disable=SC2046
cc -std=gnu11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags gusb) \
  "$source_file" -o "$binary" $(pkg-config --libs gusb)
"$binary" --self-test
"$binary"
