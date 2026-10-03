#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'Usage: sudo %s OUTPUT_FILE\n' "$0"
}

[[ "$#" == 1 ]] || { usage >&2; exit 2; }
[[ "${EUID:-$(id -u)}" == 0 ]] || {
  printf 'error: this command must run as root\n' >&2
  exit 1
}

output=$1
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_file=$script_dir/goodix53x5-extract-windows-psk.c
owner_uid=${SUDO_UID:-0}
owner_gid=${SUDO_GID:-0}

[[ ! -e "$output" ]] || {
  printf 'error: output already exists: %s\n' "$output" >&2
  exit 1
}
[[ -f "$source_file" ]] || {
  printf 'error: missing dumper source: %s\n' "$source_file" >&2
  exit 1
}

service_state=$(systemctl is-enabled fprintd.service 2>/dev/null || true)
[[ "$service_state" == masked ]] || {
  printf 'error: fprintd must be masked before booting Windows and remain masked during extraction\n' >&2
  printf '       Run: sudo systemctl mask --now fprintd.service\n' >&2
  exit 1
}
active_state=$(systemctl show fprintd.service -p ActiveState --value)
if [[ "$active_state" != inactive ]]; then
  printf 'error: fprintd must be inactive before extraction (currently %s)\n' \
    "$active_state" >&2
  exit 1
fi

for command in cc pkg-config; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command not found: %s\n' "$command" >&2
    exit 1
  }
done
pkg-config --exists gusb || {
  printf 'error: GUsb development files are required (pkg-config module gusb)\n' >&2
  exit 1
}

binary=$(mktemp /tmp/goodix53x5-extract-windows-psk.XXXXXX)
trap 'rm -f -- "$binary"' EXIT
# Word splitting is intentional for pkg-config compiler and linker flags.
# shellcheck disable=SC2046
cc -std=gnu11 -O2 -Wall -Wextra $(pkg-config --cflags gusb) \
  "$source_file" -o "$binary" $(pkg-config --libs gusb)
"$binary" --self-test
"$binary" "$output"
chown -h -- "$owner_uid:$owner_gid" "$output"
printf 'Saved the verified Windows PSK to %s\n' "$output"
