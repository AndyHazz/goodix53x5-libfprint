#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'Usage: sudo %s [--replace] PSK_FILE\n' "$0"
}

replace=0
if [[ "${1:-}" == --replace ]]; then
  replace=1
  shift
fi
[[ "$#" == 1 ]] || { usage >&2; exit 2; }
[[ "${EUID:-$(id -u)}" == 0 ]] || {
  printf 'error: this command must run as root\n' >&2
  exit 1
}

service_state=$(systemctl is-enabled fprintd.service 2>/dev/null || true)
[[ "$service_state" == masked ]] || {
  printf 'error: fprintd must remain masked while installing the Windows PSK\n' >&2
  exit 1
}
active_state=$(systemctl show fprintd.service -p ActiveState --value)
if [[ "$active_state" != inactive ]]; then
  printf 'error: fprintd must be inactive before installing the Windows PSK (currently %s)\n' \
    "$active_state" >&2
  exit 1
fi

source_file=$1
state_dir=/var/lib/fprint
state_file=$state_dir/goodix53x5.psk
backup_file=$state_dir/goodix53x5.psk.previous

[[ -f "$source_file" ]] || {
  printf 'error: PSK file does not exist: %s\n' "$source_file" >&2
  exit 1
}

if [[ "$(stat -c %s "$source_file")" == 32 ]]; then
  psk=$(od -An -tx1 -v "$source_file" | tr -d '[:space:]')
else
  psk=$(tr -d '[:space:]' < "$source_file")
fi
[[ "$psk" =~ ^[[:xdigit:]]{64}$ ]] || {
  printf 'error: PSK file must contain 32 raw bytes or exactly 64 hexadecimal characters\n' >&2
  exit 1
}

install -d -m 0700 "$state_dir"
if [[ -e "$state_file" ]]; then
  (( replace == 1 )) || {
    printf 'error: %s already exists; use --replace to preserve and replace it\n' \
      "$state_file" >&2
    exit 1
  }
  [[ ! -e "$backup_file" ]] || {
    printf 'error: backup already exists: %s\n' "$backup_file" >&2
    exit 1
  }
  install -m 0600 -o root -g root "$state_file" "$backup_file"
  printf 'Preserved the previous PSK at %s\n' "$backup_file"
fi

tmp=$(mktemp "$state_dir/.goodix53x5.psk.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
printf '%s\n' "$psk" > "$tmp"
chmod 0600 "$tmp"
chown root:root "$tmp"
sync -f "$tmp"
mv -f -- "$tmp" "$state_file"
sync -f "$state_dir"
trap - EXIT

printf 'Installed Windows GTLS PSK at %s\n' "$state_file"
printf 'fprintd remains masked; unmask and restart it after returning to the migration guide.\n'
