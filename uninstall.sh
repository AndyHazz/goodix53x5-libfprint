#!/usr/bin/env bash
# Remove recorded unchanged Milan files without touching print or PSK state.

set -euo pipefail

usage() {
  printf 'Usage: %s\n' "$0"
}

case "${1:-}" in
  "") ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 1 ;;
esac
[[ "$#" -eq 0 ]] || { usage >&2; exit 1; }

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID:-$(id -u)}" == 0 ]]; then
  "$repo_dir/scripts/remove-milan-stack-local.sh"
else
  command -v sudo >/dev/null 2>&1 || {
    printf 'error: sudo is required to remove the Milan stack\n' >&2
    exit 1
  }
  sudo "$repo_dir/scripts/remove-milan-stack-local.sh"
fi
