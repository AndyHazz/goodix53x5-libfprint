#!/usr/bin/env bash
# Build and manually install paired libfprint and full fprintd in system paths.

set -euo pipefail

usage() {
  printf 'Usage: %s [--debug]\n' "$0"
}

debug=0
case "${1:-}" in
  "") ;;
  --debug) debug=1 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 1 ;;
esac
[[ "$#" -le 1 ]] || { usage >&2; exit 1; }

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GOODIX53X5_DEBUG="$debug" "$repo_dir/scripts/build-milan-stack-local.sh"

if [[ "${EUID:-$(id -u)}" == 0 ]]; then
  "$repo_dir/scripts/install-milan-stack-local.sh"
else
  command -v sudo >/dev/null 2>&1 || {
    printf 'error: sudo is required to install the Milan stack\n' >&2
    exit 1
  }
  stack_root="${GOODIX_MILAN_STACK_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/goodix53x5-milan}"
  sudo env "GOODIX_MILAN_STACK_ROOT=$stack_root" \
    "$repo_dir/scripts/install-milan-stack-local.sh"
fi
