#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$script_dir/lib/milan-stack-common.sh"

case "${1:---installed}" in
  --build|--preflight)
    milan_reject_ephemeral_root "GOODIX_MILAN_STACK_ROOT" "$MILAN_STACK_ROOT"
    milan_open_publication
    milan_verify_payload "$MILAN_PAYLOAD" "$repo_dir"
    milan_note "build payload verified: $(dirname "$MILAN_PAYLOAD")"
    if [[ "$1" == --preflight ]]; then
      milan_files preflight / "$MILAN_PAYLOAD"
      milan_note "install preflight passed"
    fi
    ;;
  --installed)
    milan_files verify-installed /
    milan_load_layout /
    milan_verify_debug_census / "$(milan_manifest_value "$MILAN_BUILD_ENV" GOODIX53X5_DEBUG)"
    milan_verify_active_system
    milan_note "installed files, service selection, and library resolution verified"
    milan_note "installed version: $(milan_recorded_version /)"
    ;;
  --absent)
    [[ ! -e "$MILAN_INVENTORY" ]] || milan_die "manual installation inventory remains: $MILAN_INVENTORY"
    milan_note "manual Milan installation is absent"
    ;;
  *) milan_die "usage: $0 [--build|--preflight|--installed|--absent]" ;;
esac
