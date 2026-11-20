#!/usr/bin/env bash
# Start the Release workflow on main. It builds every package and creates a
# draft GitHub release to review and publish.

set -euo pipefail

repo="${GH_REPO:-AndyHazz/goodix53x5-libfprint}"

usage() {
  printf 'Usage: %s patch|minor|major|X.Y.Z\n' "$0"
}

[[ "$#" -eq 1 && "$1" =~ ^(patch|minor|major|[0-9]+\.[0-9]+\.[0-9]+)$ ]] || { usage >&2; exit 1; }

GH_REPO="$repo" gh workflow run release.yml --ref main -f "release=$1"
printf 'Started the %s release on main.\n' "$1"
# shellcheck disable=SC2016
printf 'Follow it:  GH_REPO=%s gh run watch "$(GH_REPO=%s gh run list --workflow release.yml --limit 1 --json databaseId --jq ".[0].databaseId")"\n' "$repo" "$repo"
printf 'Then review and publish the draft at https://github.com/%s/releases\n' "$repo"
