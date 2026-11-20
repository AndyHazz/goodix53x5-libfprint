#!/usr/bin/env bash
# Print the next release version and the previous release tag as key=value
# lines. The argument is patch, minor, major, or an exact X.Y.Z version.

set -euo pipefail

usage() {
  printf 'Usage: %s patch|minor|major|X.Y.Z\n' "$0"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ "$#" -eq 1 ]] || { usage >&2; exit 1; }
request="$1"
latest="$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)"

if [[ "$request" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  next="$request"
elif [[ "$request" =~ ^(patch|minor|major)$ ]]; then
  if [[ -z "$latest" ]]; then
    next=1.0.0
  else
    IFS=. read -r major minor patch <<<"${latest#v}"
    case "$request" in
      patch) next="$major.$minor.$((patch + 1))" ;;
      minor) next="$major.$((minor + 1)).0" ;;
      major) next="$((major + 1)).0.0" ;;
    esac
  fi
else
  usage >&2
  exit 1
fi

if [[ -n "$latest" ]]; then
  [[ "$next" != "${latest#v}" && "$(printf '%s\n' "${latest#v}" "$next" | sort -V | tail -n 1)" == "$next" ]] ||
    die "version $next is not newer than $latest"
fi
! git rev-parse -q --verify "refs/tags/v$next" >/dev/null || die "tag v$next already exists"

printf 'version=%s\nprevious=%s\n' "$next" "$latest"
