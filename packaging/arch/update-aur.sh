#!/usr/bin/env bash
# Publish a GitHub release's AUR package files to the libfprint-goodix53x5 AUR
# repository. Needs gh and an SSH key registered with the AUR account that
# maintains the package; shows the change and asks before pushing unless --yes
# is given.

set -euo pipefail

usage() {
  printf 'Usage: %s [--yes] VERSION\n' "$0"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

assume_yes=0
if [[ "${1:-}" == --yes ]]; then
  assume_yes=1
  shift
fi
[[ "$#" -eq 1 && "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { usage >&2; exit 1; }
version="$1"
for command in gh git sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
repo="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
bundle="libfprint-goodix53x5-aur-$version.tar.gz"
aur_url="${AUR_URL:-ssh://aur@aur.archlinux.org/libfprint-goodix53x5.git}"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
gh release download "v$version" --repo "$repo" --dir "$work" --pattern "$bundle" --pattern SHA256SUMS
(cd "$work" && grep -E "  $bundle\$" SHA256SUMS | sha256sum --check --quiet) ||
  die "$bundle does not match the release SHA256SUMS"

git clone -q "$aur_url" "$work/aur"
tar -xzf "$work/$bundle" -C "$work/aur"
git -C "$work/aur" add -A
if git -C "$work/aur" diff --cached --quiet; then
  printf 'The AUR package already matches %s v%s.\n' "$repo" "$version"
  exit 0
fi
git -C "$work/aur" diff --cached --stat
git -C "$work/aur" diff --cached -- .SRCINFO
if [[ "$assume_yes" == 0 ]]; then
  read -r -p "Push libfprint-goodix53x5 1:$version-1 to the AUR? [y/N] " answer
  [[ "$answer" == [yY] ]] || die "not pushed"
fi
git -C "$work/aur" commit -q -m "upgpkg: 1:$version-1"
git -C "$work/aur" push -q origin HEAD:master
printf 'Pushed libfprint-goodix53x5 1:%s-1 to the AUR.\n' "$version"
