#!/usr/bin/env bash
# Write the AUR package files (PKGBUILD, .SRCINFO and the install script) for a
# release source archive created by make-source-archive.sh. The PKGBUILD
# downloads that archive from the GitHub release of REPOSITORY.

set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s ARCHIVE OWNER/REPOSITORY OUTPUT_DIR\n' "$0"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ "$#" -eq 3 ]] || { usage >&2; exit 1; }
archive="$1"
repository="$2"
output_dir="$3"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ -f "$archive" ]] || die "archive not found: $archive"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository: $repository"
command -v makepkg >/dev/null 2>&1 || die "makepkg is required to write .SRCINFO"
name="$(basename "$archive")"
[[ "$name" =~ ^goodix53x5-libfprint-([0-9]+\.[0-9]+\.[0-9]+(~dev\.[0-9a-f]+)?)\.tar\.xz$ ]] ||
  die "not a release source archive name: $name"
version="${BASH_REMATCH[1]}"
# Pull request builds use 0.0.0~dev.SHA; pacman versions cannot contain "~".
pkgver="${version//\~/.}"
sha256="$(sha256sum "$archive" | cut -d ' ' -f 1)"

mkdir -p "$output_dir"
sed -e "s|@REPOSITORY@|$repository|g" -e "s|@PKGVER@|$pkgver|g" -e "s|@VERSION@|$version|g" \
  -e "s|@SHA256@|$sha256|g" \
  "$script_dir/PKGBUILD.in" > "$output_dir/PKGBUILD"
install -m 0644 "$script_dir/libfprint-goodix53x5.install" "$output_dir/"
(cd "$output_dir" && makepkg --printsrcinfo > .SRCINFO)
printf 'wrote AUR package files for %s %s to %s\n' "$repository" "$version" "$output_dir"
