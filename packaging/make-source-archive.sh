#!/usr/bin/env bash
# Create the complete release source archive: this repository at HEAD plus the
# pinned libfprint and fprintd checkouts that the packages patch and build.
#
# The upstream checkouts keep a shallow .git so the builder verifies their
# pinned revisions exactly as it does for a source installation.

set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s VERSION OUTPUT_DIR\n' "$0"
}

[[ "$#" -eq 2 ]] || { usage >&2; exit 1; }
version="$1"
output_dir="$2"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$repo_dir/scripts/lib/milan-stack-common.sh"

for command in git tar xz; do
  milan_require_command "$command"
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+.][0-9A-Za-z.]+)?$ ]] ||
  milan_die "invalid version: $version"
git -C "$repo_dir" diff --quiet HEAD -- ||
  milan_die "tracked files have uncommitted changes; the archive is built from HEAD"

name="goodix53x5-libfprint-$version"
epoch="$(git -C "$repo_dir" log -1 --format=%ct HEAD)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
tree="$work/$name"

fetch_pinned() {
  local label="$1" url="$2" revision="$3" dest="$4"

  milan_note "==> fetch pinned $label $revision"
  git init -q "$dest"
  git -C "$dest" fetch -q --depth 1 --no-tags "$url" "$revision"
  git -C "$dest" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$dest" rev-parse HEAD)" == "$revision" ]] || milan_die "$label revision mismatch"
  rm -rf -- "$dest/.git/hooks"
}

git -C "$repo_dir" archive --format=tar --prefix="$name/" HEAD | tar -x -C "$work"
cat > "$tree/release.env" <<EOF
VERSION=$version
REVISION=$(git -C "$repo_dir" rev-parse HEAD)
SOURCE_DATE_EPOCH=$epoch
EOF
mkdir "$tree/sources"
fetch_pinned libfprint "$MILAN_LIBFPRINT_URL" "$MILAN_LIBFPRINT_REVISION" "$tree/sources/libfprint"
fetch_pinned fprintd "$MILAN_FPRINTD_URL" "$MILAN_FPRINTD_REVISION" "$tree/sources/fprintd"

mkdir -p "$output_dir"
archive="$(cd "$output_dir" && pwd)/$name.tar.xz"
tar --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@$epoch" \
  -C "$work" -cf - "$name" | xz -T0 -9 > "$archive.tmp"
mv -- "$archive.tmp" "$archive"
milan_note "created $archive"
