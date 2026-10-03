#!/usr/bin/env bash
# Build this distribution's packages from a release source archive created by
# make-source-archive.sh. Debian and Ubuntu produce .deb files, Fedora .rpm files.

set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s [--install-deps] ARCHIVE OUTPUT_DIR\n' "$0"
}

install_deps=0
if [[ "${1:-}" == --install-deps ]]; then
  install_deps=1
  shift
fi
[[ "$#" -eq 2 ]] || { usage >&2; exit 1; }
[[ -f "$1" ]] || { printf 'error: archive not found: %s\n' "$1" >&2; exit 1; }
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
mkdir -p "$2"
output_dir="$(cd "$2" && pwd)"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
# shellcheck source=scripts/lib/milan-stack-common.sh
source "$repo_dir/scripts/lib/milan-stack-common.sh"

# shellcheck source=/dev/null
source /etc/os-release
case " $ID ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) format=deb ;;
  *" fedora "*) format=rpm ;;
  *) milan_die "unsupported distribution: $ID" ;;
esac

# Distribution mirrors occasionally list a package before serving it. Refresh
# the package lists and retry rather than failing the whole build.
install_with_retry() {
  local attempt
  for attempt in 1 2 3; do
    "$@" && return 0
    [[ "$attempt" == 3 ]] && break
    milan_note "dependency installation failed (attempt $attempt of 3); retrying in 60 seconds"
    sleep 60
    if [[ "$format" == deb ]]; then
      apt-get update
    else
      dnf makecache --refresh
    fi
  done
  return 1
}

if [[ "$install_deps" == 1 ]]; then
  if [[ "$format" == deb ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    install_with_retry apt-get install -y --no-install-recommends ca-certificates dpkg-dev xz-utils
  else
    install_with_retry dnf install -y findutils rpm-build tar xz 'dnf-command(builddep)'
  fi
fi

work="${GOODIX_PACKAGE_WORK_DIR:-$repo_dir/.build/packages}/$ID-${VERSION_ID:-unknown}"
milan_reject_ephemeral_root GOODIX_PACKAGE_WORK_DIR "$work"
rm -rf -- "$work"
mkdir -p "$work"
tar -xJf "$archive" -C "$work"
src="$(find "$work" -mindepth 1 -maxdepth 1 -type d -name 'goodix53x5-libfprint-*')"
[[ -n "$src" && -f "$src/release.env" ]] || milan_die "not a release source archive: $archive"
version="$(milan_manifest_value "$src/release.env" VERSION)"
# Date package metadata from the release commit so rebuilds are reproducible.
SOURCE_DATE_EPOCH="$(milan_manifest_value "$src/release.env" SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

build_deb() {
  local deb_version="$version-1~$ID${VERSION_ID:-}" maintainer

  cp -a "$src/packaging/debian" "$src/debian"
  maintainer="$(sed -n 's/^Maintainer: //p' "$src/debian/control")"
  cat > "$src/debian/changelog" <<EOF
goodix53x5-libfprint ($deb_version) ${VERSION_CODENAME:-unstable}; urgency=medium

  * Release $version. Release notes:
    https://github.com/AndyHazz/goodix53x5-libfprint/releases

 -- $maintainer  $(LC_ALL=C date -u -R -d "@$SOURCE_DATE_EPOCH")
EOF
  if [[ "$install_deps" == 1 ]]; then
    install_with_retry apt-get build-dep -y "$src"
  fi
  (cd "$src" && dpkg-buildpackage -b -us -uc)
  cp -- "$work"/fprintd-goodix53x5_"$deb_version"_*.deb "$output_dir/"
}

build_rpm() {
  local spec="$src/packaging/rpm/goodix53x5-libfprint.spec" topdir="$work/rpmbuild"

  if [[ "$install_deps" == 1 ]]; then
    install_with_retry dnf builddep -y --define "goodix_version $version" "$spec"
  fi
  rpmbuild -bb \
    --define "_topdir $topdir" \
    --define "_sourcedir $(dirname "$archive")" \
    --define "goodix_version $version" \
    --define "goodix_changelog_date $(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %Y')" \
    "$spec"
  cp -- "$topdir"/RPMS/*/*.rpm "$output_dir/"
}

"build_$format"
milan_note "packages written to $output_dir"
