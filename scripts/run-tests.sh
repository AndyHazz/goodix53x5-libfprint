#!/usr/bin/env bash
# Build and run the host-side unit tests. These need no sensor and no libfprint
# tree - only glib, OpenSSL and OpenCV.

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${TMPDIR:-/tmp}/goodix53x5-tests"
mkdir -p "$out_dir"

# OpenCV 5 renamed the features2d module to features.
if pkg-config --exists opencv5; then
  opencv_cflags=$(pkg-config --cflags opencv5)
  opencv_features=-lopencv_features
else
  opencv_cflags=$(pkg-config --cflags opencv4)
  opencv_features=-lopencv_features2d
fi
opencv_libs=(-lopencv_core -lopencv_imgproc -lopencv_flann "$opencv_features")

glib_flags=$(pkg-config --cflags --libs glib-2.0)

status=0

run_test () {
  local name="$1"
  shift
  printf '\n== %s ==\n' "$name"
  if ! "$@"; then
    status=1
  fi
}

cd "$repo_dir"

# The crypto tests compile the real driver translation unit; tests/shim stands
# in for libfprint's internal drivers_api.h (see tests/shim/drivers_api.h).
gcc -std=gnu99 -Wall -o "$out_dir/test_goodix53x5_crypto" \
  tests/test_goodix53x5_crypto.c drivers/goodix53x5/goodix53x5-crypto.c \
  -Itests/shim -Idrivers/goodix53x5 $glib_flags -lcrypto
run_test "goodix53x5 crypto" "$out_dir/test_goodix53x5_crypto"

g++ -std=c++17 -o "$out_dir/test_sigfm_extract" \
  tests/test_sigfm_extract.cpp sigfm/sigfm.cpp \
  $opencv_cflags "${opencv_libs[@]}"
run_test "sigfm extract" "$out_dir/test_sigfm_extract"

g++ -std=c++17 -o "$out_dir/test_sigfm_match" \
  tests/test_sigfm_match.cpp sigfm/sigfm.cpp \
  $opencv_cflags "${opencv_libs[@]}"
run_test "sigfm match" "$out_dir/test_sigfm_match"

if [ "$status" -eq 0 ]; then
  printf '\nAll test binaries passed.\n'
else
  printf '\nSome tests FAILED.\n'
fi
exit "$status"
