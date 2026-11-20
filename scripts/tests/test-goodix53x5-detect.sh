#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/goodix53x5-detect-test.XXXXXX")"
fake_bin=$test_root/bin
state=$test_root/state

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT
mkdir "$fake_bin" "$state"

cat > "$fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  is-active)
    [[ "$(<"$FAKE_STATE/service")" == active ]]
    ;;
  stop)
    printf 'stop\n' >> "$FAKE_STATE/systemctl.log"
    printf 'inactive\n' > "$FAKE_STATE/service"
    [[ "${FAIL_STOP:-0}" != 1 ]]
    ;;
  start)
    printf 'start\n' >> "$FAKE_STATE/systemctl.log"
    [[ "${FAIL_START:-0}" != 1 ]] || exit 1
    printf 'active\n' > "$FAKE_STATE/service"
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$fake_bin/pkg-config" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat > "$fake_bin/cc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
while (($#)); do
  if [[ "$1" == -o ]]; then
    output=$2
    shift 2
  else
    shift
  fi
done
cp "$FAKE_PROBE" "$output"
chmod 0755 "$output"
EOF

cat > "$test_root/probe" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == --self-test ]] && exit 0
exit "${PROBE_STATUS:-0}"
EOF
chmod 0755 "$fake_bin/systemctl" "$fake_bin/pkg-config" "$fake_bin/cc" \
  "$test_root/probe"

run_wrapper() {
  unshare -Ur env \
    PATH="$fake_bin:/usr/bin" \
    FAKE_STATE="$state" \
    FAKE_PROBE="$test_root/probe" \
    PROBE_STATUS="${PROBE_STATUS:-0}" \
    FAIL_STOP="${FAIL_STOP:-0}" \
    FAIL_START="${FAIL_START:-0}" \
    "$repo_dir/scripts/goodix53x5-detect.sh"
}

printf 'active\n' > "$state/service"
run_wrapper
[[ "$(<"$state/service")" == active ]]
[[ "$(<"$state/systemctl.log")" == $'stop\nstart' ]]

: > "$state/systemctl.log"
printf 'inactive\n' > "$state/service"
run_wrapper
[[ ! -s "$state/systemctl.log" ]]

: > "$state/systemctl.log"
printf 'active\n' > "$state/service"
if PROBE_STATUS=1 run_wrapper; then
  printf 'probe failure unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$(<"$state/service")" == active ]]
[[ "$(<"$state/systemctl.log")" == $'stop\nstart' ]]

: > "$state/systemctl.log"
printf 'active\n' > "$state/service"
if FAIL_STOP=1 run_wrapper; then
  printf 'stop failure unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$(<"$state/service")" == active ]]
[[ "$(<"$state/systemctl.log")" == $'stop\nstart' ]]

: > "$state/systemctl.log"
printf 'active\n' > "$state/service"
if FAIL_START=1 run_wrapper 2> "$state/restart.stderr"; then
  printf 'restart failure unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$(<"$state/systemctl.log")" == $'stop\nstart' ]]
[[ "$(<"$state/restart.stderr")" == *'could not restart fprintd.service'* ]]

printf 'ok - goodix53x5 detector wrapper\n'
