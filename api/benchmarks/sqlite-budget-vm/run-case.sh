#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <vus> <duration> <run-id>" >&2
  exit 2
fi

benchmark_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$benchmark_dir/../../.." && pwd)
k6=${K6_BIN:-k6}
vus=$1
duration=$2
run_id=$3
base_url=${AUTHOS_BENCH_BASE_URL:-http://127.0.0.1:3301}
output_root=${AUTHOS_BENCH_OUTPUT_DIR:-$benchmark_dir/benchmark-results}
result=$output_root/$run_id

[[ "$vus" =~ ^[1-9][0-9]*$ ]] || { echo "vus must be a positive integer" >&2; exit 2; }
[[ "$duration" =~ ^[1-9][0-9]*(ms|s|m|h)$ ]] || {
  echo "duration must use a k6 unit such as 60s or 5m" >&2
  exit 2
}
[[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "run-id may contain only letters, numbers, dot, underscore, and hyphen" >&2
  exit 2
}

command -v "$k6" >/dev/null || {
  echo "k6 not found: $k6" >&2
  exit 1
}
if [[ -e "$result" ]]; then
  echo "result directory already exists: $result" >&2
  exit 1
fi
install -d -m 755 "$result"

{
  date --iso-8601=seconds
  printf 'run_id=%s\nvus=%s\nduration=%s\nbase_url=%s\nthink_time=1\n' \
    "$run_id" "$vus" "$duration" "$base_url"
  printf 'authos_commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
  "$k6" version
  uname -a
} > "$result/environment.txt"

k6_args=(
  run
  --no-color
  --summary-mode=full
  --summary-export "$result/summary.json"
)
if [[ -n "${K6_LOCAL_IPS:-}" ]]; then
  k6_args+=(--local-ips "$K6_LOCAL_IPS")
fi
k6_args+=("$benchmark_dir/workload.js")

set +e
BASE_URL="$base_url" VUS="$vus" DURATION="$duration" THINK_TIME=1 \
  "$k6" "${k6_args[@]}" > "$result/k6-console.txt" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$result/k6-exit-status.txt"
exit "$status"
