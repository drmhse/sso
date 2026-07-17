#!/usr/bin/env bash
set -euo pipefail

benchmark_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$benchmark_dir/../../.." && pwd)
binary=${AUTHOS_BINARY:-$repo_root/api/target/release/sso_sqlite}
work_dir=${AUTHOS_BENCH_WORK_DIR:-$benchmark_dir/.work}
host=${AUTHOS_BENCH_HOST:-127.0.0.1}
port=${AUTHOS_BENCH_PORT:-3301}
public_url=${AUTHOS_BENCH_PUBLIC_URL:-http://$host:$port}

if [[ ! -x "$binary" ]]; then
  echo "AuthOS binary not found at $binary" >&2
  exit 1
fi
for command in base64 sha256sum; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
if [[ ! -f "$work_dir/seed.db" || ! -f "$work_dir/private.pem" || ! -f "$work_dir/public.pem" ]]; then
  echo "run prepare-seed.sh first, or set AUTHOS_BENCH_WORK_DIR to a prepared directory" >&2
  exit 1
fi

rm -f "$work_dir/authos.db" "$work_dir/authos.db-shm" "$work_dir/authos.db-wal"
cp "$work_dir/seed.db" "$work_dir/authos.db"
ulimit -n "${AUTHOS_BENCH_NOFILE:-65535}"
encryption_key=$(printf '%s' 'authos-sqlite-budget-benchmark-encryption' | sha256sum | cut -d' ' -f1)
device_trust_secret=$(printf '%s' 'authos-sqlite-budget-benchmark-device-trust' | sha256sum | cut -d' ' -f1)

export DATABASE_URL="sqlite://$work_dir/authos.db?mode=rwc"
export DB_MAX_CONNECTIONS=10
export DB_MIN_CONNECTIONS=1
export DB_ACQUIRE_TIMEOUT_SECS=30
export JWT_PRIVATE_KEY_BASE64="$(base64 -w0 "$work_dir/private.pem")"
export JWT_PUBLIC_KEY_BASE64="$(base64 -w0 "$work_dir/public.pem")"
export JWT_KID=sqlite-budget-benchmark
export JWT_EXPIRATION_HOURS=24
export ENCRYPTION_KEY="$encryption_key"
export ENCRYPTION_KEY_ID=benchmark
export DEVICE_TRUST_SECRET="$device_trust_secret"
export SERVER_HOST="$host"
export SERVER_PORT="$port"
export BASE_URL="$public_url"
export PLATFORM_BASE_URL="$public_url"
export DISABLE_RATE_LIMITING=true
export GEOIP_DISABLED=true
export BILLING_PROVIDER=none
export JOB_PROCESSOR_INTERVAL_SECS=10
export JOB_PROCESSOR_BATCH_SIZE=50
export RUST_LOG=${RUST_LOG:-warn}

exec "$binary"
