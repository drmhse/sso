#!/usr/bin/env bash
set -euo pipefail

benchmark_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$benchmark_dir/../../.." && pwd)
binary=${AUTHOS_BINARY:-$repo_root/api/target/release/sso_sqlite}
work_dir=${AUTHOS_BENCH_WORK_DIR:-$benchmark_dir/.work}
port=${AUTHOS_BENCH_PORT:-3331}

for command in base64 curl openssl sha256sum sqlite3; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

if [[ ! -x "$binary" ]]; then
  echo "AuthOS binary not found at $binary" >&2
  echo "build it with: cargo build --release --locked --manifest-path api/Cargo.toml --bin sso_sqlite" >&2
  exit 1
fi

install -d -m 700 "$work_dir"
rm -f "$work_dir"/seed.db* "$work_dir"/validation.db* "$work_dir"/server.log

if [[ ! -f "$work_dir/private.pem" || ! -f "$work_dir/public.pem" ]]; then
  openssl genrsa -out "$work_dir/private.pem" 2048 >/dev/null 2>&1
  openssl rsa -in "$work_dir/private.pem" -pubout -out "$work_dir/public.pem" >/dev/null 2>&1
  chmod 600 "$work_dir/private.pem" "$work_dir/public.pem"
fi

server_pid=
encryption_key=$(printf '%s' 'authos-sqlite-budget-benchmark-encryption' | sha256sum | cut -d' ' -f1)
device_trust_secret=$(printf '%s' 'authos-sqlite-budget-benchmark-device-trust' | sha256sum | cut -d' ' -f1)
stop_server() {
  if [[ -n "$server_pid" ]]; then
    kill -INT "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
  fi
}
trap stop_server EXIT

start_server() {
  local database=$1
  env \
    DATABASE_URL="sqlite://$database?mode=rwc" \
    DB_MAX_CONNECTIONS=10 DB_MIN_CONNECTIONS=1 DB_ACQUIRE_TIMEOUT_SECS=30 \
    JWT_PRIVATE_KEY_BASE64="$(base64 -w0 "$work_dir/private.pem")" \
    JWT_PUBLIC_KEY_BASE64="$(base64 -w0 "$work_dir/public.pem")" \
    JWT_KID=sqlite-budget-benchmark JWT_EXPIRATION_HOURS=24 \
    ENCRYPTION_KEY="$encryption_key" \
    ENCRYPTION_KEY_ID=benchmark \
    DEVICE_TRUST_SECRET="$device_trust_secret" \
    SERVER_HOST=127.0.0.1 SERVER_PORT="$port" \
    BASE_URL="http://127.0.0.1:$port" PLATFORM_BASE_URL="http://127.0.0.1:$port" \
    DISABLE_RATE_LIMITING=true GEOIP_DISABLED=true BILLING_PROVIDER=none \
    JOB_PROCESSOR_INTERVAL_SECS=10 JOB_PROCESSOR_BATCH_SIZE=50 RUST_LOG=warn \
    "$binary" > "$work_dir/server.log" 2>&1 &
  server_pid=$!

  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:$port/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$work_dir/server.log" >&2
      return 1
    fi
    sleep 0.1
  done

  echo "AuthOS did not become ready" >&2
  cat "$work_dir/server.log" >&2
  return 1
}

start_server "$work_dir/seed.db"
stop_server
sqlite3 "$work_dir/seed.db" < "$benchmark_dir/seed.sql"

cp "$work_dir/seed.db" "$work_dir/validation.db"
start_server "$work_dir/validation.db"
http_status=$(curl -sS -o "$work_dir/login-response.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"email":"benchmark-user@loadtest.local","password":"Benchmark-User-Password-2026!","org_slug":"benchmark-org","service_slug":"benchmark-service"}' \
  "http://127.0.0.1:$port/api/auth/login")
stop_server
rm -f "$work_dir/validation.db"* "$work_dir/login-response.json"

if [[ "$http_status" != 200 ]]; then
  echo "fixture login validation failed: HTTP $http_status" >&2
  exit 1
fi

sha256sum "$work_dir/seed.db"
