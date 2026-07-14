#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTHOS_BACKEND="${AUTHOS_BACKEND:-sqlite}"
AUTHOS_PORT="${AUTHOS_PORT:-39001}"
AUTHOS_HOST="${AUTHOS_HOST:-127.0.0.1}"
AUTHOS_URL="${AUTHOS_URL:-http://${AUTHOS_HOST}:${AUTHOS_PORT}}"
AUTHOS_RUNTIME_TIMEOUT_SECONDS="${AUTHOS_RUNTIME_TIMEOUT_SECONDS:-120}"
AUTHOS_OWNER_EMAIL="${AUTHOS_OWNER_EMAIL:-runtime-owner@example.test}"
AUTHOS_OWNER_PASSWORD="${AUTHOS_OWNER_PASSWORD:-Runtime-qualification-password-1!}"

case "$AUTHOS_BACKEND" in
  sqlite)
    default_binary="api/target/debug/sso_sqlite"
    ;;
  postgres)
    default_binary="api/target/debug/sso_psql"
    ;;
  mysql)
    default_binary="api/target/debug/sso_mysql"
    ;;
  *)
    echo "runtime qualification failed: AUTHOS_BACKEND must be sqlite, postgres, or mysql" >&2
    exit 2
    ;;
esac

AUTHOS_BINARY="${AUTHOS_BINARY:-$default_binary}"
if [[ "$AUTHOS_BINARY" != /* ]]; then
  AUTHOS_BINARY="${ROOT_DIR}/${AUTHOS_BINARY}"
fi

for command_name in base64 curl mktemp openssl python3 realpath; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "runtime qualification failed: missing command ${command_name}" >&2
    exit 2
  fi
done

if [[ ! -x "$AUTHOS_BINARY" ]]; then
  echo "runtime qualification failed: AuthOS binary is not executable: ${AUTHOS_BINARY}" >&2
  exit 2
fi

runtime_dir_is_external=false
if [[ -n "${AUTHOS_RUNTIME_DIR:-}" ]]; then
  runtime_dir="$(realpath -m "$AUTHOS_RUNTIME_DIR")"
  mkdir -p "$runtime_dir"
  chmod 700 "$runtime_dir"
  runtime_dir_is_external=true
else
  runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/authos-runtime-${AUTHOS_BACKEND}.XXXXXX")"
fi
key_dir="${runtime_dir}/keys"
mkdir -p "$key_dir"
runtime_log="${AUTHOS_RUNTIME_LOG:-${runtime_dir}/authos.log}"
mkdir -p "$(dirname "$runtime_log")"
authos_pid=""

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if [[ -n "$authos_pid" ]] && kill -0 "$authos_pid" >/dev/null 2>&1; then
    kill -TERM "$authos_pid" >/dev/null 2>&1 || true
    for _ in {1..20}; do
      kill -0 "$authos_pid" >/dev/null 2>&1 || break
      sleep 0.25
    done
    kill -KILL "$authos_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$authos_pid" ]]; then
    wait "$authos_pid" >/dev/null 2>&1 || true
  fi

  if [[ $exit_code -ne 0 ]]; then
    echo "runtime qualification failed for ${AUTHOS_BACKEND}; AuthOS log follows:" >&2
    tail -n 200 "$runtime_log" >&2 2>/dev/null || true
  fi

  if [[ -z "${AUTHOS_KEEP_RUNTIME_DIR:-}" && "$runtime_dir_is_external" == false ]]; then
    rm -rf "$runtime_dir"
  else
    echo "Runtime work directory retained at ${runtime_dir}" >&2
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

if [[ -z "${JWT_PRIVATE_KEY_BASE64:-}" && -z "${JWT_PUBLIC_KEY_BASE64:-}" ]]; then
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${key_dir}/jwt-private.pem"
  openssl pkey -in "${key_dir}/jwt-private.pem" -pubout \
    -out "${key_dir}/jwt-public.pem" >/dev/null 2>&1

  JWT_PRIVATE_KEY_BASE64="$(base64 < "${key_dir}/jwt-private.pem" | tr -d '\r\n')"
  JWT_PUBLIC_KEY_BASE64="$(base64 < "${key_dir}/jwt-public.pem" | tr -d '\r\n')"
elif [[ -z "${JWT_PRIVATE_KEY_BASE64:-}" || -z "${JWT_PUBLIC_KEY_BASE64:-}" ]]; then
  echo "runtime qualification failed: provide both JWT key values or neither" >&2
  exit 2
fi
export JWT_PRIVATE_KEY_BASE64 JWT_PUBLIC_KEY_BASE64
export JWT_KID="${JWT_KID:-runtime-${AUTHOS_BACKEND}}"
export JWT_EXPIRATION_HOURS=1
export ENCRYPTION_KEY="${ENCRYPTION_KEY:-$(openssl rand -hex 32)}"
export DEVICE_TRUST_SECRET="${DEVICE_TRUST_SECRET:-$(openssl rand -hex 32)}"
export PLATFORM_OWNER_EMAIL="$AUTHOS_OWNER_EMAIL"
export PLATFORM_OWNER_PASSWORD="$AUTHOS_OWNER_PASSWORD"
export SERVER_HOST="$AUTHOS_HOST"
export SERVER_PORT="$AUTHOS_PORT"
export BASE_URL="$AUTHOS_URL"
export PLATFORM_BASE_URL="$AUTHOS_URL"
export BILLING_PROVIDER=none
export GEOIP_DISABLED=true
export DISABLE_RATE_LIMITING=true
export DB_MIN_CONNECTIONS="${DB_MIN_CONNECTIONS:-1}"
export DB_MAX_CONNECTIONS="${DB_MAX_CONNECTIONS:-10}"
export DB_ACQUIRE_TIMEOUT_SECS="${DB_ACQUIRE_TIMEOUT_SECS:-10}"
export RUST_LOG="${RUST_LOG:-info}"

if [[ "$AUTHOS_BACKEND" == "sqlite" ]]; then
  export DATABASE_URL="${DATABASE_URL:-sqlite:${runtime_dir}/authos.db?mode=rwc}"
elif [[ -z "${DATABASE_URL:-}" ]]; then
  echo "runtime qualification failed: DATABASE_URL is required for ${AUTHOS_BACKEND}" >&2
  exit 2
fi

echo "Starting AuthOS ${AUTHOS_BACKEND} runtime qualification candidate on ${AUTHOS_URL}"
"$AUTHOS_BINARY" >"$runtime_log" 2>&1 &
authos_pid=$!

deadline=$((SECONDS + AUTHOS_RUNTIME_TIMEOUT_SECONDS))
until curl -fsS "${AUTHOS_URL}/health/ready" >/dev/null 2>&1; do
  if ! kill -0 "$authos_pid" >/dev/null 2>&1; then
    echo "AuthOS exited before readiness" >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "AuthOS did not become ready within ${AUTHOS_RUNTIME_TIMEOUT_SECONDS}s" >&2
    exit 1
  fi
  sleep 1
done

request_json() {
  local method=$1
  local path_name=$2
  local expected_status=$3
  local body=${4:-}
  local bearer_token=${5:-}
  local response_file status request_body_file secret_config_file
  response_file="$(mktemp "${runtime_dir}/response.XXXXXX")"
  request_body_file=''
  secret_config_file=''

  local -a curl_args=(
    --silent
    --show-error
    --output "$response_file"
    --write-out '%{http_code}'
    --request "$method"
    --header 'Accept: application/json'
  )
  if [[ -n "$body" ]]; then
    request_body_file="$(mktemp "${runtime_dir}/request-body.XXXXXX")"
    chmod 600 "$request_body_file"
    printf '%s' "$body" >"$request_body_file"
    curl_args+=(--header 'Content-Type: application/json' --data-binary "@${request_body_file}")
  fi
  if [[ -n "$bearer_token" ]]; then
    if [[ "$bearer_token" == *$'\n'* || "$bearer_token" == *$'\r'* ]]; then
      [[ -z "$request_body_file" ]] || rm -f "$request_body_file"
      rm -f "$response_file"
      echo "request_json rejected a bearer token containing a line break" >&2
      return 1
    fi
    secret_config_file="$(mktemp "${runtime_dir}/curl-config.XXXXXX")"
    chmod 600 "$secret_config_file"
    printf 'header = "Authorization: Bearer %s"\n' "$bearer_token" >"$secret_config_file"
    curl_args+=(--config "$secret_config_file")
  fi

  if ! status="$(curl "${curl_args[@]}" "${AUTHOS_URL}${path_name}")"; then
    [[ -z "$request_body_file" ]] || rm -f "$request_body_file"
    [[ -z "$secret_config_file" ]] || rm -f "$secret_config_file"
    rm -f "$response_file"
    return 1
  fi
  [[ -z "$request_body_file" ]] || rm -f "$request_body_file"
  [[ -z "$secret_config_file" ]] || rm -f "$secret_config_file"
  if [[ "$status" != "$expected_status" ]]; then
    echo "${method} ${path_name}: expected HTTP ${expected_status}, received ${status}" >&2
    sed -n '1,80p' "$response_file" >&2
    return 1
  fi
  cat "$response_file"
}

json_field() {
  local field=$1
  python3 -c '
import json
import sys

value = json.load(sys.stdin)
for component in sys.argv[1].split("."):
    value = value[component]
if isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
else:
    print(value)
' "$field"
}

health_response="$(request_json GET /health 200)"
[[ "$(printf '%s' "$health_response" | json_field status)" == "healthy" ]]
readiness_response="$(request_json GET /health/ready 200)"
[[ "$(printf '%s' "$readiness_response" | json_field database)" == "connected" ]]
capabilities_response="$(request_json GET /.well-known/authos-configuration 200)"
[[ "$(printf '%s' "$capabilities_response" | json_field openid_connect.status)" == "unsupported" ]]
request_json GET /.well-known/openid-configuration 404 >/dev/null
request_json GET /.well-known/oauth-authorization-server 404 >/dev/null
request_json GET /.well-known/jwks.json 200 >/dev/null

login_body="$(printf '%s\0%s' "$AUTHOS_OWNER_EMAIL" "$AUTHOS_OWNER_PASSWORD" | python3 -c '
import json
import sys
email, password = sys.stdin.buffer.read().split(b"\0", 1)
print(json.dumps({"email": email.decode("utf-8"), "password": password.decode("utf-8")}))
')"
login_response="$(request_json POST /api/auth/login 200 "$login_body")"
access_token="$(printf '%s' "$login_response" | json_field access_token)"
if [[ -z "$access_token" ]]; then
  echo "runtime qualification failed: login returned an empty access token" >&2
  exit 1
fi

if [[ -n "${AUTHOS_EXPECT_TENANT_SLUG:-}" ]]; then
  expected_response="$(request_json GET "/api/organizations/${AUTHOS_EXPECT_TENANT_SLUG}" 200 '' "$access_token")"
  [[ "$(printf '%s' "$expected_response" | json_field organization.slug)" == "$AUTHOS_EXPECT_TENANT_SLUG" ]]
fi

tenant_slug="${AUTHOS_TENANT_SLUG:-runtime-${AUTHOS_BACKEND}-$$}"
create_body="$(printf '{"slug":"%s","name":"Runtime Qualification"}' "$tenant_slug")"
create_response="$(request_json POST /api/organizations 200 "$create_body" "$access_token")"
[[ "$(printf '%s' "$create_response" | json_field organization.slug)" == "$tenant_slug" ]]

get_response="$(request_json GET "/api/organizations/${tenant_slug}" 200 '' "$access_token")"
[[ "$(printf '%s' "$get_response" | json_field organization.name)" == "Runtime Qualification" ]]

update_response="$(request_json PATCH "/api/organizations/${tenant_slug}" 200 \
  '{"name":"Runtime Qualification Updated"}' "$access_token")"
[[ "$(printf '%s' "$update_response" | json_field organization.name)" == "Runtime Qualification Updated" ]]

if [[ "${AUTHOS_PRESERVE_TENANT:-false}" != true ]]; then
  request_json DELETE "/api/organizations/${tenant_slug}" 200 '' "$access_token" >/dev/null
  request_json GET "/api/organizations/${tenant_slug}" 404 '' "$access_token" >/dev/null
fi

echo "Runtime database qualification passed: ${AUTHOS_BACKEND}; migrations, health/readiness, discovery/JWKS, login, and tenant CRUD."
