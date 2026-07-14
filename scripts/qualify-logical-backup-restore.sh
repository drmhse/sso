#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

backend="${AUTHOS_BACKEND:?AUTHOS_BACKEND is required}"
case "$backend" in
  postgres)
    required_tools=(pg_dump pg_restore psql)
    default_port=5432
    ;;
  mysql)
    required_tools=(mysqldump mysql)
    default_port=3306
    ;;
  *)
    echo "logical restore qualification requires AUTHOS_BACKEND=postgres or mysql" >&2
    exit 2
    ;;
esac

for command_name in "${required_tools[@]}" base64 mktemp openssl python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "logical restore qualification missing command: ${command_name}" >&2
    exit 2
  }
done

db_host="${AUTHOS_DB_HOST:-127.0.0.1}"
db_port="${AUTHOS_DB_PORT:-$default_port}"
db_name="${AUTHOS_DB_NAME:-authos_runtime}"
db_user="${AUTHOS_DB_USER:-authos_runtime}"
db_password="${AUTHOS_DB_PASSWORD:?AUTHOS_DB_PASSWORD is required}"
database_url="${DATABASE_URL:?DATABASE_URL is required and must identify the same disposable database as AUTHOS_DB_*}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/authos-${backend}-restore.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT INT TERM

mapfile -t parsed_url < <(
  printf '%s' "$database_url" | python3 -c '
import sys
from urllib.parse import unquote, urlparse

parsed = urlparse(sys.stdin.read())
print(parsed.scheme)
print(parsed.hostname or "")
print(parsed.port or "")
print(unquote(parsed.username or ""))
print(unquote(parsed.path.lstrip("/")))
print(unquote(parsed.password or ""))
'
)
expected_scheme="$backend"
[[ "$backend" == postgres ]] && expected_scheme="postgres"
if [[ "${parsed_url[0]}" != "$expected_scheme" \
   || "${parsed_url[1]}" != "$db_host" \
   || "${parsed_url[2]}" != "$db_port" \
   || "${parsed_url[3]}" != "$db_user" \
   || "${parsed_url[4]}" != "$db_name" \
   || "${parsed_url[5]}" != "$db_password" ]]; then
  echo "DATABASE_URL and AUTHOS_DB_* must identify the same disposable ${backend} database" >&2
  exit 2
fi

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${work_dir}/jwt-private.pem"
openssl pkey -in "${work_dir}/jwt-private.pem" -pubout \
  -out "${work_dir}/jwt-public.pem" >/dev/null 2>&1
export JWT_PRIVATE_KEY_BASE64="$(base64 < "${work_dir}/jwt-private.pem" | tr -d '\r\n')"
export JWT_PUBLIC_KEY_BASE64="$(base64 < "${work_dir}/jwt-public.pem" | tr -d '\r\n')"
export JWT_KID="restore-${backend}"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export DEVICE_TRUST_SECRET="$(openssl rand -hex 32)"
export AUTHOS_RUNTIME_DIR="${work_dir}/runtime"
export AUTHOS_PRESERVE_TENANT=true
export AUTHOS_TENANT_SLUG="restore-source-${backend}"

bash scripts/qualify-runtime-database.sh

source_slug="restore-source-${backend}"
destroyed_slug="restore-destroyed-${backend}"

if [[ "$backend" == postgres ]]; then
  export PGPASSWORD="$db_password"
  pg_dump \
    --host "$db_host" --port "$db_port" --username "$db_user" \
    --dbname "$db_name" --format=custom --no-owner --no-acl \
    --file "${work_dir}/authos-postgres.dump"
  changed="$(psql --host "$db_host" --port "$db_port" --username "$db_user" \
    --dbname "$db_name" --tuples-only --no-align --quiet \
    --command "WITH changed AS (UPDATE organizations SET slug='${destroyed_slug}' WHERE slug='${source_slug}' RETURNING 1) SELECT COUNT(*) FROM changed")"
  [[ "$changed" == "1" ]] || {
    echo "logical restore qualification could not destroy the PostgreSQL canary" >&2
    exit 1
  }
  pg_restore \
    --host "$db_host" --port "$db_port" --username "$db_user" \
    --dbname "$db_name" --clean --if-exists --no-owner --no-acl \
    "${work_dir}/authos-postgres.dump"
  source_count="$(psql --host "$db_host" --port "$db_port" --username "$db_user" \
    --dbname "$db_name" --tuples-only --no-align --quiet \
    --command "SELECT COUNT(*) FROM organizations WHERE slug='${source_slug}'")"
  destroyed_count="$(psql --host "$db_host" --port "$db_port" --username "$db_user" \
    --dbname "$db_name" --tuples-only --no-align --quiet \
    --command "SELECT COUNT(*) FROM organizations WHERE slug='${destroyed_slug}'")"
  unset PGPASSWORD
else
  export MYSQL_PWD="$db_password"
  mysqldump \
    --host="$db_host" --port="$db_port" --user="$db_user" \
    --single-transaction --skip-lock-tables --no-tablespaces \
    --result-file="${work_dir}/authos-mysql.sql" "$db_name"
  mysql --host="$db_host" --port="$db_port" --user="$db_user" \
    --batch --skip-column-names "$db_name" \
    --execute="UPDATE organizations SET slug='${destroyed_slug}' WHERE slug='${source_slug}'; SELECT ROW_COUNT();" \
    | tail -n 1 | grep -qx '1' || {
      echo "logical restore qualification could not destroy the MySQL canary" >&2
      exit 1
    }
  mysql --host="$db_host" --port="$db_port" --user="$db_user" "$db_name" \
    < "${work_dir}/authos-mysql.sql"
  source_count="$(mysql --host="$db_host" --port="$db_port" --user="$db_user" \
    --batch --skip-column-names "$db_name" \
    --execute="SELECT COUNT(*) FROM organizations WHERE slug='${source_slug}'")"
  destroyed_count="$(mysql --host="$db_host" --port="$db_port" --user="$db_user" \
    --batch --skip-column-names "$db_name" \
    --execute="SELECT COUNT(*) FROM organizations WHERE slug='${destroyed_slug}'")"
  unset MYSQL_PWD
fi

if [[ "$source_count" != 1 || "$destroyed_count" != 0 ]]; then
  echo "logical restore qualification did not restore the destroyed canary exactly" >&2
  exit 1
fi

export AUTHOS_EXPECT_TENANT_SLUG="restore-source-${backend}"
export AUTHOS_TENANT_SLUG="restore-postcheck-${backend}"
export AUTHOS_PRESERVE_TENANT=false
bash scripts/qualify-runtime-database.sh

echo "Logical backup/restore qualification passed: ${backend}; preserved login and tenant data plus post-restore CRUD."
