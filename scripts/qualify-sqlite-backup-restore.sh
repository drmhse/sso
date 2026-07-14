#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTHOS_BINARY="${AUTHOS_BINARY:-api/target/debug/sso_sqlite}"
if [[ "$AUTHOS_BINARY" != /* ]]; then
  AUTHOS_BINARY="${ROOT_DIR}/${AUTHOS_BINARY}"
fi
if [[ ! -x "$AUTHOS_BINARY" ]]; then
  echo "backup/restore qualification failed: missing executable ${AUTHOS_BINARY}" >&2
  exit 2
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/authos-backup-restore.XXXXXX")"
cleanup() {
  local exit_code=$?
  if [[ -z "${AUTHOS_KEEP_BACKUP_RESTORE_DIR:-}" ]]; then
    rm -rf "$work_dir"
  else
    echo "Backup/restore qualification directory retained at ${work_dir}" >&2
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/source" "$work_dir/backup" "$work_dir/restored"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/jwt-private.pem"
openssl pkey -in "$work_dir/jwt-private.pem" -pubout \
  -out "$work_dir/jwt-public.pem" >/dev/null 2>&1
export JWT_PRIVATE_KEY_BASE64="$(base64 < "$work_dir/jwt-private.pem" | tr -d '\r\n')"
export JWT_PUBLIC_KEY_BASE64="$(base64 < "$work_dir/jwt-public.pem" | tr -d '\r\n')"
export JWT_KID=backup-restore-evidence
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export DEVICE_TRUST_SECRET="$(openssl rand -hex 32)"
export AUTHOS_BINARY
export AUTHOS_BACKEND=sqlite
export AUTHOS_OWNER_EMAIL=restore-owner@example.test
export AUTHOS_OWNER_PASSWORD='Restore-qualification-password-1!'

preserved_tenant="backup-restore-evidence"
AUTHOS_RUNTIME_DIR="$work_dir/source" \
AUTHOS_TENANT_SLUG="$preserved_tenant" \
AUTHOS_PRESERVE_TENANT=true \
DATABASE_URL="sqlite:$work_dir/source/authos.db?mode=rwc" \
  bash scripts/qualify-runtime-database.sh

scripts/authos-sqlite-backup.py \
  --database "$work_dir/source/authos.db" \
  --output "$work_dir/backup/authos.db"
scripts/authos-sqlite-backup.py \
  --database "$work_dir/backup/authos.db" \
  --verify-manifest "$work_dir/backup/authos.db.manifest.json"
cp "$work_dir/backup/authos.db" "$work_dir/restored/authos.db"
chmod 600 "$work_dir/restored/authos.db"

AUTHOS_RUNTIME_DIR="$work_dir/restored" \
AUTHOS_EXPECT_TENANT_SLUG="$preserved_tenant" \
DATABASE_URL="sqlite:$work_dir/restored/authos.db?mode=rwc" \
  bash scripts/qualify-runtime-database.sh

echo "SQLite backup/restore qualification passed: consistent snapshot, manifest verification, restored login, preserved tenant, and post-restore tenant CRUD."
