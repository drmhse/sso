#!/usr/bin/env bash
# The `test-support` features unlock test-only shortcuts: the all-zero
# device-trust fallback key, context-free encrypt/decrypt, and a worker-less
# AuditHandle. They must never reach a production build, so assert they are
# absent from the normal (non-dev) dependency graph.
set -euo pipefail

cd "$(dirname "$0")/../api"

for features in "" "--no-default-features --features db_psql" "--no-default-features --features db_mysql"; do
  # shellcheck disable=SC2086
  hits=$(cargo tree -e normal,features $features 2>/dev/null | grep -c 'test-support' || true)
  if [ "$hits" -ne 0 ]; then
    echo "FAIL: 'test-support' is enabled in a production build (${features:-default features}):" >&2
    # shellcheck disable=SC2086
    cargo tree -e normal,features $features 2>/dev/null | grep -B3 'test-support' >&2
    exit 1
  fi
done

# The layer crates default to db_sqlite so `cargo test -p <crate>` works
# standalone. Every internal dependency is therefore declared with
# `default-features = false`; if one is ever missed, db_sqlite would leak into a
# Postgres/MySQL build and silently select the wrong code path.
for pair in "db_psql:db_sqlite" "db_mysql:db_sqlite" "db_psql:db_mysql" "db_mysql:db_psql"; do
  want="${pair%%:*}"
  forbid="${pair##*:}"
  hits=$(cargo tree -e normal,features --no-default-features --features "$want" 2>/dev/null \
    | grep -c "feature \"$forbid\"" || true)
  if [ "$hits" -ne 0 ]; then
    echo "FAIL: building with $want also enables $forbid; an internal dependency is missing default-features = false" >&2
    exit 1
  fi
done

echo "test-support isolation OK: absent from all production dependency graphs."
echo "db backend features are mutually exclusive across db_sqlite/db_psql/db_mysql."
