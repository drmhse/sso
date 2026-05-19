#!/bin/bash
set -e

echo "Preparing SQLx offline query data for all database backends..."
echo ""

# Prepare for SQLite
echo "==> Preparing for SQLite..."
export DATABASE_URL="sqlite:data/data.db"
export SQLX_OFFLINE_DIR=".sqlx-sqlite"
cargo sqlx prepare --workspace -- --features db_sqlite
echo "✓ SQLite preparation complete"
echo ""

# Prepare for PostgreSQL
echo "==> Preparing for PostgreSQL..."
if [ -z "$POSTGRES_DATABASE_URL" ]; then
    echo "⚠ POSTGRES_DATABASE_URL not set. Using default."
    echo "  Set POSTGRES_DATABASE_URL to use a real database for preparation."
    export DATABASE_URL="postgres://postgres:password@localhost:5432/sso_dev"
else
    export DATABASE_URL="$POSTGRES_DATABASE_URL"
fi
export SQLX_OFFLINE_DIR=".sqlx-psql"
cargo sqlx prepare --workspace -- --features db_psql
echo "✓ PostgreSQL preparation complete"
echo ""

# Prepare for MySQL
echo "==> Preparing for MySQL..."
if [ -z "$MYSQL_DATABASE_URL" ]; then
    echo "⚠ MYSQL_DATABASE_URL not set. Using default."
    echo "  Set MYSQL_DATABASE_URL to use a real database for preparation."
    export DATABASE_URL="mysql://root:password@localhost:3306/sso_dev"
else
    export DATABASE_URL="$MYSQL_DATABASE_URL"
fi
export SQLX_OFFLINE_DIR=".sqlx-mysql"
cargo sqlx prepare --workspace -- --features db_mysql
echo "✓ MySQL preparation complete"
echo ""

echo "=========================================="
echo "All database backends prepared successfully!"
echo "=========================================="
echo ""
echo "Offline query data locations:"
echo "  SQLite:     .sqlx-sqlite/"
echo "  PostgreSQL: .sqlx-psql/"
echo "  MySQL:      .sqlx-mysql/"
