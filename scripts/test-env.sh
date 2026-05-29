#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
API_DIR="$ROOT_DIR/api"
DB_TYPE="${1:-postgres}" # Default to postgres

echo "========================================="
echo "  SSO Platform - Test Environment"
echo "  Database: $DB_TYPE"
echo "========================================="
echo ""

# Start docker services (includes mock-server for testing)
echo "🐳 Starting Docker services..."
cd "$API_DIR"

if [ "$DB_TYPE" = "postgres" ]; then
  docker compose -f docker-compose.test.yml up -d --build db-test mock-server mailpit keycloak
elif [ "$DB_TYPE" = "mysql" ]; then
  docker compose -f docker-compose.test.yml up -d --build --force-recreate db-mysql-test mock-server mailpit keycloak
else
  # SQLite doesn't need a DB container, just supporting services
  docker compose -f docker-compose.test.yml up -d --build mock-server mailpit keycloak
fi

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 3

# Check if Keycloak is ready
until curl -s http://localhost:8081/ > /dev/null 2>&1; do
  echo "  ⏳ Waiting for Keycloak..."
  sleep 2
done
echo "  ✓ Keycloak is ready!"

# Check if DB is ready
if [ "$DB_TYPE" = "postgres" ]; then
  until docker exec sso-db-test pg_isready -U sso_test_user -d sso_test > /dev/null 2>&1; do
    echo "  ⏳ Waiting for PostgreSQL..."
    sleep 1
  done
  echo "  ✓ PostgreSQL is ready!"
elif [ "$DB_TYPE" = "mysql" ]; then
  until docker exec -e MYSQL_PWD=root_password sso-db-mysql-test mysqladmin ping -h localhost -u root --silent > /dev/null 2>&1; do
    echo "  ⏳ Waiting for MySQL..."
    sleep 1
  done
  echo "  ✓ MySQL is ready!"
fi

# Check if mock-server is ready
until curl -s http://localhost:9000/health > /dev/null 2>&1; do
  echo "  ⏳ Waiting for mock-server..."
  sleep 1
done
echo "  ✓ Mock server is ready!"

# Check if mailpit is ready
until curl -s http://localhost:8025 > /dev/null 2>&1; do
  echo "  ⏳ Waiting for Mailpit..."
  sleep 1
done
echo "  ✓ Mailpit is ready!"

# Reset Databases to ensure clean state
echo ""
echo "🔄 Resetting database for clean test environment..."
if [ "$DB_TYPE" = "postgres" ]; then
  docker exec sso-db-test psql -U sso_test_user -d postgres -c "DROP DATABASE IF EXISTS sso_test;" > /dev/null 2>&1
  docker exec sso-db-test psql -U sso_test_user -d postgres -c "CREATE DATABASE sso_test;" > /dev/null 2>&1
  echo "  ✓ PostgreSQL database 'sso_test' recreated."
elif [ "$DB_TYPE" = "mysql" ]; then
  # Use root user for database admin operations (more reliable than app user)
  docker exec -e MYSQL_PWD=root_password sso-db-mysql-test mysql -u root -e "DROP DATABASE IF EXISTS sso_test;" 2>/dev/null || true
  docker exec -e MYSQL_PWD=root_password sso-db-mysql-test mysql -u root -e "CREATE DATABASE IF NOT EXISTS sso_test;"
  docker exec -e MYSQL_PWD=root_password sso-db-mysql-test mysql -u root -e "GRANT ALL PRIVILEGES ON sso_test.* TO 'sso_test_user'@'%'; FLUSH PRIVILEGES;"
  echo "  ✓ MySQL database 'sso_test' recreated."
fi

echo ""
echo "========================================="
echo "  Services Running:"
echo "========================================="
if [ "$DB_TYPE" = "postgres" ]; then
  echo "  📊 PostgreSQL:   localhost:5433"
elif [ "$DB_TYPE" = "mysql" ]; then
  echo "  📊 MySQL:        localhost:3307"
fi
echo "  🎭 Mock Server:  http://localhost:9000"
echo "  🔐 Keycloak UI:  http://localhost:8081"
echo "  📧 Mailpit UI:   http://localhost:8025"
echo "  📨 SMTP Server:  localhost:1025"
echo ""
echo "========================================="
echo "  Test Environment Setup:"
echo "========================================="
echo "  • Using .env.test for configuration"
echo "  • Database: $DB_TYPE"
echo ""

# Copy env file
echo "📝 Copying .env.test to .env..."
cp "$API_DIR/.env.test" "$API_DIR/.env"
sync

echo ""
echo "========================================="
echo "  Starting API Server ($DB_TYPE)..."
echo "========================================="
echo ""

# Export env vars from .env file
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  export "$key=$value"
done < "$API_DIR/.env"

# Export DB_TYPE for tests to pick up
export DB_TYPE="$DB_TYPE"

cd "$API_DIR"
echo "💡 API server starting on http://localhost:3001"
echo "💡 Once running, open a new terminal and run:"
echo "   cd test-integration && npm test"
echo ""


if [ "$DB_TYPE" = "postgres" ]; then
  cargo run --bin sso_psql --no-default-features --features db_psql
elif [ "$DB_TYPE" = "mysql" ]; then
  export DATABASE_URL="mysql://sso_test_user:sso_test_password@localhost:3307/sso_test"
  cargo run --bin sso_mysql --no-default-features --features db_mysql
elif [ "$DB_TYPE" = "sqlite" ]; then
  # Ensure sqlite file directory exists
  mkdir -p data
  # Drop existing database for clean test run
  if [ -f "data/sso_test.db" ]; then
    echo "🗑️  Dropping existing SQLite database..."
    rm -f data/sso_test.db*
  fi

  touch data/sso_test.db
  export DATABASE_URL="sqlite://data/sso_test.db?mode=rwc"
  # SQLite in WAL mode supports multiple readers + 1 writer
  # Set reasonable connection limit for parallel tests
  export DB_MAX_CONNECTIONS=10
  export DB_ACQUIRE_TIMEOUT_SECS=10
  cargo run --bin sso_sqlite --no-default-features --features db_sqlite
else
  echo "❌ Unknown database type: $DB_TYPE"
  exit 1
fi
