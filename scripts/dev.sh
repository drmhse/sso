#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
API_DIR="$ROOT_DIR/api"

echo "========================================="
echo "  SSO Platform - Development Mode"
echo "========================================="
echo ""

# Start docker services
echo "🐳 Starting Docker services (postgres, mailpit)..."
cd "$API_DIR"
docker compose -f docker-compose.dev.yml up -d --build

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 3

# Check if postgres is ready
until docker exec sso-db-test pg_isready -U sso_test_user -d sso_test > /dev/null 2>&1; do
  echo "  ⏳ Waiting for PostgreSQL..."
  sleep 1
done
echo "  ✓ PostgreSQL is ready!"

# Check if mailpit is ready
until curl -s http://localhost:8025 > /dev/null 2>&1; do
  echo "  ⏳ Waiting for Mailpit..."
  sleep 1
done
echo "  ✓ Mailpit is ready!"

echo ""
echo "========================================="
echo "  Services Running:"
echo "========================================="
echo "  📊 PostgreSQL:  localhost:5433"
echo "  📧 Mailpit UI:  http://localhost:8025"
echo "  📨 SMTP Server: localhost:1025"
echo ""
echo "========================================="
echo "  Development Setup:"
echo "========================================="
echo "  • Using .env.dev for configuration"
echo "  • Real OAuth providers (configure in .env.dev)"
echo "  • Mailpit for email testing"
echo ""

# Copy env file
echo "📝 Copying .env.dev to .env..."
cp "$API_DIR/.env.dev" "$API_DIR/.env"
sync  # Ensure file is fully written to disk

echo ""
echo "========================================="
echo "  Starting API Server..."
echo "========================================="
echo ""

# Export env vars from .env file (handles values with spaces)
while IFS='=' read -r key value; do
  # Skip comments and empty lines
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  # Remove any leading/trailing whitespace from key
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  # Export the variable
  export "$key=$value"
done < "$API_DIR/.env"

cd "$API_DIR"
cargo run --bin sso_psql --no-default-features --features db_psql
