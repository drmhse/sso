#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "=========================================="
echo "Building SSO binaries for all database backends"
echo "=========================================="
echo ""

# Build SQLite binary
echo -e "${BLUE}==> Building SQLite binary...${NC}"
cargo build --release --no-default-features --features db_sqlite
echo -e "${GREEN}✓${NC} SQLite binary built: target/release/sso_sqlite"
echo ""

# Build PostgreSQL binary
echo -e "${BLUE}==> Building PostgreSQL binary...${NC}"
cargo build --release --no-default-features --features db_psql
echo -e "${GREEN}✓${NC} PostgreSQL binary built: target/release/sso_psql"
echo ""

# Build MySQL binary
echo -e "${BLUE}==> Building MySQL binary...${NC}"
cargo build --release --no-default-features --features db_mysql
echo -e "${GREEN}✓${NC} MySQL binary built: target/release/sso_mysql"
echo ""

echo "=========================================="
echo -e "${GREEN}✓${NC} Build complete!"
echo "=========================================="
echo ""
echo "Binaries are available at:"
echo "  - target/release/sso_sqlite"
echo "  - target/release/sso_psql"
echo "  - target/release/sso_mysql"
echo ""
