#!/bin/bash

# SSO Platform - Automated Setup Script
# This script initializes the development environment by generating required secrets

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
API_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$API_DIR/.env"
ENV_EXAMPLE="$API_DIR/.env.example"

echo "SSO Platform - Environment Setup"
echo "=================================="
echo ""

# Check if .env exists
if [ -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}Warning: .env file already exists${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    # Backup existing .env
    cp "$ENV_FILE" "$ENV_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}Created backup of existing .env file${NC}"
fi

# Copy .env.example to .env
echo "Creating .env from .env.example..."
cp "$ENV_EXAMPLE" "$ENV_FILE"

# Generate RSA keys
echo "Generating RSA key pair..."
openssl genrsa -out "$API_DIR/private.pem" 2048 2>/dev/null
openssl rsa -in "$API_DIR/private.pem" -pubout -out "$API_DIR/public.pem" 2>/dev/null

# Base64-encode the keys and remove newlines
echo "Encoding keys..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    PRIVATE_KEY_BASE64=$(base64 -i "$API_DIR/private.pem" | tr -d '\n')
    PUBLIC_KEY_BASE64=$(base64 -i "$API_DIR/public.pem" | tr -d '\n')
else
    # Linux
    PRIVATE_KEY_BASE64=$(base64 -w 0 "$API_DIR/private.pem")
    PUBLIC_KEY_BASE64=$(base64 -w 0 "$API_DIR/public.pem")
fi

# Generate a unique Key ID
JWT_KID=$(openssl rand -hex 16)

# Generate encryption key
echo "Generating encryption key..."
ENCRYPTION_KEY=$(openssl rand -hex 32)

# Replace placeholders in .env
echo "Configuring .env file..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS requires -i '' for in-place editing
    sed -i '' "s|JWT_PRIVATE_KEY_BASE64=.*|JWT_PRIVATE_KEY_BASE64=$PRIVATE_KEY_BASE64|" "$ENV_FILE"
    sed -i '' "s|JWT_PUBLIC_KEY_BASE64=.*|JWT_PUBLIC_KEY_BASE64=$PUBLIC_KEY_BASE64|" "$ENV_FILE"
    sed -i '' "s|JWT_KID=.*|JWT_KID=$JWT_KID|" "$ENV_FILE"
    sed -i '' "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$ENCRYPTION_KEY|" "$ENV_FILE"
else
    # Linux
    sed -i "s|JWT_PRIVATE_KEY_BASE64=.*|JWT_PRIVATE_KEY_BASE64=$PRIVATE_KEY_BASE64|" "$ENV_FILE"
    sed -i "s|JWT_PUBLIC_KEY_BASE64=.*|JWT_PUBLIC_KEY_BASE64=$PUBLIC_KEY_BASE64|" "$ENV_FILE"
    sed -i "s|JWT_KID=.*|JWT_KID=$JWT_KID|" "$ENV_FILE"
    sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$ENCRYPTION_KEY|" "$ENV_FILE"
fi

# Clean up temporary .pem files
echo "Cleaning up temporary files..."
rm "$API_DIR/private.pem" "$API_DIR/public.pem"

echo ""
echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit .env and set PLATFORM_OWNER_EMAIL to your email address"
echo "  2. Configure at least one OAuth provider (GitHub, Google, or Microsoft)"
echo "     See docs for creating OAuth apps: docs/content/api/getting-started.md"
echo "  3. Start the service: docker-compose up --build sso-sqlite"
echo ""
