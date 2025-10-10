#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="sso"
VERSION=$(grep -E "^version" Cargo.toml | head -1 | cut -d'"' -f2)

# Check if logged in to Docker Hub
if ! cat ~/.docker/config.json 2>/dev/null | grep -q "index.docker.io"; then
    echo -e "${RED}❌ Not logged in to Docker Hub${NC}"
    echo "Please run: docker login"
    exit 1
fi

echo -e "${GREEN}✓${NC} Logged in to Docker Hub"

# Prompt for Docker Hub username if not provided
if [ -z "$DOCKER_USERNAME" ]; then
    echo -n "Enter your Docker Hub username: "
    read DOCKER_USERNAME
fi

if [ -z "$DOCKER_USERNAME" ]; then
    echo -e "${RED}❌ Docker Hub username is required${NC}"
    exit 1
fi

# Build multi-platform image
FULL_IMAGE_NAME="${DOCKER_USERNAME}/${IMAGE_NAME}"

echo ""
echo "=================================================="
echo "Building and Publishing Docker Image"
echo "=================================================="
echo "Image: ${FULL_IMAGE_NAME}"
echo "Version: ${VERSION}"
echo "Tags: latest, ${VERSION}"
echo "=================================================="
echo ""

# Ask for confirmation
echo -n "Continue? (y/N): "
read -r CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Clean build
echo -e "${YELLOW}→${NC} Cleaning previous builds..."
cargo clean

# Build the Docker image (multi-platform)
echo -e "${YELLOW}→${NC} Building Docker image..."
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "${FULL_IMAGE_NAME}:${VERSION}" \
    --tag "${FULL_IMAGE_NAME}:latest" \
    --push \
    .

echo ""
echo -e "${GREEN}✓${NC} Successfully built and pushed:"
echo "  - ${FULL_IMAGE_NAME}:${VERSION}"
echo "  - ${FULL_IMAGE_NAME}:latest"
echo ""
echo "To use this image:"
echo "  docker pull ${FULL_IMAGE_NAME}:latest"
echo "  docker run -p 3000:3000 ${FULL_IMAGE_NAME}:latest"
echo ""
