# =============================================================================
# Dockerfile - Minimal runtime image for pre-built binaries
# =============================================================================
# This Dockerfile is used with the native build approach:
# 1. Binary is cross-compiled on the host using cargo-zigbuild
# 2. This Dockerfile just packages it into a minimal Alpine image
# 
# Usage:
#   docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 --build-arg BINARY_NAME=sso_sqlite .
# =============================================================================

FROM alpine:3.20

# Build argument for the binary name (e.g., sso_sqlite, sso_psql, sso_mysql)
ARG TARGETARCH
ARG BINARY_NAME=sso_sqlite

# Install runtime dependencies
# libgcc: Required for Rust binaries (unwinding)
# ca-certificates: For HTTPS requests (GeoIP download, OAuth)
RUN apk add --no-cache \
    libgcc \
    ca-certificates

WORKDIR /app

# Copy the pre-built binary from target/dist/linux-${TARGETARCH}
COPY target/dist/linux-${TARGETARCH}/${BINARY_NAME} /app/sso

# Copy the entrypoint
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Ensure permissions
RUN chmod +x /app/sso /app/docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/docker-entrypoint.sh"]
