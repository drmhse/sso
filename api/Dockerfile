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

LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/drmhse/AuthOS"

# Build argument for the binary name (e.g., sso_sqlite, sso_psql, sso_mysql)
ARG TARGETARCH
ARG BINARY_NAME=sso_sqlite

# Install runtime dependencies
# libgcc: Required for Rust binaries (unwinding)
# ca-certificates: For HTTPS requests (GeoIP download, OAuth)
RUN apk add --no-cache \
    libgcc \
    ca-certificates \
    && addgroup -S -g 10001 authos \
    && adduser -S -D -H -u 10001 -G authos authos \
    && install -d -m 0700 -o authos -g authos /app /app/data /app/geoip

WORKDIR /app

# Copy the pre-built binary from target/dist/linux-${TARGETARCH}
COPY --chown=authos:authos target/dist/linux-${TARGETARCH}/${BINARY_NAME} /app/sso

# Copy the entrypoint
COPY --chown=authos:authos docker-entrypoint.sh /app/docker-entrypoint.sh

# Retain the complete license notice in the conveyed runtime image.
COPY --chown=root:root LICENSE /usr/share/licenses/authos/AGPL-3.0.txt

# Ensure permissions
RUN chmod 0555 /app/sso /app/docker-entrypoint.sh

USER 10001:10001

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${SERVER_PORT:-3000}/health/ready" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
