# Build stage
FROM rust:1.89-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code, migrations, and SQLx query cache
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Enable SQLX offline mode (uses cached query metadata)
ENV SQLX_OFFLINE=true

# Build for release with optimizations
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies including sqlite3 for debugging
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/sso /app/sso

# Copy migrations
COPY --from=builder /app/migrations ./migrations

# Copy entrypoint script
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Create data directory for SQLite with proper permissions
RUN mkdir -p /app/data && chmod 777 /app/data

# Make sure binary and entrypoint are executable
RUN chmod +x /app/sso /app/docker-entrypoint.sh

# Expose port
EXPOSE 3000

# Use entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]
