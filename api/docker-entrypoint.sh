#!/bin/sh
set -e

echo "=== SSO Platform - Container Initialization ==="

# ============================================================================
# SQLite Database Setup
# ============================================================================
case "$DATABASE_URL" in
sqlite:*)
    echo "Initializing SQLite database..."

    # Extract database path from DATABASE_URL
    DB_PATH="${DATABASE_URL#sqlite:}"

    # Create parent directory if it doesn't exist
    DB_DIR=$(dirname "$DB_PATH")
    mkdir -p "$DB_DIR"

    # Create empty database file if it doesn't exist
    if [ ! -f "$DB_PATH" ]; then
        echo "Creating database file at $DB_PATH"
        touch "$DB_PATH"
    fi
    chmod 600 "$DB_PATH"

    echo "✓ SQLite database ready"
    ;;
esac

# ============================================================================
# GeoIP Database Setup
# ============================================================================
# Default path if not specified
GEOIP_DATABASE_PATH="${GEOIP_DATABASE_PATH:-/app/geoip/GeoLite2-City.mmdb}"

if [ "$GEOIP_DISABLED" = "true" ]; then
    echo "⚠ GeoIP features disabled via GEOIP_DISABLED=true"
else
    echo "Checking GeoIP database..."

    # Create GeoIP directory
    GEOIP_DIR=$(dirname "$GEOIP_DATABASE_PATH")
    mkdir -p "$GEOIP_DIR"

    # Check if database exists
    if [ -f "$GEOIP_DATABASE_PATH" ]; then
        echo "✓ GeoIP database found at $GEOIP_DATABASE_PATH"
    else
        echo "⚠ GeoIP database not found at $GEOIP_DATABASE_PATH"

        # Attempt automatic download if license key is provided
        if [ -n "$MAXMIND_LICENSE_KEY" ]; then
            echo "Attempting automatic GeoIP download..."
            export GEOIP_DATABASE_PATH
            if /app/sso setup-geoip; then
                echo "✓ GeoIP database downloaded successfully"
            else
                echo "⚠ GeoIP setup failed - geographic features will be unavailable"
                echo "  The service will start but without impossible travel detection"
            fi
        else
            echo "⚠ MAXMIND_LICENSE_KEY not set - skipping automatic download"
            echo "  Geographic security features will be unavailable"
            echo ""
            echo "To enable GeoIP features:"
            echo "  1. Get a free license key: https://www.maxmind.com/en/geolite2/signup"
            echo "  2. Set environment variable: MAXMIND_LICENSE_KEY=your_key"
            echo "  3. Restart the container"
            echo ""
        fi
    fi
fi

# ============================================================================
# Start Application
# ============================================================================
echo "=== Starting SSO Service ==="
echo ""

# Execute the main application
exec /app/sso
