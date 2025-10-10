#!/bin/bash
set -e

# Extract database path from DATABASE_URL
DB_PATH="${DATABASE_URL#sqlite:}"

# Create parent directory if it doesn't exist
DB_DIR=$(dirname "$DB_PATH")
mkdir -p "$DB_DIR"

# Create empty database file if it doesn't exist
if [ ! -f "$DB_PATH" ]; then
    echo "Creating database file at $DB_PATH"
    touch "$DB_PATH"
    chmod 666 "$DB_PATH"
fi

# Execute the main application
exec /app/sso
