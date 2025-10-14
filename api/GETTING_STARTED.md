# Getting Started

This guide will help you get the SSO API running locally in under 5 minutes.

## Prerequisites

- Rust (1.75 or later)
- Cargo

That's it! No Docker, no external databases needed.

## Quick Start

1. **Clone the repository** (if you haven't already)

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and update any values as needed. The defaults will work for local development.

3. **Run the server**
   ```bash
   cargo run
   ```

That's it! The server will:
- Automatically create the SQLite database (`./data/data.db`)
- Run all migrations
- Bootstrap the platform owner from `PLATFORM_OWNER_EMAIL` in `.env`
- Start listening on `http://localhost:3000`

## What Just Happened?

The project uses SQLx with **offline mode**, which means:
- The `.sqlx/` directory contains cached query metadata
- No database connection is needed during compilation
- `cargo run` "just works" on first run

The SQLite database and migrations are handled automatically by the application at startup.

## Testing the API

```bash
# Check server health
curl http://localhost:3000/api/user

# View available OAuth providers
curl http://localhost:3000/auth/github
```

## Development Commands

```bash
# Run the server
cargo run

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy

# Run type checking
cargo check
```

## Project Structure

- `src/` - Application source code
- `migrations/` - Database migrations (run automatically)
- `.sqlx/` - SQLx query metadata cache (committed to repo)
- `data/` - SQLite database files (gitignored)

## Troubleshooting

### "Address already in use"
Port 3000 is already occupied. Either stop the other process or change `SERVER_PORT` in `.env`.

### Compilation errors about database queries
The `.sqlx/` directory might be out of sync. Regenerate it:
```bash
cargo sqlx prepare
```

## Next Steps

- Read [COMPREHENSIVE_SSO_API_DOCUMENTATION.md](./COMPREHENSIVE_SSO_API_DOCUMENTATION.md) for API details
- Check [CLAUDE.md](./CLAUDE.md) for development guidelines
- Set up OAuth credentials in `.env` for GitHub, Google, or Microsoft
