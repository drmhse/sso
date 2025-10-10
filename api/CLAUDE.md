# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Running
- `cargo build` - Build the SSO service
- `cargo run` - Run the service locally (requires .env file)
- `docker-compose up` - Run with Docker and SQLite
- `./scripts/docker-build.sh` - Build Docker image locally
- `./scripts/docker-publish.sh` - Publish Docker image

### Testing and Quality
- `cargo test` - Run all tests
- `cargo clippy` - Lint code
- `cargo fmt` - Format code

### Database
- SQLite database located at `./data/data.db` (or per DATABASE_URL env var)
- Schema defined in `migrations/00000000000000_initial_schema.sql`
- **IMPORTANT**: Never alter DB directly without migration file; and never run the migrations manually, they are ran by the app during startup.

## Architecture Overview

This is a multi-tenant SSO platform built in Rust using Axum, supporting B2B2C scenarios with OAuth2 providers (GitHub, Google, Microsoft) and Stripe billing integration.

### Core Components

**Authentication Flow:**
- SSO via OAuth2 (`src/auth/sso.rs`)
- JWT token management (`src/auth/jwt.rs`)
- Device flow for CLIs/mobile apps (`src/auth/device_flow.rs`)

**Database Layer:**
- SQLite with SQLx ORM (`src/db/`)
- Batched database writer for high-throughput device code creation (`main.rs:57-170`)
- Automatic WAL checkpointing every 10 seconds for performance

**Organization Management:**
- Multi-tenant organizations with member roles and invitations (`src/handlers/organizations.rs`, `src/handlers/invitations.rs`)
- Service per-organization model with plan-based billing
- Platform owner governance and approval workflows (`src/handlers/platform.rs`)

**Integration Services:**
- Stripe webhooks for subscription billing (`src/handlers/webhook.rs`, `src/billing/stripe.rs`)
- Token encryption service for secure credential storage (`src/encryption/`)
- Background token refresh job (`src/jobs/token_refresh.rs`)

### API Structure

**Public Routes:**
- `/auth/:provider` - OAuth2 initiation
- `/auth/device/*` - Device flow endpoints
- `/api/organizations` - Public organization creation

**Protected Routes (JWT Required):**
- `/api/user` - User profile
- `/api/organizations/*` - Organization management
- `/api/provider-token/:provider` - Provider token access

**Platform Owner Routes:**
- `/api/platform/*` - Platform governance and organization approval

### Key Environment Variables

All configuration is loaded from environment variables (.env file supported):
- `DATABASE_URL` - SQLite database path
- `JWT_SECRET` - JWT signing secret (required)
- OAuth provider credentials (GitHub, Google, Microsoft)
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` - Billing integration
- `PLATFORM_OWNER_EMAIL` - Auto-bootstrap platform owner

### Performance Optimizations

- Aggressive SQLite WAL checkpointing (TRUNCATE mode every 10s)
- Batched device code creation (256 items per batch, 5ms timeout)
- Background token refresh with encryption support
- Multi-threaded runtime (4 worker threads)

### Security Features

- Optional token encryption for stored OAuth tokens
- JWT-based session management with revocation tracking
- Role-based access control (platform owner vs regular users)
- CORS enabled for cross-origin requests

### CRITICAL

- when troubleshooting, propritize running type checks for rust code than running the server (unless integration test)
- do not use placeholders in code, always use actual implementation code no TODOs accepted
- when you can't figure some package API issue, prioritize using curl to fetch the documentation that is relevant or the Fetch tool
- do not give up, ever. always be resilient until all the compilation errors and warnings are all resolved
- you never have to write unit tests, only the integration test scripts in node.js (for end to end testing)
- always read the complete file to understand it correctly so that you don't leave around dead code or duplicate implementations
- respect proper rust architecture
- security comes first. always review the code for security (not vulnarabilites, just security such as routes protection from unauthorized access)
- be careful not to bake in environment variables to the image
- when writing a commit message, do not attribute to claude or anthropic. the only commiter in this app is DRM HSE <info@drmhse.com>
