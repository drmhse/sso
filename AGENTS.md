# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend (Rust API)
- `cargo build` - Build the SSO service
- `cargo run` - Run the service locally (requires .env file)
- `cargo test` - Run all tests
- `cargo clippy` - Lint code
- `cargo fmt` - Format code
- `docker-compose up --build -d` - Run with Docker and SQLite
- `./scripts/docker-publish.sh` - Publish Docker image to registry

### SDK (TypeScript)
- `npm run build` - Build SDK for distribution
- `npm run dev` - Build SDK in watch mode
- `npm run typecheck` - Run TypeScript type checking
- `npm run lint` - Lint TypeScript code
- `npm run prepublishOnly` - Build before publishing to npm

### Web Client (Vue.js)
- `npm run dev` - Start Vite development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build

### Integration Tests
- `cd etc/test-integration && npm test` - Run all integration tests
- `cd etc/test-integration && npm run test:auth` - Run authentication tests only
- `cd etc/test-integration && npm run test:organizations` - Run organization tests only

## Architecture Overview

This is a multi-tenant SSO platform built as a monorepo with three main packages:

### Core Components

**API (Rust Backend)**: `api/`
- Axum-based REST API with SQLite database
- Dual authentication flows (admin OAuth2 vs end-user SSO)
- Device authorization flow (RFC 8628) for CLIs/mobile apps
- Multi-tenant organization management with role-based access control
- Bring Your Own OAuth (BYOO) - tenants use their own OAuth credentials
- Stripe webhook integration for billing
- Encrypted credential storage using AES-GCM

**SDK (TypeScript)**: `sso-sdk/`
- Zero-dependency client library built on native fetch
- Strongly typed API interface for all backend endpoints
- Framework-agnostic design works in any JavaScript environment
- Published to npm as `@drmhse/sso-sdk`

**Web Client (Vue.js)**: `web-client/`
- Administrative dashboard for platform owners and organization admins
- Uses the published SDK from npm for all API communication
- Pinia for state management, Vue Router for navigation
- Role-based UI that adapts to user permissions

### Key Architectural Patterns

**Multi-Tenancy**: Organizations are completely isolated with their own users, services, and OAuth configurations.

**Dual-Flow Authentication**:
- Admin flow: Platform/organization admins login via direct OAuth2
- End-user flow: Regular users authenticate through tenant-configured OAuth providers (BYOO)

**Device Flow Support**: RFC 8628 implementation enables CLIs and mobile apps to authenticate without browsers.

**Security by Design**:
- JWT-based sessions with revocation tracking
- OAuth tokens encrypted at rest
- All sensitive operations require proper authentication
- CORS enabled for cross-origin requests

### Database Schema

SQLite database with migrations in `api/migrations/`:
- Organizations, services, plans, and subscriptions
- Users, members, and invitations with role-based permissions
- Device codes for OAuth2 device flow
- Audit logs for platform governance
- Encrypted OAuth credentials for BYOO

### Critical Development Rules

- **NEVER** alter the database directly without migration files
- **NEVER** run migrations manually - they run automatically on startup
- **ALWAYS** use proper Rust error handling with `anyhow`/`thiserror`
- Security comes first - validate all inputs and check permissions
- No TODOs or placeholders in production code
- Prioritize type checking (`cargo clippy`) over running the server during development
- Use actual implementation code, never stubs or placeholders
- any interactions with the api must be through the sdk. so, if you ever need to add something to the api, you must update the sdk and then call it meaning you must then use the local version after the update by relinking so that later patch and publish to npm after properly updating its docs and confirming nothing is broken.

### Environment Configuration

All configuration via environment variables:
- `DATABASE_URL` - SQLite database path
- `JWT_PRIVATE_KEY_BASE64` - Base64-encoded RSA private key for JWT signing (required)
- `JWT_PUBLIC_KEY_BASE64` - Base64-encoded RSA public key for JWT verification (required)
- `JWT_KID` - Unique Key ID for key rotation and JWKS (required)
- OAuth provider credentials (GitHub, Google, Microsoft)
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` - Billing integration
- `PLATFORM_OWNER_EMAIL` - Auto-bootstrap platform owner

### SDK Development Workflow

1. Make changes to `sso-sdk/`
2. Run `npm run build` to compile
3. For local testing: `npm link` in SDK directory, then `npm link @drmhse/sso-sdk` in web-client
4. After testing: `npm publish` to release new version
5. Update web-client's package.json to use new SDK version

### Testing Strategy

- **Unit Tests**: Rust backend tests via `cargo test`
- **Integration Tests**: End-to-end Node.js tests in `etc/test-integration/`
- **Load Tests**: Performance testing scripts in `etc/load-tests/`
- No frontend unit tests - integration tests cover full user journeys

### Performance Optimizations

- SQLite WAL mode with aggressive checkpointing every 10 seconds
- Batched database writes for device code creation (256 items per batch)
- Background token refresh job with encryption support
- Multi-threaded runtime (4 worker threads)

### Deployment

- Docker container with multi-stage build
- SQLite database mounted as persistent volume at `/app/data`
- Environment-based configuration (12-factor app)
- Resource limits: 1 vCPU, 1GB RAM for production VPS deployment
