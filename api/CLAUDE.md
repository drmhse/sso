# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Running
- `cargo build` - Build the SSO service
- `cargo run` - Run the service locally (requires .env file)
- `npm run dev` - Start development environment (from project root)
- `npm test` - Start test environment (from project root)

### Testing and Quality
- `cargo test` - Run all tests
- `cargo clippy` - Lint code
- `cargo fmt` - Format code

### Database
- SQLite database located at `./data/data.db` (or per DATABASE_URL env var)
- Comprehensive schema with recent migrations:
  - `00000000000000_initial_schema.sql` - Base schema
  - `20250107000000_admin_auth_and_byoo.sql` - Admin auth & BYOO support
  - `20250110000000_add_user_id_for_linking.sql` - Identity linking support
  - `20251010000000_add_login_events.sql` - Analytics tracking
- **IMPORTANT**: Never alter DB directly without migration file; and never run the migrations manually, they are ran by the app during startup.

## Workspace Layout

`api/` is a cargo workspace, not a single crate. The root package `sso` is the
HTTP layer; everything below it is a layer crate under `api/crates/`. Layers may
only depend downward, and cargo enforces that (a cycle will not compile).

| Crate | Holds | May depend on |
|---|---|---|
| `authos-core` | config, constants, error, utils, client_ip, rsa_keys, runtime_metadata | - |
| `authos-entities` | sea-orm models | core |
| `authos-crypto` | jwt, api_key, mfa, refresh_tokens, sso, safe_http, concurrency, encryption | core |
| `authos-db` | connection (`DB`), transaction helpers, models | core, entities |
| `authos-audit` | audit actor | core, entities, db |
| `authos-store` | store layer | core, entities, crypto, db, audit |
| `authos-services` | services, billing, email, jobs, device_flow, token_refresher | all of the above |
| `sso` (`api/src`) | handlers, router, middleware, state, http_security, lite_web | all |
| `authos-testkit` | shared test fixtures | dev-dependency only |

Each crate's `lib.rs` re-exports the layers below it under their original module
names, so `crate::error`, `crate::store`, `crate::entities` resolve everywhere;
you rarely need to write `authos_core::` explicitly.

`api/src/main.rs` and the three `sso_{sqlite,psql,mysql}.rs` binaries are 3-line
shims over `sso::run()`. Do not put logic in them: the crate used to be compiled
twice per build because `sso_sqlite.rs` was `include!("main.rs")`.

**Backend features.** Only crates with backend-conditional code carry
`db_sqlite`/`db_psql`/`db_mysql`, and they forward to every dependency that also
has such code, dev-dependencies included. Every internal dependency is declared
`default-features = false`. This matters: the transaction helpers differ in
arity per backend, so a mixed-feature graph fails to compile or, worse, selects
the wrong path. `npm run check:test-support` asserts the backends stay mutually
exclusive.

**`test-support` features** (`authos-crypto`, `authos-audit`, `authos-services`)
unlock test-only shortcuts - the all-zero device-trust fallback key, context-free
encrypt/decrypt, a worker-less `AuditHandle`. They are reachable only through
dev-dependencies and must never enter a production build; the same check script
enforces this.

**Adding a module:** put it in the lowest layer that can hold it, add it to
`scripts/check-layers.mjs`'s layer table, and run `npm run check:layers`.

**Policy checks scan the whole workspace.** Anything walking Rust sources must
use `scripts/lib/rust-sources.mjs` (or the Python equivalent in
`check-monitoring-assets.py`), never a bare `api/src`, or it will silently stop
covering the layer crates.

## Architecture Overview

This is a comprehensive multi-tenant SSO platform built in Rust using Axum, supporting B2B2C scenarios with OAuth2 providers (GitHub, Google, Microsoft), Stripe billing integration, analytics, and advanced identity management.

### Core Components

**Authentication System:**
- Dual authentication flows: end-user SSO and admin OAuth (`api/crates/authos-crypto/src/crypto/sso.rs`)
- JWT token management with revocation tracking (`api/crates/authos-crypto/src/crypto/jwt.rs`)
- Device flow for CLIs/mobile apps with enhanced state management (`api/crates/authos-services/src/services/device_flow.rs`)
- Admin authentication for platform/organization management
- Social account identity linking and unlinking (`src/handlers/identities.rs`)

**Database Layer:**
- SQLite with SQLx ORM (`api/crates/authos-db/src/db/`)
- Comprehensive schema: users, organizations, services, login_events, identities, oauth_states
- Batched database writer for high-throughput device code creation (256 items per batch, 5ms timeout)
- Aggressive WAL checkpointing (TRUNCATE mode every 10 seconds) for performance
- Background jobs for token refresh and maintenance

**Organization Management:**
- Multi-tenant organizations with member roles and invitations (`src/handlers/organizations/`, `src/handlers/invitations.rs`)
- Bring Your Own OAuth (BYOO) - custom OAuth credentials per organization
- End-user (customer) management with session control
- Service per-organization model with auto-provisioned plans and grants
- Platform owner governance and approval workflows (`src/handlers/platform/`)

**Analytics & Monitoring:**
- Comprehensive login event tracking and analytics (`src/handlers/analytics.rs`)
- Login trends by date range, service, and OAuth provider
- Recent login monitoring with pagination
- Organization-based analytics filtering

**Service & Plan Management:**
- Service lifecycle management with usage tracking (`src/handlers/services.rs`)
- Plan creation and subscription management
- Automatic provider token grants and default plan provisioning
- Service limits enforcement based on organization tiers

**Integration Services:**
- Stripe webhooks for subscription billing (`src/handlers/webhook.rs`, `api/crates/authos-services/src/billing/providers/stripe.rs`)
- Token encryption service for secure credential storage (`api/crates/authos-crypto/src/encryption/`)
- Background token refresh job with encryption support (`api/crates/authos-services/src/jobs/token_refresh.rs`)

### API Structure

**Public Routes:**
- `/auth/:provider` - End-user OAuth2 initiation
- `/auth/:provider/callback` - OAuth2 callback handling
- `/auth/device/*` - Device flow endpoints (RFC 8628)
- `/api/organizations` - Public organization creation

**Admin Authentication Routes:**
- `/auth/admin/:provider` - Admin OAuth initiation (platform/organization admins)
- `/auth/admin/:provider/callback` - Admin OAuth callback

**Protected Routes (JWT Required):**
- `/api/user` - User profile and identity management
- `/api/user/identities` - Social account linking/unlinking
- `/api/organizations/*` - Organization management, members, services
- `/api/organizations/:org_slug/oauth-credentials/:provider` - BYOO credential management
- `/api/organizations/:org_slug/users` - End-user (customer) management
- `/api/organizations/:org_slug/analytics/*` - Organization analytics and reporting
- `/api/organizations/:org_slug/services/:service_slug/api-keys` - API key management for service-to-service auth
- `/api/services/*` - Service and plan management
- `/api/invitations/*` - Invitation system
- `/api/provider-token/:provider` - Fresh OAuth token access

**Platform Owner Routes:**
- `/api/platform/*` - Platform governance and organization approval
- `/api/platform/organizations/*` - Organization lifecycle management
- `/api/platform/tiers` - Organization tier management
- `/api/platform/audit-log` - Platform audit trail

### Key Environment Variables

All configuration is loaded from environment variables (.env file supported):
- `DATABASE_URL` - Database connection string
- `JWT_PRIVATE_KEY_BASE64` - Base64-encoded RSA private key (required)
- `JWT_PUBLIC_KEY_BASE64` - Base64-encoded RSA public key (required)
- `JWT_KID` - Key ID for JWKS (required)
- Platform OAuth credentials: `PLATFORM_GITHUB_CLIENT_ID/SECRET`, `PLATFORM_GOOGLE_CLIENT_ID/SECRET`, `PLATFORM_MICROSOFT_CLIENT_ID/SECRET`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` - Billing integration
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_EMAIL` - Email configuration
- `ENCRYPTION_KEY` - 32-byte hex key for credential encryption
- `PLATFORM_OWNER_EMAIL` - Auto-bootstrap platform owner

See `.env.example` for complete list and `.env.dev`/`.env.test` for development/testing configurations.

### Performance Optimizations

- Aggressive SQLite WAL checkpointing (TRUNCATE mode every 10s)
- Batched device code creation (256 items per batch, 5ms timeout)
- Background token refresh with encryption support
- Multi-threaded runtime (4 worker threads)

### Security Features

- Encrypted OAuth credential storage for BYOO (AES-GCM encryption)
- JWT-based session management with revocation tracking
- Role-based access control (platform owner, organization admin, member)
- Enhanced redirect URI validation and security checks
- Login event tracking for comprehensive audit trails
- Session revocation capabilities for end-users
- API key authentication with SHA256 hashing and constant-time verification
- Identity linking security (prevents account lockout)
- CORS enabled for cross-origin requests
- Organization status enforcement (pending/suspended org restrictions)

### CRITICAL

- when troubleshooting, prioritize running type checks for rust code than running the server (unless integration test)
- do not use placeholders in code, always use actual implementation code no TODOs accepted
- when you can't figure some package API issue, prioritize using curl to fetch the documentation that is relevant or the Fetch tool
- do not give up, ever. always be resilient until all the compilation errors and warnings are all resolved
- you never have to write unit tests, only the integration test scripts in node.js (for end to end testing)
- always read the complete file to understand it correctly so that you don't leave around dead code or duplicate implementations
- respect proper rust architecture
- security comes first. always review the code for security (not vulnerabilities, just security such as routes protection from unauthorized access)
- be careful not to bake in environment variables to the image
- when writing a commit message, do not attribute to claude or anthropic. the only commiter in this app is DRM HSE <info@drmhse.com>
- any interactions with the api must be through the sdk. so, if you ever need to add something to the api, you must update the sdk and then call it meaning you must then use the local version after the update by relinking so that later patch and publish to npm after properly updating its docs and confirming nothing is broken.
