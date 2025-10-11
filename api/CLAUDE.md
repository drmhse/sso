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
- Comprehensive schema with recent migrations:
  - `00000000000000_initial_schema.sql` - Base schema
  - `20250107000000_admin_auth_and_byoo.sql` - Admin auth & BYOO support
  - `20250110000000_add_user_id_for_linking.sql` - Identity linking support
  - `20251010000000_add_login_events.sql` - Analytics tracking
- **IMPORTANT**: Never alter DB directly without migration file; and never run the migrations manually, they are ran by the app during startup.

## Architecture Overview

This is a comprehensive multi-tenant SSO platform built in Rust using Axum, supporting B2B2C scenarios with OAuth2 providers (GitHub, Google, Microsoft), Stripe billing integration, analytics, and advanced identity management.

### Core Components

**Authentication System:**
- Dual authentication flows: end-user SSO and admin OAuth (`src/auth/sso.rs`)
- JWT token management with revocation tracking (`src/auth/jwt.rs`)
- Device flow for CLIs/mobile apps with enhanced state management (`src/auth/device_flow.rs`)
- Admin authentication for platform/organization management
- Social account identity linking and unlinking (`src/handlers/identities.rs`)

**Database Layer:**
- SQLite with SQLx ORM (`src/db/`)
- Comprehensive schema: users, organizations, services, login_events, identities, oauth_states
- Batched database writer for high-throughput device code creation (256 items per batch, 5ms timeout)
- Aggressive WAL checkpointing (TRUNCATE mode every 10 seconds) for performance
- Background jobs for token refresh and maintenance

**Organization Management:**
- Multi-tenant organizations with member roles and invitations (`src/handlers/organizations.rs`, `src/handlers/invitations.rs`)
- Bring Your Own OAuth (BYOO) - custom OAuth credentials per organization
- End-user (customer) management with session control
- Service per-organization model with auto-provisioned plans and grants
- Platform owner governance and approval workflows (`src/handlers/platform.rs`)

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
- Stripe webhooks for subscription billing (`src/handlers/webhook.rs`, `src/billing/stripe.rs`)
- Token encryption service for secure credential storage (`src/encryption/`)
- Background token refresh job with encryption support (`src/jobs/token_refresh.rs`)

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
- `DATABASE_URL` - SQLite database path
- `JWT_SECRET` - JWT signing secret (required)
- OAuth provider credentials (GitHub, Google, Microsoft)
- Platform admin OAuth credentials for admin authentication:
  - `PLATFORM_GITHUB_CLIENT_ID`, `PLATFORM_GITHUB_CLIENT_SECRET`
  - `PLATFORM_GOOGLE_CLIENT_ID`, `PLATFORM_GOOGLE_CLIENT_SECRET`
  - `PLATFORM_MICROSOFT_CLIENT_ID`, `PLATFORM_MICROSOFT_CLIENT_SECRET`
- `PLATFORM_ADMIN_REDIRECT_URI` - Admin OAuth callback URL
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` - Billing integration
- `PLATFORM_OWNER_EMAIL` - Auto-bootstrap platform owner
- Encryption configuration for OAuth credential storage

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
