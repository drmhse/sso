# Multi-Tenant SSO Platform

[![Build Status](https://img.shields.io/github/actions/workflow/status/drmhse/sso/rust.yml?branch=main)](https://github.com/drmhse/sso/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

A production-ready, multi-tenant SSO platform built in Rust using Axum. It supports B2B2C scenarios with a unique dual-flow architecture, allowing both platform-level administration and tenant-specific "Bring Your Own OAuth" (BYOO) for providers like GitHub, Google, and Microsoft.

## Key Features

-   **Multi-Tenant Architecture**: Securely isolated organizations, each with their own members, services, and configurations.
-   **Dual Authentication Flows**:
    -   **Admin Flow**: A dedicated OAuth flow using platform-managed credentials for super-admin and organization management dashboards.
    -   **End-User Flow**: A flexible flow for authenticating end-users of tenant applications.
-   **Bring Your Own OAuth (BYOO)**: Empower your customers (organizations) to connect and use their *own* OAuth applications, providing a seamless, white-labeled experience for their users.
-   **Device Authorization Flow (RFC 8628)**: Securely authenticate headless applications, CLI tools, and smart devices.
-   **Platform Governance**: A super-admin (Platform Owner) role with a full approval workflow for new organizations, tier management, and platform-wide auditing.
-   **Role-Based Access Control (RBAC)**: Granular permissions for Platform Owners, Organization Owners, Admins, and Members.
-   **Secure Credential Management**: Tenant-provided OAuth secrets are securely encrypted at rest using AES-GCM.
-   **High-Performance Backend**: Built with Rust and Axum for speed and safety, leveraging a highly-optimized SQLite database with WAL mode, batch processing for high-throughput device codes, and asynchronous token refresh jobs.
-   **Stripe Integration**: Ready for billing with webhook handlers for subscription management.

## Architecture at a Glance

The system operates on two primary user journeys:

#### 1. The Administrator Journey
An administrator (either a Platform Owner or an Organization Admin) logs in to a management dashboard. They use a dedicated set of endpoints (`/auth/admin/*`) that authenticate against the platform's own configured OAuth applications. Based on their role, they are issued a JWT that grants them access to either platform-wide settings or a specific organization's management panel.

#### 2. The End-User Journey
An end-user of a customer's application (e.g., `app.acme.com`) initiates a login. The SSO platform dynamically checks if the `acme` organization has provided its own OAuth credentials (BYOO). If so, it uses them; otherwise, it falls back to the platform's default apps. After authentication, the user is securely redirected back to `app.acme.com` with a JWT scoped specifically for that service.

## Quick Start

### Prerequisites

-   Rust 1.89 or higher
-   SQLite 3.43 or higher
-   An `.env` file (see Configuration section)

### Running Locally

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/drmhse/sso.git
    cd sso/api
    ```

2.  **Set up your environment:**
    Copy the example environment file and fill in your secrets.
    ```bash
    cp .env.example .env
    nano .env
    ```

3.  **Build the application:**
    ```bash
    cargo build --release
    ```

4.  **Run the service:**
    Database migrations are applied automatically on startup.
    ```bash
    cargo run --release
    ```

The API will be available at `http://localhost:3000`.

### Docker Deployment

The project includes a multi-stage `Dockerfile` for a lean, secure production image.

```bash
# Build and run with Docker Compose (recommended)
docker-compose up --build -d

# Or build the image manually
docker build -t sso-platform .
docker run -p 3000:3000 --env-file .env -v $(pwd)/data:/app/data sso-platform
```

## Configuration

The application is configured entirely via environment variables.

| Variable                          | Required | Description                                                                                    |
| :-------------------------------- | :------: | :--------------------------------------------------------------------------------------------- |
| **Core**                          |          |                                                                                                |
| `DATABASE_URL`                    |   Yes    | Connection string for SQLite (e.g., `sqlite:/app/data/data.db`).                               |
| `JWT_SECRET`                      |   Yes    | A long, random, secure string for signing JWTs.                                                |
| `JWT_EXPIRATION_HOURS`            |    No    | JWT lifetime in hours. Defaults to `24`.                                                       |
| `ENCRYPTION_KEY`                  |    No    | **Highly Recommended.** A 32-byte (64-hex-char) key for encrypting organization secrets.     |
| **Server**                        |          |                                                                                                |
| `BASE_URL`                        |   Yes    | The public base URL of the service (e.g., `http://localhost:3000`).                            |
| `PLATFORM_ADMIN_REDIRECT_URI`     |   Yes    | The callback URL for your separate admin dashboard frontend.                                   |
| `SERVER_PORT`                     |    No    | Port to run the service on. Defaults to `3000`.                                                |
| **Platform Owner**                |          |                                                                                                |
| `PLATFORM_OWNER_EMAIL`            |   Yes    | Email of the user to be automatically bootstrapped as the super-admin.                         |
| **Default OAuth Apps**            |   Yes    | Credentials for the platform's default apps (used as a fallback for BYOO).                     |
| `GITHUB_CLIENT_ID`                |   Yes    |                                                                                                |
| `GITHUB_CLIENT_SECRET`            |   Yes    |                                                                                                |
| `GITHUB_REDIRECT_URI`             |   Yes    |                                                                                                |
| `GOOGLE_...`, `MICROSOFT_...`     |   Yes    | ...and so on for other providers.                                                              |
| **Admin OAuth Apps**              |   Yes    | Credentials for the **dedicated** apps used **only for the admin login flow**.                 |
| `PLATFORM_GITHUB_CLIENT_ID`       |   Yes    |                                                                                                |
| `PLATFORM_GITHUB_CLIENT_SECRET`   |   Yes    |                                                                                                |
| `PLATFORM_GOOGLE_...`             |   Yes    | ...and so on for other providers.                                                              |
| **Billing**                       |          |                                                                                                |
| `STRIPE_SECRET_KEY`               |   Yes    | Your Stripe API secret key.                                                                    |
| `STRIPE_WEBHOOK_SECRET`           |   Yes    | The signing secret for your Stripe webhook endpoint.                                           |

## Core API Flows (High-Level Guide)

This API is designed around distinct user journeys.

#### 1. Organization Onboarding
1.  A new user calls `POST /api/organizations` with their desired `slug`, `name`, and `owner_email`.
2.  The organization is created with `pending` status.
3.  A Platform Owner uses the admin dashboard to view pending organizations.
4.  The Platform Owner calls `POST /api/platform/organizations/:id/approve` to activate the new organization and assign it a tier.

#### 2. Admin Login
1.  An admin is redirected to `/auth/admin/:provider`.
2.  After successful OAuth, the callback issues a JWT.
    -   If the user is the Platform Owner, they get a platform-level token.
    -   If they are an org member, they get an organization-level token.
3.  The admin is redirected to the management dashboard with the token.

#### 3. End-User Login (BYOO)
1.  A user is redirected from a tenant's app to `/auth/:provider?org=...&service=...&redirect_uri=...`.
2.  The SSO platform uses the organization's custom OAuth credentials if they exist.
3.  After successful OAuth, the user is redirected back to the tenant's `redirect_uri` with a service-scoped JWT.

#### 4. Device Login
1.  A CLI makes a `POST` to `/auth/device/code` to get a `user_code`.
2.  The user visits `/activate` in a browser and enters the code.
3.  The CLI polls `POST /auth/token` until it receives a JWT.

---

For a complete list of all endpoints, detailed request/response models, and error codes, please see the [**Comprehensive API Documentation**](COMPREHENSIVE_SSO_API_DOCUMENTATION.md).

## Security Features

This platform is built with security as a primary concern.

-   **Encrypted Secrets**: Organization-provided OAuth secrets are encrypted at rest using AES-GCM.
-   **Secure Redirects**: End-user login flows require the `redirect_uri` to be pre-registered with the service, preventing open redirect vulnerabilities.
-   **PKCE & State Validation**: The OAuth2 implementation uses Proof Key for Code Exchange (PKCE) for applicable providers and enforces `state` parameter validation to prevent CSRF attacks.
-   **JWT Revocation**: Sessions are tracked in the database, and logging out immediately invalidates the JWT on the server side.
-   **Granular RBAC**: Strict permission checks are enforced at the API layer for all management actions (e.g., only an `owner` can transfer ownership).

## Testing

The project is structured to support comprehensive integration testing.
(Placeholder for testing commands)
```bash
# Run all integration tests (example)
cd test-integration
npm install
npm test
```

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the `LICENSE` file for details.
