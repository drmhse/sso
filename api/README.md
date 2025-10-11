# SSO Platform - Backend API

[![Build Status](https://img.shields.io/github/actions/workflow/status/drmhse/sso/rust.yml?branch=main)](https://github.com/drmhse/sso/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

This is the core backend service for the multi-tenant SSO platform. It's a production-ready, high-performance API built in Rust using the Axum framework. It supports B2B2C scenarios with a unique dual-flow architecture, allowing both platform-level administration and tenant-specific "Bring Your Own OAuth" (BYOO) for providers like GitHub, Google, and Microsoft.

## Key Features

-   **Multi-Tenant Architecture**: Securely isolated organizations, each with their own members, services, and configurations.
-   **Dual Authentication Flows**:
    -   **Admin Flow**: A dedicated OAuth flow for super-admin and organization management dashboards.
    -   **End-User Flow**: A flexible flow for authenticating end-users of tenant applications.
-   **Bring Your Own OAuth (BYOO)**: Empower your customers (organizations) to connect and use their *own* OAuth applications for a white-labeled experience.
-   **Device Authorization Flow (RFC 8628)**: Securely authenticate headless applications, CLI tools, and smart devices.
-   **Platform Governance**: A super-admin (Platform Owner) role with a full approval workflow for new organizations, tier management, and platform-wide auditing.
-   **Identity Management**: End-users can link and unlink multiple social accounts (e.g., GitHub, Google) to a single profile.
-   **End-User Management**: Tools for organization admins to manage their customers, including session revocation.
-   **Role-Based Access Control (RBAC)**: Granular permissions for Platform Owners, Organization Owners, Admins, and Members.
-   **Secure JWT Session Management**: Stateless authentication with server-side revocation and secure refresh token rotation.
-   **Encrypted Credential Management**: Tenant-provided OAuth secrets are securely encrypted at rest using AES-GCM.
-   **Comprehensive Analytics**: Detailed login, growth, and activity metrics for both individual organizations and the entire platform.
-   **High-Performance Backend**: Built with Rust and Axum for speed and safety, leveraging a highly-optimized SQLite database with WAL mode and batched writes.
-   **Stripe Integration**: Ready for billing with webhook handlers for subscription management.

## Architecture at a Glance

The system operates on two primary user journeys:

#### 1. The Administrator Journey
An administrator logs in to a management dashboard using dedicated `/auth/admin/*` endpoints. Based on their role, they are issued a JWT granting access to either platform-wide settings or a specific organization's management panel.

#### 2. The End-User Journey
An end-user of a customer's application (e.g., `app.acme.com`) initiates a login. The SSO platform dynamically uses the `acme` organization's own OAuth credentials (BYOO) if configured, otherwise falling back to platform defaults. After authentication, the user is redirected back to `app.acme.com` with a service-scoped JWT.

## Quick Start

### Prerequisites

-   Rust 1.89 or higher
-   Docker & Docker Compose
-   An `.env` file (see Configuration section)

### Running with Docker (Recommended)

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

3.  **Build and run with Docker Compose:**
    This command builds the image and starts the service in the background. The database will be stored in the `sso/api/data` directory.
    ```bash
    docker-compose up --build -d
    ```

The API will be available at `http://localhost:3000`. Database migrations are applied automatically on startup.

## Configuration

The application is configured entirely via environment variables. Create a `.env` file in the `sso/api` directory from the `.env.example`.

| Variable                          | Required  | Description                                                                                    |
| :-------------------------------- | :-------: | :--------------------------------------------------------------------------------------------- |
| **Core**                          |           |                                                                                                |
| `DATABASE_URL`                    |    Yes    | Connection string for SQLite (e.g., `sqlite:/app/data/data.db` in Docker).                     |
| `JWT_SECRET`                      |    Yes    | A long, random, secure string for signing JWTs.                                                |
| `ENCRYPTION_KEY`                  |  **Yes**  | **Critical for security.** 32-byte (64-hex-char) key for encrypting organization secrets.        |
| **Server**                        |           |                                                                                                |
| `BASE_URL`                        |    Yes    | The public base URL of the service (e.g., `http://localhost:3000`).                            |
| `PLATFORM_ADMIN_REDIRECT_URI`     |    Yes    | The callback URL for your separate admin dashboard frontend (e.g., `http://localhost:5173/callback`). |
| `PLATFORM_DEVICE_ACTIVATION_URI`  |    Yes    | The URL for the platform-level device activation page (e.g., `http://localhost:5173/activate`).  |
| **Platform Owner**                |           |                                                                                                |
| `PLATFORM_OWNER_EMAIL`            |    Yes    | Email of the user to be automatically bootstrapped as the super-admin.                         |
| **Default OAuth Apps (for BYOO fallback)** |    Yes    | Credentials for the platform's default apps, used when an organization doesn't bring their own.  |
| `GITHUB_CLIENT_ID` / `_SECRET`... |    Yes    | ...and so on for Google and Microsoft.                                                         |
| **Admin OAuth Apps (for Admin Login)** |    Yes    | Credentials for the **dedicated** apps used **only for the admin login flow**.               |
| `PLATFORM_GITHUB_CLIENT_ID`...    |    Yes    | ...and so on for Google and Microsoft.                                                         |
| **Billing**                       |           |                                                                                                |
| `STRIPE_SECRET_KEY`               |    Yes    | Your Stripe API secret key.                                                                    |
| `STRIPE_WEBHOOK_SECRET`           |    Yes    | The signing secret for your Stripe webhook endpoint.                                           |

## API Documentation

For a complete list of all endpoints, detailed request/response models, and error codes, please see the [**Comprehensive API Documentation**](COMPREHENSIVE_SSO_API_DOCUMENTATION.md).

## Testing

The project includes both unit tests and a full end-to-end integration test suite.

*   **Unit Tests**: Run with `cargo test`.
*   **Integration Tests**: Located in `etc/test-integration/`. These run against a live instance of the API.
    ```bash
    # From the project root
    cd etc/test-integration
    npm install
    npm test
    ```

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the `LICENSE` file for details.
