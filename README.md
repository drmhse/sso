# Multi-Tenant Single Sign-On (SSO) Platform

This repository contains the source code for a multi-tenant, production-grade Single Sign-On (SSO) platform. The system is designed to provide robust, secure, and flexible authentication for B2B2C applications, built with a focus on performance, security, and maintainability.

The platform's core is a high-performance Rust backend using the Axum framework, supported by a zero-dependency TypeScript SDK for API interaction and a Vue.js web client for administration. Its primary architectural feature is a dual-flow authentication system that separates administrative access from end-user authentication, enabling tenants to use their own custom OAuth2 credentials (Bring Your Own OAuth - BYOO).

## Architecture Overview

This project is structured as a monorepo containing three distinct but interconnected packages. The `web-client` consumes the `sso-sdk`, which in turn communicates with the `api`.

```
sso/
├── api/          # Rust (Axum) backend API
├── sso-sdk/      # TypeScript SDK for the API
└── web-client/   # Vue.js frontend for administration
```

*   **`sso/api`**: The core of the platform. This is a high-performance Rust application that exposes a RESTful API to handle all authentication flows, data storage, and business logic. It uses an optimized SQLite database for persistence and is designed for containerized deployment.

*   **`sso/sso-sdk`**: A zero-dependency, strongly-typed TypeScript SDK that provides a clean, programmatic interface for the `sso/api`. It is framework-agnostic and is published to npm as `@drmhse/sso-sdk`.

*   **`sso/web-client`**: The administrative dashboard for the platform. Built with Vue.js, it consumes the `sso-sdk` to provide a user interface for Platform Owners to manage tenants and for Organization Admins to manage their services, teams, and settings.

## Core Features

*   **Multi-Tenant Architecture**: Securely isolated environments for each customer organization, with distinct users, services, and configurations.
*   **Dual Authentication Flows**: Segregated authentication paths for platform/organization administrators versus application end-users.
*   **Bring Your Own OAuth (BYOO)**: Allows tenant organizations to connect and use their own custom OAuth2 applications for providers like GitHub, Google, and Microsoft.
*   **Device Authorization Flow (RFC 8628)**: Provides a secure authentication method for headless applications, command-line tools, and smart devices.
*   **Platform Governance Layer**: A super-admin (Platform Owner) role with a complete approval workflow for new organizations, tier management, and platform-wide auditing capabilities.
*   **Comprehensive Analytics**: Detailed login, growth, and activity metrics for both individual organizations and the entire platform.
*   **Identity Management**: End-users can link and unlink multiple social accounts (e.g., GitHub, Google) to a single profile.
*   **End-User Management**: Tools for organization admins to manage their customers, including viewing profiles and revoking active sessions.
*   **Role-Based Access Control (RBAC)**: Granular permissions for Platform Owners, Organization Owners, Admins, and Members enforced at the API level.
*   **Secure Credential Management**: Tenant-provided OAuth secrets are encrypted at rest using AES-GCM.
*   **High-Performance Design**: Built with Rust and Axum for speed and safety, leveraging an optimized SQLite database with WAL mode, batched writes, and background jobs for maintenance.
*   **Stripe Webhook Integration**: Foundation for subscription and billing management.

## System Prerequisites

To build and run this project locally, the following dependencies are required:

*   **Rust**: Version 1.89 or higher
*   **Node.js**: Version 18 or higher
*   **Docker & Docker Compose**: For containerized deployment and local environment setup.

## Getting Started

Follow these steps to set up and run the entire platform locally for development.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/drmhse/sso.git
    cd sso
    ```

2.  **Configure the Backend Environment**
    Navigate to the API directory and create an environment file from the example.
    ```bash
    cd api
    cp .env.example .env
    ```
    Populate the `.env` file with the necessary secrets for JWT, OAuth providers, and Stripe. A crucial variable is `PLATFORM_OWNER_EMAIL`, which automatically grants super-admin privileges to the specified user upon their first login.

3.  **Build and Run the Backend API**
    Using Docker Compose is the recommended method as it encapsulates the environment. From the `sso/api` directory:
    ```bash
    docker-compose up --build -d
    ```
    The API will be available at `http://localhost:3000`. Database migrations are applied automatically on startup.

4.  **Set Up the Web Client**
    Install dependencies for the frontend application. The web client will use the published SDK from npm.
    ```bash
    # From the sso/web-client directory
    cd ../web-client
    npm install
    ```

5.  **Run the Web Client**
    Start the Vite development server.
    ```bash
    npm run dev
    ```
    The web client will be available at `http://localhost:5173` and is configured via `.env.development` to communicate with the local API.

At this point, the complete system is running locally. You can access the admin dashboard to interact with the platform.

## Usage Example (SDK)

The `sso-sdk` provides a simple and powerful way to interact with the platform.

```typescript
import { SsoClient, SsoApiError } from '@drmhse/sso-sdk';

// Initialize the client
const sso = new SsoClient({
  baseURL: 'http://localhost:3000',
  token: localStorage.getItem('sso_token')
});

// Example: Redirect a user to log in
function redirectToLogin() {
  const loginUrl = sso.auth.getLoginUrl('github', {
    org: 'acme-corp',
    service: 'main-app',
    redirect_uri: 'http://localhost:4000/callback' // Your app's callback URL
  });
  window.location.href = loginUrl;
}

// Example: Fetch user profile after authentication
async function fetchUserProfile() {
  try {
    const profile = await sso.user.getProfile();
    console.log(`Authenticated as: ${profile.email}`);
  } catch (error) {
    if (error instanceof SsoApiError && error.isAuthError()) {
      console.error('Session expired. Please log in again.');
    }
  }
}
```

## Live Examples

The `examples/` directory contains runnable applications that demonstrate key authentication flows. These are the best way to see the SDK in action. Ensure the backend API is running before starting the examples.

### `examples/sample-app`
A simple Vue.js web application that showcases two key flows:
1.  The standard **Web Redirect Flow** for end-user login.
2.  The **Device Activation UI** (`/activate`) that works with the CLI examples, allowing users to authorize devices from their browser.

**To run:**
```bash
cd examples/sample-app
npm install
npm run dev
```

### `examples/sample-byoo-cli`
Demonstrates the **End-User (BYOO) Device Flow**. This is perfect for seeing how a tenant's own CLI application would authenticate its users through the SSO platform, using the tenant's custom OAuth credentials if configured.

**To run:**
```bash
cd examples/sample-byoo-cli
npm install
npm start
```

### `examples/sample-admin-cli`
Demonstrates the purpose and structure of the **Platform Admin Device Flow**. This is ideal for building secure administrative CLI tools for managing the entire SSO platform, separate from any specific tenant.

**To run:**
```bash
cd examples/sample-admin-cli
npm install
npm start
```

## Development Workflow

A typical development workflow involves the following sequence:

1.  **API Changes**: Modify the Rust code in `sso/api`. Rebuild and restart the API service (`docker-compose up --build`).
2.  **SDK Changes**: If an API contract has changed, update the types and methods in `sso/sso-sdk`. After making changes, increment the version in `package.json` and run `npm run build`.
3.  **Local Testing**: To test SDK changes in the `web-client` before publishing, link the local package:
    ```bash
    # In sso/sso-sdk directory
    npm link
    
    # In sso/web-client directory
    npm link @drmhse/sso-sdk
    ```
4.  **Publish SDK**: Once changes are verified, publish the new version to npm from the `sso-sdk` directory:
    ```bash
    npm publish
    ```
5.  **Update Web Client**: Update the SDK version in `sso/web-client/package.json` and run `npm install` to pull the latest changes from npm.

## Testing Strategy

The platform employs a multi-layered testing strategy to ensure reliability and correctness.

*   **Backend Unit Tests**: Located within the `sso/api` package, executed via `cargo test`. These cover individual functions and modules in the Rust backend.
*   **End-to-End Integration Tests**: A comprehensive suite of Node.js tests located in `etc/test-integration/` that test the API endpoints against a running instance of the service.
    ```bash
    # Run all integration tests
    cd etc/test-integration && npm test

    # Run specific test suites
    npm run test:auth
    npm run test:organizations
    ```
*   **Load Tests**: Performance testing scripts using k6 are located in `etc/load-tests/`.

## Deployment

The `sso/api` is designed for containerized deployment. The provided multi-stage `Dockerfile` builds a minimal, optimized production image.

*   **Configuration**: The application is configured exclusively through environment variables, adhering to twelve-factor app principles. No secrets are baked into the image.
*   **Database**: The SQLite database file should be mounted as a persistent volume to `/app/data` within the container.
*   **Resource Limits**: The service is optimized for low-resource environments. For a production VPS deployment, recommended resource limits are **1 vCPU** and **1GB RAM**.

## License

This project contains components with different licenses. Please consult the `LICENSE` file within each package for specific terms.

*   **`sso/api`**: Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
*   **`sso/sso-sdk`**: Licensed under the MIT License.
