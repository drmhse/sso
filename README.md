# Multi-Tenant Single Sign-On (SSO) Platform

This repository contains the source code for a multi-tenant, production-grade Single Sign-On (SSO) platform. The system is designed to provide robust, secure, and flexible authentication for B2B2C applications, built with a focus on performance, security, and maintainability.

The platform's core is a Rust backend using the Axum framework, supported by a TypeScript SDK for API interaction and a Vue.js web client for administration. Its primary architectural feature is a dual-flow authentication system that separates administrative access from end-user authentication, enabling tenants to use their own custom OAuth2 credentials (Bring Your Own OAuth - BYOO).

## Architecture Overview

This project is structured as a monorepo containing three distinct but interconnected packages:

```
sso/
├── api/          # Rust (Axum) backend API
├── sso-sdk/      # TypeScript SDK for the API
└── web-client/   # Vue.js frontend for administration
```

*   **`sso/api`**: The core of the platform. This is a high-performance Rust application that exposes a RESTful API to handle all authentication flows, data storage, and business logic. It uses an optimized SQLite database for persistence and is designed for containerized deployment.

*   **`sso/sso-sdk`**: A zero-dependency, strongly-typed TypeScript SDK that provides a clean, programmatic interface for the `sso/api`. It is framework-agnostic and can be used in any JavaScript or TypeScript environment (browser, Node.js, etc.).

*   **`sso/web-client`**: The administrative frontend for the platform. Built with Vue.js, it consumes the `sso-sdk` to provide a user interface for Platform Owners to manage tenants and for Organization Admins to manage their services, teams, and settings.

## Core Features

*   **Multi-Tenant Architecture**: Securely isolated environments for each customer organization, with distinct users, services, and configurations.
*   **Dual Authentication Flows**: Segregated authentication paths for platform/organization administrators versus application end-users.
*   **Bring Your Own OAuth (BYOO)**: Allows tenant organizations to connect and use their own custom OAuth2 applications for providers like GitHub, Google, and Microsoft, enabling a white-labeled user experience.
*   **Device Authorization Flow (RFC 8628)**: Provides a secure authentication method for headless applications, command-line tools, and smart devices.
*   **Platform Governance Layer**: A super-admin (Platform Owner) role with a complete approval workflow for new organizations, tier management, and platform-wide auditing capabilities.
*   **Role-Based Access Control (RBAC)**: Granular permissions for Platform Owners, Organization Owners, Admins, and Members are enforced at the API level.
*   **Secure Credential Management**: Tenant-provided OAuth secrets are encrypted at rest using AES-GCM.
*   **Stripe Webhook Integration**: Foundation for subscription and billing management.

## System Prerequisites

To build and run this project locally, the following dependencies are required:

*   **Rust**: Version 1.89 or higher (see `sso/api/Dockerfile`)
*   **Node.js**: Version 18 or higher
*   **Docker & Docker Compose**: For containerized deployment and local environment setup.
*   **SQLite**: Version 3.43 or higher (for local development outside of Docker).

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
    Populate the `.env` file with the necessary secrets for JWT, OAuth providers, and Stripe.

3.  **Build and Run the Backend API**
    Using Docker Compose is the recommended method as it encapsulates the environment.
    ```bash
    # From the sso/api directory
    docker-compose up --build -d
    ```
    The API will be available at `http://localhost:3000`. Database migrations are applied automatically on startup.

4.  **Set Up the TypeScript SDK**
    The SDK must be built and linked locally to be available to the `web-client`.
    ```bash
    # From the sso/sso-sdk directory
    cd ../sso-sdk
    npm install
    npm run build
    npm link
    ```

5.  **Set Up the Web Client**
    Link the SDK and install dependencies for the frontend application.
    ```bash
    # From the sso/web-client directory
    cd ../web-client
    npm install
    npm link @drmhse/sso-sdk
    ```

6.  **Run the Web Client**
    Start the Vite development server.
    ```bash
    npm run dev
    ```
    The web client will be available at `http://localhost:5173` and is configured via `.env.development` to communicate with the local API.

At this point, the complete system is running locally. You can access the admin dashboard to interact with the platform.

## Package Reference

For detailed information on each package, please refer to their individual documentation.

### `sso/api`
The Rust backend service. It contains all API endpoints, database logic, and authentication flows.
*   **Technology**: Rust, Axum, Tokio, SQLx, SQLite
*   **Documentation**: [sso/api/README.md](sso/api/README.md)

### `sso/web-client`
The administrative frontend application. It provides the user interface for managing the platform and its organizations.
*   **Technology**: Vue.js 3, Pinia, Vue Router, Tailwind CSS
*   **Documentation**: [sso/web-client/README.md](sso/web-client/README.md)

### `sso/sso-sdk`
The TypeScript client library for interacting with the `sso/api`.
*   **Technology**: TypeScript, native `fetch`
*   **Documentation**: [sso/sso-sdk/README.md](sso/sso-sdk/README.md)

## Development Workflow

A typical development workflow involves the following sequence:

1.  **API Changes**: Modify the Rust code in `sso/api`. Rebuild and restart the API service (`docker-compose up --build`).
2.  **SDK Changes**: If an API contract has changed, update the types and methods in `sso/sso-sdk`. Rebuild the SDK with `npm run build`.
3.  **Web Client Changes**: The `web-client` uses a linked version of the SDK, so changes are reflected automatically after the SDK is rebuilt. The Vite development server provides hot module replacement for frontend changes.

## Testing

The platform's testing strategy includes:

*   **Backend Unit & Integration Tests**: Located within the `sso/api` package, executed via `cargo test`.
*   **End-to-End Integration Tests**: A separate test suite (e.g., in `sso/api/test-integration`) can be used to test API flows against a running instance of the service.

## Deployment

The `sso/api` is designed for containerized deployment. The provided multi-stage `Dockerfile` builds a minimal, optimized production image.

*   **Configuration**: The application is configured exclusively through environment variables, adhering to twelve-factor app principles. No secrets are baked into the image.
*   **Database**: The SQLite database file should be mounted as a persistent volume to `/app/data` within the container.
*   **Statelessness**: The API service is stateless, allowing for horizontal scaling behind a load balancer (with considerations for a shared SQLite database if scaling beyond a single instance).

## Contributing

Contributions are welcome. Please adhere to the following process:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Commit your changes with clear, descriptive messages.
4.  Ensure all tests pass and any new functionality is covered by tests.
5.  Open a pull request with a detailed description of your changes.

## License

This project contains components with different licenses. Please consult the `LICENSE` file within each package for specific terms.

*   **`sso/api`**: Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
*   **`sso/sso-sdk`**: Licensed under the MIT License.
