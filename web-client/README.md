# SSO Platform - Web Client

This package contains the administrative web client for the Multi-Tenant SSO Platform. It serves as the primary user interface for both Platform Owners and Organization Administrators to manage the system's resources, including organizations, services, team members, and platform-wide settings.

The application is built using Vue.js 3 and consumes the `@drmhse/sso-sdk` npm package to interact with the backend API, providing a reactive and secure management experience.

## Core Features

*   **Secure Authentication**: Implements the OAuth2 administrative login flow for platform and organization access.
*   **Dual-Mode Dashboards**: Provides distinct, permission-driven views for Platform Owners (platform-wide management) and Organization Administrators (tenant-specific management).
*   **Comprehensive Management Interfaces**: User interfaces for managing organizations, services, team members, invitations, and BYOO (Bring Your Own OAuth) credentials.
*   **Role-Based Access Control (RBAC)**: The UI dynamically adapts to the authenticated user's role, restricting access to sensitive operations based on claims within their JSON Web Token (JWT).
*   **Reactive State Management**: Utilizes Pinia for a centralized, predictable, and typed state management layer that handles all API interactions.

## Technology Stack

*   **Framework**: Vue.js 3 (Composition API with `<script setup>`)
*   **State Management**: Pinia
*   **Routing**: Vue Router
*   **HTTP Client**: The `@drmhse/sso-sdk` npm package, which provides a typed interface to the backend API.
*   **UI Framework**: Tailwind CSS with Headless UI for accessible components.
*   **Build Tool**: Vite

## Prerequisites

*   Node.js version 18 or higher.
*   A running instance of the `sso/api` backend service.

## Local Development Setup

Follow these steps to run the web client in a local development environment.

1.  **Install Dependencies**
    From the `sso/web-client` directory, install the required npm packages:
    ```bash
    npm install
    ```
    This will automatically install the latest version of `@drmhse/sso-sdk` from npm.

2.  **Configure Environment Variables**
    Create a local environment file by copying the development example:
    ```bash
    cp .env.development .env.local
    ```
    The default `VITE_API_BASE_URL` is set to `http://localhost:3000`, which corresponds to the default address of the local `sso/api` service. Adjust this value if your backend is running on a different address.

3.  **Run the Development Server**
    Start the Vite development server:
    ```bash
    npm run dev
    ```
    The application will be accessible at `http://localhost:5173`.

### SDK Version Management

The web client uses the published `@drmhse/sso-sdk` package from npm. To update to a newer version of the SDK:

```bash
# Check for newer versions
npm outdated @drmhse/sso-sdk

# Update to the latest version
npm update @drmhse/sso-sdk

# Or install a specific version
npm install @drmhse/sso-sdk@0.1.2
```

For SDK developers who need to test local changes before publishing, you can temporarily link the local SDK:

```bash
# From the SDK directory
cd ../sso-sdk
npm run build && npm link

# From the web-client directory
cd ../web-client
npm link @drmhse/sso-sdk
```

Remember to unlink and reinstall the published version when done testing:
```bash
npm unlink @drmhse/sso-sdk
npm install @drmhse/sso-sdk
```

### Available Scripts

*   `npm run dev`: Starts the Vite development server with hot module replacement.
*   `npm run build`: Compiles and bundles the application for production.
*   `npm run preview`: Serves the production build locally for testing.

## Architecture

The client is architected for maintainability and a clear separation of concerns, following several key principles:

*   **SDK-Driven Data Layer**: All communication with the backend API is abstracted away by the `@drmhse/sso-sdk` npm package. No direct `fetch` or `axios` calls are made within the client application. A singleton instance of the `SsoClient` is initialized and shared across the application.

*   **Centralized State Management**: [Pinia](https://pinia.vuejs.org/) is used as the single source of truth for application state. All API requests and data mutations are handled through Pinia store actions. This ensures predictable state transitions and decouples components from data-fetching logic.

*   **Composable-Based Logic**: Reusable logic, such as permission checking (`usePermissions`) and notification management (`useNotifications`), is encapsulated in Vue Composition API composables for modularity and reuse.

*   **Router-Controlled Access**: [Vue Router](https://router.vuejs.org/) manages navigation and access control. Navigation guards are used to protect routes, initialize the authentication state, and enforce role-based access rules defined in route metadata.

### Project Structure

```
sso/web-client/
├── src/
│   ├── api/          # Singleton instance of the SSO SDK client
│   ├── assets/       # Static assets (images, fonts)
│   ├── components/   # Reusable, stateless UI components
│   ├── composables/  # Reusable Vue Composition API functions
│   ├── layouts/      # Main application layout components (e.g., AppLayout)
│   ├── router/       # Vue Router configuration and navigation guards
│   ├── stores/       # Pinia state management modules
│   ├── utils/        # Utility functions (formatters, parsers)
│   ├── views/        # Page-level components, mapped to routes
│   └── main.js       # Application entry point
└── ...
```

## Authentication and Routing

Authentication is managed via JSON Web Tokens (JWTs) obtained from the API's OAuth2 administrative login flow.

1.  **Token Storage**: The JWT is stored in `localStorage` under the key `sso_token`.
2.  **State Initialization**: On application startup, the main navigation guard in `router/index.js` triggers the `initializeAuth` action in the `auth` Pinia store. This action validates the stored token by attempting to fetch the user's profile.
3.  **Protected Routes**: Routes requiring authentication are marked with `meta: { requiresAuth: true }`. The navigation guard enforces this, redirecting unauthenticated users to the `/login` page.
4.  **Role-Based Routes**: Routes requiring platform owner privileges are marked with `meta: { requiresPlatformOwner: true }`. The navigation guard checks the decoded JWT claims to enforce this rule.
5.  **Logout**: The logout process involves calling the `POST /api/auth/logout` endpoint (via the SDK) to invalidate the session on the server, followed by clearing the token from `localStorage` and the Pinia store.

## Configuration

The application is configured via environment variables defined in `.env` files.

*   **`VITE_API_BASE_URL`**: The only required variable. It specifies the base URL of the `sso/api` backend.
    *   In `/.env.development`, this defaults to `http://localhost:3000`.
    *   In `/.env.production`, this should be set to the public URL of your deployed API.

## Building for Production

To create a production-ready build of the application, run the following command:

```bash
npm run build
```

This will compile the Vue components and assets, outputting the optimized, static files to the `dist/` directory. This directory can then be served by any static web server.
