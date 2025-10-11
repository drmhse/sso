# SSO Platform - Web Client

This package contains the administrative web client for the Multi-Tenant SSO Platform. It serves as the primary user interface for both Platform Owners and Organization Administrators to manage the system's resources.

The application is built using Vue.js 3 and consumes the `@drmhse/sso-sdk` npm package to interact with the backend API, providing a reactive and secure management experience.

## Core Features

*   **Secure Admin Login**: Implements the OAuth2 administrative login flow for platform and organization access.
*   **Dual-Mode Dashboards**: Provides distinct, permission-driven views for Platform Owners (platform-wide management) and Organization Administrators (tenant-specific management).
*   **Comprehensive Management Interfaces**:
    *   Organization lifecycle management (approval, suspension).
    *   Service creation and configuration.
    *   Team member and invitation management.
    *   Bring Your Own OAuth (BYOO) credential configuration.
    *   End-user (customer) session management.
*   **Automatic Token Refresh**: Implements an API interceptor that seamlessly refreshes expired sessions using refresh tokens, providing an uninterrupted user experience.
*   **Role-Based Access Control (RBAC)**: The UI dynamically adapts to the authenticated user's role, restricting access to sensitive operations based on claims within their JSON Web Token (JWT).
*   **Reactive State Management**: Utilizes Pinia for a centralized, predictable, and typed state management layer that handles all API interactions.

## Technology Stack

*   **Framework**: Vue.js 3 (Composition API with `<script setup>`)
*   **State Management**: Pinia
*   **Routing**: Vue Router
*   **API Client**: The `@drmhse/sso-sdk` npm package.
*   **UI Framework**: Tailwind CSS
*   **Build Tool**: Vite

## Local Development Setup

Follow these steps to run the web client in a local development environment.

1.  **Install Dependencies**
    From the `sso/web-client` directory, install the required npm packages:
    ```bash
    npm install
    ```

2.  **Configure Environment Variables**
    The `VITE_API_BASE_URL` in `.env.development` defaults to `http://localhost:3000`, which corresponds to the local `sso/api` service. No changes are needed if your backend is running on the default port.

3.  **Run the Development Server**
    Start the Vite development server:
    ```bash
    npm run dev
    ```
    The application will be accessible at `http://localhost:5173`.

### SDK Development

For SDK developers who need to test local changes before publishing, you can link the local SDK:

1.  **Build and Link SDK**: From the `sso/sso-sdk` directory:
    ```bash
    npm run build && npm link
    ```
2.  **Link in Web Client**: From the `sso/web-client` directory:
    ```bash
    npm link @drmhse/sso-sdk
    ```
Remember to unlink (`npm unlink @drmhse/sso-sdk`) and reinstall the published version when done.

## Architecture

*   **SDK-Driven Data Layer**: All communication with the backend API is abstracted away by the `@drmhse/sso-sdk`. A singleton instance of the `SsoClient` is initialized and shared across the application.

*   **Automatic Token Refresh Interceptor**: The application wraps the SDK client with an interceptor (`src/api/interceptor.js`) that automatically handles 401 Unauthorized errors. When a token expires, it transparently uses the stored refresh token to get a new session, queues any failed requests, and retries them upon success. This provides seamless session management without interrupting the user.

*   **Centralized State (Pinia)**: Pinia is the single source of truth. All API requests and data mutations are handled through Pinia store actions, ensuring predictable state transitions.

*   **Router-Controlled Access**: Vue Router manages navigation and access control. Navigation guards protect routes by checking for a valid token and ensuring the user has the required role (e.g., Platform Owner) as defined in route metadata.

### Project Structure

```
sso/web-client/
├── src/
│   ├── api/          # SDK client initialization and interceptor
│   ├── components/   # Reusable UI components
│   ├── composables/  # Reusable Vue Composition API functions (permissions, notifications)
│   ├── layouts/      # Main application layout components
│   ├── router/       # Vue Router configuration and navigation guards
│   ├── stores/       # Pinia state management modules
│   └── views/        # Page-level components, mapped to routes
└── ...
```

## Building for Production

To create a production-ready build of the application, run:

```bash
npm run build
```

This will output optimized, static files to the `dist/` directory, which can be served by any static web server.
