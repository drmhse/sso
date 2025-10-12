## 1. Journey Identification and End-to-End Tracing

I have identified the following primary user and system journeys. Each is traced across the `web-client` (or example app), `sso-sdk`, and `api` stacks.

### Journey 1: Admin Login and Session Establishment

This journey is for platform owners or organization admins to access the management dashboard.

1.  **`web-client` (UI - `views/auth/Login.vue`)**:
    *   The user is presented with "Sign in with..." buttons.
    *   Clicking a button triggers the `handleLogin(provider)` method.

2.  **`sso-sdk` (Client-Side - `modules/auth.ts`)**:
    *   `handleLogin` calls `sso.auth.getAdminLoginUrl(provider)`.
    *   The SDK constructs the URL: `http://localhost:3000/auth/admin/:provider`. It does not make an API call, it simply prepares the URL for redirection.

3.  **`api` (Backend - `handlers/auth.rs` -> `auth_admin_provider`)**:
    *   The `GET /auth/admin/:provider` endpoint is hit.
    *   A dedicated "admin" OAuth client is created using the `PLATFORM_*` environment variables.
    *   A unique `state` (CSRF token) and `pkce_verifier` (for Microsoft) are generated.
    *   This state is stored in the `oauth_states` table with `is_admin_flow = true`.
    *   The user is redirected to the OAuth provider (e.g., GitHub) for authorization.

4.  **`api` (Backend - `handlers/auth.rs` -> `auth_admin_callback`)**:
    *   After successful OAuth, the provider redirects back to `GET /auth/admin/:provider/callback`.
    *   The handler validates the `state` parameter against the `oauth_states` table and confirms `is_admin_flow`.
    *   It exchanges the `code` for an OAuth token using the admin OAuth client.
    *   It fetches the user's profile from the provider (`get_provider_user_info`).
    *   It finds or creates a user in the `users` table (`find_or_create_user`).
    *   It upserts the provider details into the `identities` table.
    *   It determines the correct JWT to issue:
        *   If `is_platform_owner` is true for the user, a **Platform Owner JWT** is created (no `org` claim).
        *   If the user is a member of any organizations, an **Organization Management JWT** is created for their first/primary organization (with an `org` claim).
        *   If the user is new and has no orgs, a basic JWT is created (no `org` claim), prompting them to create one.
    *   A new entry is created in the `sessions` table, including a new `refresh_token`.
    *   The user is redirected to the `web-client`'s callback URL (`http://localhost:5173/callback`) with the `access_token` and `refresh_token` as query parameters.

5.  **`web-client` (UI - `views/auth/Callback.vue` & `stores/auth.js`)**:
    *   The callback view extracts the tokens from the URL.
    *   It calls the Pinia store action `authStore.handleLoginCallback(accessToken, refreshToken)`.
    *   The store saves both tokens to `localStorage`, decodes the JWT to get claims, sets the token in the SDK instance, and fetches the user profile to confirm the session is valid.
    *   The application state is now `authenticated`, and the user is redirected to the appropriate dashboard by the navigation guard in `router/index.js`.

### Journey 2: End-User SSO Login (Web Redirect)

This journey is for a final user of a tenant's application (e.g., a customer of "Acme Corp").

1.  **`examples/sample-app` (UI - `views/Home.vue`)**:
    *   The application calls `sso.auth.getLoginUrl(...)` with `org`, `service`, and `redirect_uri` parameters.
    *   The user's browser is redirected to the generated URL.

2.  **`sso-sdk` (Client-Side - `modules/auth.ts`)**:
    *   `getLoginUrl` constructs the URL: `http://localhost:3000/auth/:provider?org=...&service=...&redirect_uri=...`.

3.  **`api` (Backend - `handlers/auth.rs` -> `auth_provider`)**:
    *   The `GET /auth/:provider` endpoint is hit.
    *   It validates that the provided `redirect_uri` is registered for the specified service.
    *   It checks the `organization_oauth_credentials` table to see if the organization has **BYOO** credentials for this provider.
    *   It dynamically creates an OAuth client: either the custom BYOO client or the platform's default.
    *   It generates and stores a `state` in the `oauth_states` table, linking it to the `org`, `service`, and `redirect_uri`. `is_admin_flow` is `false`.
    *   The user is redirected to the OAuth provider.

4.  **`api` (Backend - `handlers/auth.rs` -> `auth_callback`)**:
    *   The provider redirects to `GET /auth/:provider/callback`.
    *   The handler validates the `state`.
    *   It exchanges the `code` for a token using the correct client (BYOO or platform default).
    *   It fetches the user's profile, finds/creates a user, and upserts their identity. If BYOO was used, `issuing_org_id` is saved with the identity.
    *   It creates a **Service JWT** with `org` and `service` claims.
    *   It creates a session with a `refresh_token`.
    *   It records the successful login in the `login_events` table for analytics.
    *   The user is redirected to the service's original `redirect_uri` with the `access_token` and `refresh_token`.

### Journey 3: End-User Device Flow (for CLIs)

This journey involves a CLI (the device) and a web browser (for user interaction).

1.  **`examples/sample-byoo-cli` (CLI)**:
    *   The CLI starts the flow by calling `sso.auth.deviceCode.request(...)` with its `client_id`, `org`, and `service`.

2.  **`api` (Backend - `handlers/auth.rs` -> `device_code`)**:
    *   The `POST /auth/device/code` endpoint is hit.
    *   It validates the `client_id` against the `org` and `service` to ensure it's a valid service.
    *   It retrieves the service's `device_activation_uri`.
    *   It generates a `device_code` (for the CLI) and a `user_code` (for the human).
    *   It sends a request to a **batching DB writer task** (`db_writer_task`) to create an entry in the `device_codes` table. This is a performance optimization.
    *   It immediately returns the codes and `verification_uri` to the CLI.

3.  **User (in Browser - `examples/sample-app/views/Activate.vue`)**:
    *   The user opens the `verification_uri` and enters the `user_code`.
    *   The frontend calls `sso.auth.deviceCode.verify(userCode)`.

4.  **`api` (Backend - `handlers/auth.rs` -> `device_verify`)**:
    *   The `POST /auth/device/verify` endpoint is hit.
    *   It finds the `device_code` record by the `user_code`, checks for expiry, and returns the context (`org_slug`, `service_slug`, and available providers for that org).

5.  **User (in Browser - `examples/sample-app/views/Activate.vue`)**:
    *   The frontend uses the returned context to call `sso.auth.getLoginUrl(...)`, crucially passing the `user_code` in the parameters.
    *   This initiates a standard End-User SSO Login flow (Journey 2).

6.  **`api` (Backend - `handlers/auth.rs` -> `auth_callback`)**:
    *   During the callback, the handler finds the `user_code` in the `oauth_states` table.
    *   It finds the corresponding record in `device_codes` and updates its status to `'authorized'`, linking it to the `user_id`.
    *   It shows a success page to the user in the browser.

7.  **`examples/sample-byoo-cli` (CLI)**:
    *   While the user was authenticating, the CLI has been polling `sso.auth.deviceCode.exchangeToken(...)` every `interval` seconds.
    *   Initially, the API returns a `DEVICE_CODE_PENDING` error, which the CLI handles.

8.  **`api` (Backend - `handlers/auth.rs` -> `token_exchange`)**:
    *   Once the device code is authorized, the `POST /auth/token` endpoint succeeds.
    *   It validates the `device_code` and `client_id`.
    *   It confirms the code is `authorized` and has a `user_id`.
    *   It creates a **Service JWT** for that user, org, and service.
    *   It creates a session entry with a `refresh_token`.
    *   It returns the `access_token` to the CLI. The CLI is now authenticated.

### Journey 4: Session Renewal (Token Refresh)

This journey happens automatically when an access token expires.

1.  **`web-client` (UI - `api/interceptor.js`)**:
    *   The application makes an API call using the intercepted SDK (e.g., `sso.organizations.list()`).
    *   The API returns a `401 Unauthorized` error because the token is expired.
    *   The interceptor catches the `SsoApiError`. It checks if `isRefreshing` is false.
    *   It sets `isRefreshing = true` and calls `authStore.refreshAccessToken()`. Any other requests that fail during this time are queued.

2.  **`web-client` (Store - `stores/auth.js`)**:
    *   `refreshAccessToken` calls `sso.auth.refreshToken(this.refreshToken)`.

3.  **`sso-sdk` (Client-Side - `modules/auth.ts`)**:
    *   `refreshToken` makes a `POST /api/auth/refresh` call with the `refresh_token`.

4.  **`api` (Backend - `handlers/auth.rs` -> `refresh_token`)**:
    *   The handler finds the session by the provided `refresh_token`.
    *   It validates that the refresh token has not expired.
    *   It creates a **new** `access_token` and a **new** `refresh_token` (token rotation).
    *   It updates the existing session record in the `sessions` table with the new tokens and expiry dates.
    *   It returns the new token pair to the client.

5.  **`web-client` (UI - `stores/auth.js` & `api/interceptor.js`)**:
    *   The `authStore` receives the new tokens and updates its state and `localStorage`.
    *   The interceptor receives the new `access_token`.
    *   It processes the queue, re-trying the originally failed request(s) with the new token.
    *   The original call resolves successfully, and the user experiences no interruption.
