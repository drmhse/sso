# Comprehensive SSO Platform API Documentation

## 1. Overview

This document provides a complete technical reference for the multi-tenant SSO platform. The system is designed to provide robust, secure, and flexible authentication for B2B2C applications.

It features a dual-architecture authentication system:
1.  **Platform & Organization Administration:** A dedicated OAuth2 flow using platform-managed credentials for administrative access to the platform itself and to individual organizations.
2.  **End-User Authentication (Bring Your Own OAuth - BYOO):** A flexible flow that allows tenant organizations to use their own custom OAuth2 application credentials, providing a white-labeled authentication experience for their end-users.

The platform is built in Rust using the Axum web framework and leverages a highly optimized SQLite database for performance and ease of deployment.

### Core Features
- **Multi-Tenant Organizations:** Securely isolated environments for each customer organization.
- **Dual OAuth Flows:** Separate, secure authentication paths for administrators and end-users.
- **Bring Your Own OAuth (BYOO):** Tenant organizations can connect their own GitHub, Google, and Microsoft OAuth applications.
- **Platform Governance:** A super-admin (Platform Owner) layer for approving, managing, and monitoring organizations.
- **Role-Based Access Control (RBAC):** Granular permissions for Platform Owners, Organization Owners, Admins, and Members.
- **Device Authorization Flow (RFC 8628):** Secure authentication for CLI tools, smart devices, and other headless applications.
- **Secure JWT Session Management:** Stateless authentication using JSON Web Tokens with a server-side revocation mechanism.
- **Encrypted Credential Storage:** Organization-provided OAuth secrets are securely encrypted at rest using AES-GCM.
- **Stripe Webhook Integration:** Foundation for subscription and billing management.

---

## 2. System Architecture & Key Concepts

### 2.1. Data Models

#### `User`
The global representation of an individual person. A user is uniquely identified by their email address.
```json
{
  "id": "string (UUID)",
  "email": "string",
  "is_platform_owner": "boolean",
  "created_at": "datetime (ISO 8601)"
}
```

#### `Organization`
A tenant in the system. Each organization is an isolated entity with its own users, services, and settings. They must be approved by a Platform Owner before becoming active.
```json
{
  "id": "string (UUID)",
  "slug": "string (unique identifier)",
  "name": "string",
  "owner_user_id": "string (FK to User)",
  "status": "string (pending|active|suspended|rejected)",
  "tier_id": "string (FK to OrganizationTier)",
  "max_services": "integer (optional override)",
  "max_users": "integer (optional override)",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

#### `Service`
An application belonging to an organization that uses the SSO platform for authentication. Each service has a unique `client_id` and can be configured with its own OAuth scopes and redirect URIs.
```json
{
  "id": "string (UUID)",
  "org_id": "string (FK to Organization)",
  "slug": "string",
  "name": "string",
  "service_type": "string (web|mobile|desktop|api)",
  "client_id": "string (unique)",
  "github_scopes": "string (JSON array)",
  "microsoft_scopes": "string (JSON array)",
  "google_scopes": "string (JSON array)",
  "redirect_uris": "string (JSON array of allowed URIs)",
  "created_at": "datetime"
}
```

#### `Membership`
Links a `User` to an `Organization` with a specific role.
```json
{
  "id": "string (UUID)",
  "org_id": "string (FK to Organization)",
  "user_id": "string (FK to User)",
  "role": "string (owner|admin|member)",
  "created_at": "datetime"
}
```

#### `OrganizationOAuthCredential`
Stores the custom, encrypted OAuth credentials for an organization's specific provider application (the core of BYOO).
```json
{
  "id": "string (UUID)",
  "org_id": "string (FK to Organization)",
  "provider": "string (github|google|microsoft)",
  "client_id": "string",
  "client_secret_encrypted": "blob (AES-GCM encrypted secret)",
  "encryption_key_id": "string",
  "created_at": "datetime"
}
```

### 2.2. JWT Structure & Types

The system issues different types of JWTs depending on the authentication context. The JWT payload (`Claims`) includes:

```json
{
  "sub": "user_id",
  "email": "user_email",
  "is_platform_owner": false,
  "org": "organization_slug",   // Present in Org and Service JWTs
  "service": "service_slug", // Present only in Service JWTs
  "plan": "plan_name",
  "features": ["feature1", "feature2"],
  "exp": 1672531199,
  "iat": 1672444800
}
```

There are three conceptual types of JWTs issued:

1.  **Platform Owner JWT:**
    *   `is_platform_owner`: `true`
    *   `org`: `null`
    *   `service`: `null`
    *   **Usage:** Accessing the `/api/platform/*` endpoints for top-level system administration.

2.  **Organization Management JWT:**
    *   `is_platform_owner`: `false`
    *   `org`: `"organization-slug"`
    *   `service`: `null`
    *   **Usage:** Accessing `/api/organizations/{org_slug}/*` endpoints for managing an organization's settings, members, services, etc.

3.  **End-User Service JWT:**
    *   `is_platform_owner`: `false`
    *   `org`: `"organization-slug"`
    *   `service`: `"service-slug"`
    *   **Usage:** Passed to the organization's own application (`redirect_uri`) for user session management within that specific service. It is also used to access user-centric API endpoints like `/api/user` and `/api/provider-token/:provider`.

### 2.3. Authentication Flows Explained

#### Flow A: Platform / Organization Admin Login

This flow is for administrators logging into a dashboard to manage the platform or a specific organization.

**Endpoints:** `/auth/admin/:provider` and `/auth/admin/:provider/callback`

1.  Admin visits the management dashboard and clicks "Login with GitHub/Google/etc.".
2.  The frontend redirects to `/auth/admin/:provider?org_slug={optional_org_slug}`.
3.  The SSO service uses the **platform's dedicated OAuth credentials** (from `PLATFORM_...` env vars) to redirect the admin to the provider.
4.  After the admin approves, the provider redirects back to `/auth/admin/:provider/callback`.
5.  The SSO service exchanges the code for a token and fetches the user's profile.
6.  It looks up the user by email in the database.
    *   **If `user.is_platform_owner` is true:** A **Platform Owner JWT** is generated.
    *   **If user is a member of `{optional_org_slug}`:** An **Organization Management JWT** is generated.
    *   **Otherwise:** The user is redirected to a frontend page to create a new organization.
7.  The user is redirected to the platform's admin dashboard callback URL (`PLATFORM_ADMIN_REDIRECT_URI`) with the JWT.

#### Flow B: End-User Login (with BYOO)

This flow is for end-users of a tenant's application.

**Endpoints:** `/auth/:provider` and `/auth/:provider/callback`

1.  A user on an organization's app (e.g., `https://app.my-customer.com`) clicks "Login".
2.  The customer's app redirects the user to the SSO service at `/auth/:provider?org=my-customer&service=main-app&redirect_uri=https://app.my-customer.com/callback`.
3.  The SSO service looks up the organization `my-customer`.
    *   **If `my-customer` has configured its own OAuth credentials (BYOO):** The SSO service uses those custom credentials to initiate the OAuth flow.
    *   **Otherwise:** It falls back to using the default platform-wide OAuth application credentials.
4.  The user is sent to the provider (GitHub, etc.) to authorize the application.
5.  The provider redirects back to `/auth/:provider/callback`.
6.  The SSO service exchanges the code, finds or creates the user, and generates an **End-User Service JWT** containing the user's identity within the context of `my-customer` and `main-app`.
7.  The service performs a final redirect back to the `redirect_uri` provided in step 2, appending the JWT: `https://app.my-customer.com/callback?token={jwt}`.

#### Flow C: Device Authorization (RFC 8628)

This flow is for CLIs and other devices without a web browser.

**Endpoints:** `/auth/device/code`, `/activate`, `/auth/device/verify`, `/auth/token`

1.  A CLI application makes a `POST` request to `/auth/device/code` with its `client_id`, `org`, and `service` slugs.
2.  The API responds with a `device_code`, a human-friendly `user_code` (e.g., `WXYZ-1234`), and a `verification_uri`.
3.  The CLI displays the `user_code` and asks the user to visit the `verification_uri` in a browser.
4.  The user visits `/activate`, enters the `user_code`, and is then taken through a standard web login flow (Flow B, but without a final `redirect_uri`). Upon successful login, the device is marked as authorized.
5.  Simultaneously, the CLI polls the `/auth/token` endpoint every few seconds, sending its `device_code`.
    *   Initially, it receives a `pending` error.
    *   Once the user completes step 4, the `/auth/token` endpoint responds with a valid **End-User Service JWT**.
6.  The CLI can now use this JWT to make authenticated API calls.

---

## 3. API Reference

All successful responses are `2xx`. Error responses follow a standard format (see Section 5).

### 3.1. Public Authentication Endpoints

These endpoints do not require a JWT.

#### `POST /api/organizations`
Create a new organization. The organization will be created with a `pending` status and must be approved by a Platform Owner.

- **Request Body:**
  ```json
  {
    "slug": "acme-corp",
    "name": "Acme Corporation",
    "owner_email": "founder@acme.com"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "organization": { /* Organization Object */ },
    "owner": { /* User Object for the owner */ },
    "membership": { /* Membership Object for the owner */ }
  }
  ```

#### `GET /auth/:provider`
Initiate the end-user OAuth2 web login flow.

- **Path Parameters:**
  - `provider`: `github` | `google` | `microsoft`
- **Query Parameters:**
  - `org` (required): The slug of the organization.
  - `service` (required): The slug of the service.
  - `redirect_uri` (optional): The final URL to redirect the user to with the JWT. Must be one of the URIs registered for the service.
- **Response:** `302 Found` redirect to the OAuth provider.

#### `GET /auth/:provider/callback`
Callback URL for the OAuth2 provider for the end-user flow. This is handled by the browser and should not be called directly.

#### `GET /auth/admin/:provider`
Initiate the Platform/Organization Admin OAuth2 web login flow.

- **Path Parameters:**
  - `provider`: `github` | `google` | `microsoft`
- **Query Parameters:**
  - `org_slug` (optional): If the user intends to manage a specific organization.
- **Response:** `302 Found` redirect to the OAuth provider using platform-specific admin credentials.

#### `GET /auth/admin/:provider/callback`
Callback URL for the admin OAuth2 flow.

#### `POST /auth/device/code`
Request a device and user code for the Device Flow.

- **Request Body:**
  ```json
  {
    "client_id": "service-client-id",
    "org": "acme-corp",
    "service": "acme-cli"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "device_code": "a_long_unguessable_string",
    "user_code": "ABCD-1234",
    "verification_uri": "https://sso.example.com/activate",
    "expires_in": 900,
    "interval": 5
  }
  ```

#### `GET /activate`
HTML page for the user to enter their `user_code`.

#### `POST /auth/device/verify`
Verify a `user_code` and initiate the web authentication part of the device flow. This is called from the `/activate` page form.

- **Request Body:**
  ```json
  {
    "user_code": "ABCD-1234"
  }
  ```
- **Response:** `302 Found` redirect to the provider selection page.

#### `POST /auth/token`
Exchange a `device_code` for a JWT after user authorization. This is polled by the device/CLI.

- **Request Body:**
  ```json
  {
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "a_long_unguessable_string",
    "client_id": "service-client-id"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "access_token": "your.jwt.token",
    "token_type": "Bearer",
    "expires_in": 86400
  }
  ```

### 3.2. Authenticated User Endpoints
**Authentication:** Requires any valid JWT.

#### `POST /api/auth/logout`
Revokes the provided JWT, invalidating the current session.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response:** `204 No Content`

#### `GET /api/user`
Get the profile of the currently authenticated user within their token's context.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response (`200 OK`):**
  ```json
  {
    "id": "user-uuid",
    "email": "user@example.com",
    "org": "organization-slug-from-jwt",
    "service": "service-slug-from-jwt"
  }
  ```

#### `PATCH /api/user`
Update the authenticated user's profile.

- **Headers:** `Authorization: Bearer {jwt}`
- **Request Body:**
  ```json
  {
    "email": "new.email@example.com"
  }
  ```
- **Success Response (`200 OK`):** Returns the updated User Response object.

#### `GET /api/subscription`
Get the current user's subscription details for the service specified in the JWT.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response (`200 OK`):**
  ```json
  {
    "service": "service-slug",
    "plan": "pro",
    "features": ["api-access", "advanced-analytics"],
    "status": "active",
    "current_period_end": "2024-02-15T10:30:00Z"
  }
  ```

#### `GET /api/provider-token/:provider`
Retrieve a fresh, valid OAuth access token for an external provider on behalf of the user. This will automatically refresh the token if it's expired.

- **Headers:** `Authorization: Bearer {jwt}`
- **Path Parameters:**
  - `provider`: `github` | `google` | `microsoft`
- **Success Response (`200 OK`):**
  ```json
  {
    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
    "refresh_token": "ghr_1B4a2e378f3bc1e6b2c5f1e4d7a8b9c0d",
    "expires_at": "2024-02-15T10:30:00Z",
    "scopes": ["user", "repo"],
    "provider": "github"
  }
  ```

### 3.3. Organization Management Endpoints
**Authentication:** Requires an **Organization Management JWT** or **Platform Owner JWT**. Access is restricted to members of the organization specified in the path.

#### `GET /api/organizations`
List all organizations the authenticated user is a member of.

- **Headers:** `Authorization: Bearer {jwt}`
- **Query Parameters:** `page`, `limit`, `status`
- **Success Response (`200 OK`):**
  ```json
  [
    {
      "organization": { /* Organization Object */ },
      "membership_count": 5,
      "service_count": 3,
      "tier": { /* OrganizationTier Object */ }
    }
  ]
  ```

#### `GET /api/organizations/:org_slug`
Get detailed information for a specific organization.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response (`200 OK`):** Returns a single Organization Response object as shown above.

#### `PATCH /api/organizations/:org_slug`
Update organization details.
**Authorization:** Requires `owner` or `admin` role.

- **Headers:** `Authorization: Bearer {jwt}`
- **Request Body:**
  ```json
  {
    "name": "New Company Name",
    "max_services": 20,
    "max_users": 50
  }
  ```
- **Success Response (`200 OK`):** Returns the updated Organization Response object.

#### Member Management (`/api/organizations/:org_slug/members`)
- `GET /`: List members of the organization.
- `PATCH /:user_id`: Update a member's role. (**Owner only**)
- `POST /:user_id`: Remove a member from the organization. (**Owner/Admin**)
- `POST /transfer-ownership`: Transfer ownership to another member. (**Owner only**)

#### BYOO Credential Management (`/api/organizations/:org_slug/oauth-credentials/:provider`)
- `POST /`: Set or update the custom OAuth credentials for a provider. (**Owner/Admin**)
  - **Request Body:** `{ "client_id": "...", "client_secret": "..." }`
- `GET /`: Get the configured `client_id` for a provider (secret is never returned). (**Member**)

### 3.4. Service & Plan Management Endpoints
**Authentication:** Requires an **Organization Management JWT** or **Platform Owner JWT**. Access is restricted to the organization specified.

#### `POST /api/organizations/:org_slug/services`
Create a new service for an organization.
**Authorization:** Requires `owner` or `admin` role.

- **Request Body:**
  ```json
  {
    "slug": "dashboard-app",
    "name": "Company Dashboard",
    "service_type": "web",
    "github_scopes": ["user:email", "read:org"],
    "redirect_uris": ["https://app.my-customer.com/callback"]
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "service": { /* Service Object */ },
    "provider_grants": [ /* ProviderTokenGrant Objects */ ],
    "default_plan": { /* Plan Object for the 'free' tier */ },
    "usage": {
      "current_services": 2,
      "max_services": 10,
      "tier": "Pro Tier"
    }
  }
  ```

#### Other Service Endpoints (`/api/organizations/:org_slug/services/:service_slug`)
- `GET /`: Get service details. (**Member**)
- `PATCH /`: Update service details. (**Owner/Admin**)
- `DELETE /`: Delete a service. (**Owner only**)
- `POST /plans`: Create a new subscription plan for the service. (**Owner/Admin**)
- `GET /plans`: List all plans for the service. (**Member**)

### 3.5. Invitation Management Endpoints
**Authentication:** Requires a JWT.

- `POST /api/organizations/:org_slug/invitations`: Create and send an invitation. (**Owner/Admin**)
- `GET /api/organizations/:org_slug/invitations`: List invitations for an organization. (**Owner/Admin**)
- `POST /api/organizations/:org_slug/invitations/:invitation_id`: Cancel a pending invitation. (**Owner/Admin**)
- `GET /api/invitations`: List invitations received by the current user.
- `POST /api/invitations/accept`: Accept an invitation using its token.
- `POST /api/invitations/decline`: Decline an invitation using its token.

### 3.6. Platform Owner Endpoints
**Authentication:** Requires a **Platform Owner JWT**.

- `GET /api/platform/organizations`: List all organizations on the platform with filters.
- `POST /api/platform/organizations/:id/approve`: Approve a pending organization and assign a tier.
- `POST /api/platform/organizations/:id/reject`: Reject a pending organization with a reason.
- `POST /api/platform/organizations/:id/suspend`: Suspend an active organization.
- `POST /api/platform/organizations/:id/activate`: Re-activate a suspended organization.
- `PATCH /api/platform/organizations/:id/tier`: Update an organization's tier and resource limits.
- `POST /api/platform/owners`: Promote an existing user to a platform owner.
- `GET /api/platform/audit-log`: Retrieve the platform-wide audit log with filters.

### 3.7. Webhook Endpoints

#### `POST /webhooks/stripe`
Endpoint for receiving and processing Stripe webhook events.

- **Headers:** `Stripe-Signature` (required)
- **Response:** `200 OK` on success.

---

## 4. Configuration (Environment Variables)

The system is configured entirely through environment variables.

| Variable                          | Required | Description                                                                                    |
| --------------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| **Database**                      |          |                                                                                                |
| `DATABASE_URL`                    | Yes      | Connection string for the SQLite database (e.g., `sqlite:./data/sso.db`).                      |
| **JWT**                           |          |                                                                                                |
| `JWT_SECRET`                      | Yes      | A long, random, secret string for signing JWTs.                                                |
| `JWT_EXPIRATION_HOURS`            | No       | JWT lifetime in hours. Defaults to `24`.                                                       |
| **Server**                        |          |                                                                                                |
| `BASE_URL`                        | Yes      | The public base URL of the service (e.g., `http://localhost:3000`).                            |
| `SERVER_HOST`                     | No       | Host to bind the server to. Defaults to `0.0.0.0`.                                             |
| `SERVER_PORT`                     | No       | Port to bind the server to. Defaults to `3000`.                                                |
| `PLATFORM_ADMIN_REDIRECT_URI`     | Yes      | The callback URL for the admin frontend application.                                           |
| **Platform Owner**                |          |                                                                                                |
| `PLATFORM_OWNER_EMAIL`            | Yes      | Email of the user to be automatically designated as the platform owner on startup.             |
| **Default OAuth Apps**            | Yes      | Credentials for the platform's default apps, used when an organization doesn't bring their own.  |
| `GITHUB_CLIENT_ID`                | Yes      |                                                                                                |
| `GITHUB_CLIENT_SECRET`            | Yes      |                                                                                                |
| `GITHUB_REDIRECT_URI`             | Yes      |                                                                                                |
| `GOOGLE_CLIENT_ID`...             | Yes      | ...and so on for Google and Microsoft.                                                         |
| **Platform Admin OAuth Apps**     | Yes      | Credentials for the dedicated OAuth apps used **only for the admin login flow**.               |
| `PLATFORM_GITHUB_CLIENT_ID`       | Yes      |                                                                                                |
| `PLATFORM_GITHUB_CLIENT_SECRET`   | Yes      |                                                                                                |
| `PLATFORM_GOOGLE_CLIENT_ID`...    | Yes      | ...and so on for Google and Microsoft.                                                         |
| **Security**                      |          |                                                                                                |
| `ENCRYPTION_KEY`                  | No       | 32-byte (64 hex characters) key for encrypting BYOO secrets. If not set, secrets are not encrypted. |
| **Billing**                       |          |                                                                                                |
| `STRIPE_SECRET_KEY`               | Yes      | Your Stripe API secret key.                                                                    |
| `STRIPE_WEBHOOK_SECRET`           | Yes      | The signing secret for your Stripe webhook endpoint.                                           |

---

## 5. Error Handling

All API errors are returned with a consistent JSON structure.

- **Format:**
  ```json
  {
    "error": "Human-readable error message",
    "error_code": "ERROR_CODE_ENUM",
    "timestamp": "2024-01-15T10:30:00Z"
  }
  ```

- **Common Error Codes & Statuses:**
  - `400 Bad Request` (`BAD_REQUEST`, `DEVICE_CODE_EXPIRED`, `SERVICE_LIMIT_EXCEEDED`)
  - `401 Unauthorized` (`UNAUTHORIZED`, `TOKEN_EXPIRED`, `JWT_ERROR`)
  - `403 Forbidden` (`FORBIDDEN`, `ORGANIZATION_NOT_ACTIVE`)
  - `404 Not Found` (`NOT_FOUND`)
  - `500 Internal Server Error` (`INTERNAL_SERVER_ERROR`, `DATABASE_ERROR`, `OAUTH_ERROR`)
