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
- **Secure JWT Session Management:** Stateless authentication using JSON Web Tokens with a server-side revocation mechanism and secure refresh token rotation.
- **Encrypted Credential Storage:** Organization-provided OAuth secrets are securely encrypted at rest using AES-GCM.
- **Comprehensive Analytics:** Detailed login and growth metrics for both individual organizations and the entire platform.
- **End-User Management:** Tools for organization admins to manage their customers, including session revocation.
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
  "device_activation_uri": "string (optional URI for device flow)",
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

#### `Session`
Tracks an active JWT session for revocation purposes and enables token refresh.
```json
{
  "id": "string (UUID)",
  "user_id": "string (FK to User)",
  "token_hash": "string (SHA256 of the JWT)",
  "expires_at": "datetime",
  "refresh_token": "string (unique, for token rotation)",
  "refresh_token_expires_at": "datetime",
  "created_at": "datetime"
}
```

#### `LoginEvent`
Records a successful login for analytics and auditing.
```json
{
    "id": "string (UUID)",
    "user_id": "string (FK to User)",
    "service_id": "string (FK to Service)",
    "provider": "string (github|google|microsoft)",
    "created_at": "datetime"
}
```

### 2.2. JWT Structure & Types

The system uses **RS256** (RSA with SHA-256) asymmetric signing for JWTs. The JWT header includes a `kid` (Key ID) field for key rotation support. The JWT payload (`Claims`) includes:

```json
{
  "sub": "user_id",
  "email": "user_email",
  "is_platform_owner": false,
  "org": "organization_slug",   // Optional: Present in Org and Service JWTs
  "service": "service_slug", // Optional: Present only in Service JWTs
  "plan": "plan_name",       // Optional
  "features": ["feature1"],  // Optional
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

This flow is for administrators logging into a dashboard to manage the platform or a specific organization. It uses the `/auth/admin/*` endpoints and the platform's dedicated OAuth credentials.

#### Flow B: End-User Login (with BYOO)

This flow is for end-users of a tenant's application. It uses the `/auth/:provider` endpoints and dynamically selects between the organization's custom OAuth credentials (BYOO) or the platform's default credentials.

#### Flow C: Device Authorization (RFC 8628)

This flow is for CLIs and other devices without a web browser.
1.  **CLI:** `POST /auth/device/code` to get `user_code` and `verification_uri`.
2.  **User:** Visits `verification_uri`, enters `user_code`. The frontend calls `POST /auth/device/verify` to get context and initiates a web login (Flow B).
3.  **CLI:** Polls `POST /auth/token` with the `device_code` until it receives a JWT.

#### Flow D: Refresh Token Flow

This flow allows clients to renew an expired access token without user interaction.
1.  **Client:** Stores the `refresh_token` received during the initial login.
2.  **Client:** When the `access_token` expires, sends a `POST /api/auth/refresh` request with the `refresh_token`.
3.  **API:** Validates the refresh token, revokes it, and issues a new `access_token` and a new `refresh_token` (token rotation).
4.  **Client:** Stores the new tokens and replaces the old ones.

---

## 3. API Reference

All successful responses are `2xx`. Error responses follow a standard format (see Section 5).

### 3.1. Public Authentication Endpoints

These endpoints do not require a JWT.

- `GET /.well-known/jwks.json`: Retrieve the JSON Web Key Set (JWKS) containing the public key(s) used to verify JWT signatures. This endpoint is public and requires no authentication.
- `POST /api/organizations`: Create a new organization (pending status).
- `GET /auth/:provider`: Initiate end-user OAuth login.
- `GET /auth/admin/:provider`: Initiate admin OAuth login.
- `POST /auth/device/code`: Request codes for Device Flow.
- `POST /auth/device/verify`: Verify a `user_code` from the web UI to get login context.
- `POST /auth/token`: Exchange a `device_code` for a JWT.

#### `GET /.well-known/jwks.json`
Retrieve the JSON Web Key Set (JWKS) containing the public RSA key(s) used to verify JWT signatures. This enables third-party backends to validate JWTs without accessing any shared secrets.

- **Authentication:** None required (public endpoint)
- **Success Response (`200 OK`):**
  ```json
  {
    "keys": [
      {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "sso-key-2025-01-01",
        "n": "base64url-encoded-modulus",
        "e": "base64url-encoded-exponent"
      }
    ]
  }
  ```

### 3.2. Authenticated User Endpoints
**Authentication:** Requires any valid JWT.

#### `POST /api/auth/logout`
Revokes the provided JWT, invalidating the current session.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response:** `204 No Content`

#### `POST /api/auth/refresh`
Exchanges a valid refresh token for a new access token and a new refresh token (token rotation).

- **Request Body:**
  ```json
  {
    "refresh_token": "your-refresh-token"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "access_token": "new.jwt.access-token",
    "refresh_token": "new-refresh-token",
    "expires_in": 86400
  }
  ```

#### `GET /api/user`
Get the profile of the currently authenticated user.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response (`200 OK`):** `{ "id": "...", "email": "...", "org": "...", "service": "..." }`

#### `PATCH /api/user`
Update the authenticated user's profile.

- **Headers:** `Authorization: Bearer {jwt}`
- **Request Body:** `{ "email": "new.email@example.com" }`

#### `GET /api/subscription`
Get the current user's subscription details for the service specified in the JWT.

- **Headers:** `Authorization: Bearer {jwt}`
- **Success Response (`200 OK`):** `{ "service": "...", "plan": "...", "features": [], "status": "...", "current_period_end": "..." }`

#### `GET /api/provider-token/:provider`
Retrieve a fresh, valid OAuth access token for an external provider on behalf of the user.

- **Headers:** `Authorization: Bearer {jwt}` (must be a **Service Context JWT** - obtained via service login)
- **Success Response (`200 OK`):** `{ "access_token": "...", "refresh_token": "...", "expires_at": "...", "scopes": [], "provider": "..." }`
- **Note:** This endpoint requires the JWT to have service context (org and service claims). It returns tokens that were obtained through that specific service's OAuth flow, ensuring proper token isolation between services.

### 3.3. Identity Management Endpoints
**Authentication:** Requires any valid JWT.

- `GET /api/user/identities`: List all social accounts linked to the authenticated user in the current authentication context (platform or specific service).
- `POST /api/user/identities/:provider/link`: Start the flow to link a new social account. Returns an `authorization_url` to redirect the user to.
- `DELETE /api/user/identities/:provider`: Unlink a social account.

### 3.4. Organization Management Endpoints
**Authentication:** Requires an **Organization Management JWT** or **Platform Owner JWT**.

- `GET /api/organizations`: List all organizations the user is a member of.
- `GET /api/organizations/:org_slug`: Get detailed information for a specific organization.
- `PATCH /api/organizations/:org_slug`: Update organization details. (**Owner/Admin**)

#### Member Management (`/api/organizations/:org_slug/members`)
- `GET /`: List members of the organization.
- `PATCH /:user_id`: Update a member's role. (**Owner only**)
- `POST /:user_id`: Remove a member from the organization. (**Owner/Admin**)
- `POST /transfer-ownership`: Transfer ownership to another member. (**Owner only**)
  - **Request Body:** `{ "new_owner_email": "member@example.com" }`

#### BYOO Credential Management (`/api/organizations/:org_slug/oauth-credentials/:provider`)
- `POST /`: Set or update custom OAuth credentials. (**Owner/Admin**)
- `GET /`: Get the configured `client_id` (secret is never returned). (**Member**)

#### End-User (Customer) Management (`/api/organizations/:org_slug/users`)
- `GET /`: List all end-users (customers) of the organization's services. (**Member**)
- `GET /:user_id`: Get detailed information for a specific end-user. (**Member**)
- `DELETE /:user_id/sessions`: Revoke all active sessions for an end-user, forcing re-authentication. (**Owner/Admin**)

#### Organization Analytics (`/api/organizations/:org_slug/analytics`)
- `GET /login-trends`: Get daily login counts over a date range.
- `GET /logins-by-service`: Get login counts grouped by service.
- `GET /logins-by-provider`: Get login counts grouped by OAuth provider.
- `GET /recent-logins`: Get a list of the most recent login events.

### 3.5. Service & Plan Management Endpoints
**Authentication:** Requires an **Organization Management JWT** or **Platform Owner JWT**.

- `POST /api/organizations/:org_slug/services`: Create a new service. (**Owner/Admin**)
- `GET /api/organizations/:org_slug/services`: List all services for an organization.
- `GET /api/organizations/:org_slug/services/:service_slug`: Get service details.
- `PATCH /api/organizations/:org_slug/services/:service_slug`: Update service details. (**Owner/Admin**)
- `DELETE /api/organizations/:org_slug/services/:service_slug`: Delete a service. (**Owner only**)
- `POST /api/organizations/:org_slug/services/:service_slug/plans`: Create a subscription plan. (**Owner/Admin**)
- `GET /api/organizations/:org_slug/services/:service_slug/plans`: List all plans for a service.

### 3.6. Invitation Management Endpoints
**Authentication:** Requires a JWT.

- `POST /api/organizations/:org_slug/invitations`: Create an invitation. (**Owner/Admin**)
- `GET /api/organizations/:org_slug/invitations`: List invitations for an organization. (**Owner/Admin**)
- `POST /api/organizations/:org_slug/invitations/:invitation_id`: Cancel a pending invitation. (**Owner/Admin**)
- `GET /api/invitations`: List invitations received by the current user.
- `POST /api/invitations/accept`: Accept an invitation via token.
- `POST /api/invitations/decline`: Decline an invitation via token.

### 3.7. Platform Owner Endpoints
**Authentication:** Requires a **Platform Owner JWT**.

- `GET /api/platform/organizations`: List all organizations on the platform.
- `POST /api/platform/organizations/:id/approve`: Approve a pending organization.
- `POST /api/platform/organizations/:id/reject`: Reject a pending organization.
- `POST /api/platform/organizations/:id/suspend`: Suspend an active organization.
- `POST /api/platform/organizations/:id/activate`: Re-activate a suspended organization.
- `PATCH /api/platform/organizations/:id/tier`: Update an organization's tier.
- `POST /api/platform/owners`: Promote a user to platform owner.
- `DELETE /api/platform/owners/:user_id`: Demote a platform owner.
- `GET /api/platform/audit-log`: Retrieve the platform-wide audit log.
- `GET /api/platform/tiers`: List all available organization tiers.

### 3.8. Platform Analytics Endpoints
**Authentication:** Requires a **Platform Owner JWT**.

- `GET /api/platform/analytics/overview`: Get high-level metrics for the entire platform.
- `GET /api/platform/analytics/organization-status`: Get a breakdown of organization counts by status.
- `GET /api/platform/analytics/growth-trends`: Get daily new user and new organization counts.
- `GET /api/platform/analytics/login-activity`: Get daily platform-wide login counts.
- `GET /api/platform/analytics/top-organizations`: List the most active organizations.
- `GET /api/platform/analytics/recent-organizations`: List the most recently created organizations.

### 3.9. Webhook Endpoints

- `POST /webhooks/stripe`: Endpoint for receiving Stripe webhook events.

---

## 4. Configuration (Environment Variables)

The system is configured entirely through environment variables.

| Variable                          | Required | Description                                                                                    |
| --------------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| **Database**                      |          |                                                                                                |
| `DATABASE_URL`                    | Yes      | Connection string for the SQLite database (e.g., `sqlite:./data/sso.db`).                      |
| **JWT**                           |          |                                                                                                |
| `JWT_PRIVATE_KEY_BASE64`          | Yes      | Base64-encoded RSA private key for signing JWTs.                                               |
| `JWT_PUBLIC_KEY_BASE64`           | Yes      | Base64-encoded RSA public key for verifying JWT signatures.                                    |
| `JWT_KID`                         | Yes      | Unique Key ID for key rotation and JWKS identification.                                        |
| `JWT_EXPIRATION_HOURS`            | No       | JWT lifetime in hours. Defaults to `24`.                                                       |
| **Server**                        |          |                                                                                                |
| `BASE_URL`                        | Yes      | The public base URL of the service (e.g., `http://localhost:3000`).                            |
| `SERVER_HOST` / `SERVER_PORT`     | No       | Host/port to bind to. Defaults to `0.0.0.0:3000`.                                              |
| `PLATFORM_ADMIN_REDIRECT_URI`     | Yes      | The callback URL for the admin frontend application.                                           |
| `PLATFORM_DEVICE_ACTIVATION_URI`  | Yes      | The URL for the platform-level device activation page.                                         |
| **Platform Owner**                |          |                                                                                                |
| `PLATFORM_OWNER_EMAIL`            | Yes      | Email of the user to be automatically designated as the platform owner on startup.             |
| **Default OAuth Apps**            | Yes      | Credentials for the platform's default apps, used when an organization doesn't bring their own.  |
| `GITHUB_CLIENT_ID` / `_SECRET`... | Yes      | ...and so on for Google and Microsoft.                                                         |
| **Platform Admin OAuth Apps**     | Yes      | Credentials for the dedicated OAuth apps used **only for the admin login flow**.               |
| `PLATFORM_GITHUB_CLIENT_ID`...    | Yes      | ...and so on for Google and Microsoft.                                                         |
| **Security**                      |          |                                                                                                |
| `ENCRYPTION_KEY`                  | **Yes**  | **Critical.** 32-byte (64 hex characters) key for encrypting BYOO secrets. If not set, secrets are stored in plaintext. |
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
  - `400 Bad Request` (`BAD_REQUEST`, `DEVICE_CODE_EXPIRED`, `SERVICE_LIMIT_EXCEEDED`, `TEAM_LIMIT_EXCEEDED`, `INVITATION_EXPIRED`)
  - `401 Unauthorized` (`UNAUTHORIZED`, `TOKEN_EXPIRED`, `JWT_ERROR`)
  - `403 Forbidden` (`FORBIDDEN`, `ORGANIZATION_NOT_ACTIVE`)
  - `404 Not Found` (`NOT_FOUND`)
  - `500 Internal Server Error` (`INTERNAL_SERVER_ERROR`, `DATABASE_ERROR`, `OAUTH_ERROR`, `STRIPE_ERROR`)
