# SSO Platform SDK

A zero-dependency, strongly-typed TypeScript SDK for interacting with the multi-tenant SSO Platform API.

## Features

-   **Zero Dependencies**: Built on native `fetch` API - no external dependencies.
-   **Framework Agnostic**: Pure TypeScript - works in any JavaScript environment.
-   **Strongly Typed**: Complete TypeScript definitions for all API endpoints.
-   **Stateless Design**: No internal state management - integrates with any state solution.
-   **Predictable Error Handling**: Custom `SsoApiError` class with structured error information.
-   **Modern**: Supports Node.js 18+ and all modern browsers.

## Installation

```bash
npm install @drmhse/sso-sdk
```

## Quick Start

```typescript
import { SsoClient, SsoApiError } from '@drmhse/sso-sdk';

// Initialize the client
const sso = new SsoClient({
  baseURL: 'https://sso.example.com',
  token: localStorage.getItem('sso_token') // Optional initial token
});

// Use the SDK
async function example() {
  try {
    // Get user profile
    const profile = await sso.user.getProfile();
    console.log(profile.email);

    // List organizations
    const orgs = await sso.organizations.list();
    console.log(orgs);
  } catch (error) {
    if (error instanceof SsoApiError) {
      console.error(`API Error: ${error.message} (${error.errorCode})`);
    }
  }
}
```

## Authentication Flows

### End-User OAuth Login

```typescript
// 1. Redirect user to OAuth provider
const loginUrl = sso.auth.getLoginUrl('github', {
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback'
});
window.location.href = loginUrl;

// 2. In your callback handler, extract both tokens from the URL
const params = new URLSearchParams(window.location.search);
const accessToken = params.get('access_token');
const refreshToken = params.get('refresh_token');

if (accessToken && refreshToken) {
  sso.setAuthToken(accessToken);
  localStorage.setItem('sso_token', accessToken);
  localStorage.setItem('sso_refresh_token', refreshToken);
}
```

### Admin Login

```typescript
const adminUrl = sso.auth.getAdminLoginUrl('github', {
  org_slug: 'acme-corp' // Optional: directs user to a specific org dashboard after login
});
window.location.href = adminUrl;
```

### Device Flow (for CLIs)

This flow involves both the CLI and a web browser.

```typescript
// --- In your CLI Application ---

// 1. Request device code
const deviceAuth = await sso.auth.deviceCode.request({
  client_id: 'cli-client-id',
  org: 'acme-corp',
  service: 'acme-cli'
});

console.log(`Visit: ${deviceAuth.verification_uri}`);
console.log(`Enter code: ${deviceAuth.user_code}`);

// 4. Poll for the token
const pollForToken = async () => {
  // Polling logic...
};
pollForToken();


// --- In your Web Application at /activate ---

// 2. After user enters the code, verify it to get context
const context = await sso.auth.deviceCode.verify(userEnteredCode);

// 3. Redirect user to the appropriate login flow, passing the user_code
// This links the browser session to the device waiting for authorization.
const loginUrl = sso.auth.getLoginUrl('github', { 
  org: context.org_slug,
  service: context.service_slug,
  user_code: userEnteredCode, // CRITICAL: Pass user_code here
});
window.location.href = loginUrl; // User logs in, authorizing the device
```

### Refreshing Tokens

Renew an expired access token using a refresh token. This uses token rotation for enhanced security.

```typescript
try {
  const tokens = await sso.auth.refreshToken(storedRefreshToken);
  
  // Update tokens in your application state and storage
  sso.setAuthToken(tokens.access_token);
  localStorage.setItem('sso_token', tokens.access_token);
  localStorage.setItem('sso_refresh_token', tokens.refresh_token);
} catch (error) {
  // Refresh failed, user needs to log in again
  console.error("Token refresh failed:", error);
}
```

### Logout

```typescript
await sso.auth.logout();
sso.setAuthToken(null);
localStorage.removeItem('sso_token');
localStorage.removeItem('sso_refresh_token');
```

## API Reference

### Analytics (`sso.analytics`)

Provides login tracking and metrics for a specific organization.

```typescript
// Get login trends over time
const trends = await sso.analytics.getLoginTrends('acme-corp', {
  start_date: '2025-01-01',
  end_date: '2025-01-31'
});
```

### Authentication (`sso.auth`)

Handles all authentication flows, including OAuth, device flow, and token management.

```typescript
// Get a fresh OAuth token for an external provider (e.g., GitHub)
const githubToken = await sso.auth.getProviderToken('github');
// Use githubToken.access_token to make GitHub API calls
```

### Organizations (`sso.organizations`)

Manages organizations, members, and BYOO credentials.

```typescript
// Create organization (public endpoint)
const org = await sso.organizations.createPublic({
  slug: 'acme-corp',
  name: 'Acme Corporation',
  owner_email: 'founder@acme.com'
});

// BYOO: Set custom OAuth credentials
await sso.organizations.oauthCredentials.set('acme-corp', 'github', {
  client_id: 'Iv1.abc123',
  client_secret: 'secret-value'
});
```

#### End-User Management (`sso.organizations.endUsers`)

Manage your organization's customers (end-users with subscriptions).

```typescript
// List all end-users for an organization
const endUsers = await sso.organizations.endUsers.list('acme-corp', {
  page: 1,
  limit: 20
});

// Revoke all active sessions for a specific end-user
await sso.organizations.endUsers.revokeSessions('acme-corp', 'user-id-123');
```

### Services & Plans (`sso.services`)

Manages the applications (services) and subscription plans for an organization.

```typescript
// Create a service
const result = await sso.services.create('acme-corp', {
  slug: 'main-app',
  name: 'Main Application',
  service_type: 'web',
  redirect_uris: ['https://app.acme.com/callback']
});

// Create a subscription plan for that service
await sso.services.plans.create('acme-corp', 'main-app', {
  name: 'pro',
  price_cents: 2999, // Note: price is in cents
  currency: 'usd',
  features: ['api-access', 'priority-support']
});
```

### User Profile & Identities (`sso.user`)

Manages the authenticated user's own profile and linked social accounts.

```typescript
// Get profile
const profile = await sso.user.getProfile();

// Start linking a new social account
const { authorization_url } = await sso.user.identities.startLink('google');
window.location.href = authorization_url;

// Unlink a social account
await sso.user.identities.unlink('github');
```

### Invitations (`sso.invitations`)

Manages team invitations for an organization.

```typescript
// Create and send an invitation
await sso.invitations.create('acme-corp', {
  email: 'new-dev@example.com',
  role: 'member'
});

// List invitations for the current user
const myInvites = await sso.invitations.listForUser();
```

### Platform Administration (`sso.platform`)

Platform owner methods require a Platform Owner JWT.

```typescript
// List all organizations awaiting approval
const pendingOrgs = await sso.platform.organizations.list({
  status: 'pending'
});

// Approve an organization
await sso.platform.organizations.approve('org-id-123', {
  tier_id: 'tier-starter'
});
```

#### Platform Analytics (`sso.platform.analytics`)

Provides platform-wide metrics for platform owners.

```typescript
// Get platform-wide analytics overview
const overview = await sso.platform.analytics.getOverview();
console.log(`Total Users: ${overview.total_users}`);
```

## Error Handling

The SDK throws `SsoApiError` for all API errors:

```typescript
import { SsoApiError } from '@drmhse/sso-sdk';

try {
  await sso.organizations.get('non-existent');
} catch (error) {
  if (error instanceof SsoApiError) {
    console.error(`Error ${error.statusCode}: ${error.message}`);
    console.error(`Code: ${error.errorCode}`);

    if (error.isAuthError()) {
      // Redirect to login
    }
  }
}
```

## TypeScript

The SDK is written in TypeScript and includes complete type definitions.

```typescript
import type {
  Organization,
  Service,
  User,
  JwtClaims,
  SsoApiError,
  // ... and many more types
} from '@drmhse/sso-sdk';
```

## License

MIT
