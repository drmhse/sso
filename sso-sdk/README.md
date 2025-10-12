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

## Validating Tokens in Your Backend

The SSO platform uses **RS256** (RSA with SHA-256) asymmetric signing for JWTs. This means your backend services can validate JWT signatures without needing access to any shared secrets.

### How It Works

1. **Fetch the JWKS**: The SSO platform exposes a public JWKS (JSON Web Key Set) endpoint at `/.well-known/jwks.json` containing the public RSA key(s).
2. **Cache the Keys**: Fetch and cache the JWKS in your backend to avoid repeated requests.
3. **Verify Tokens**: When a client sends a JWT, extract the `kid` (Key ID) from the token header, find the matching key in your cached JWKS, and verify the signature.
4. **Validate Claims**: After signature verification, validate token claims like `exp` (expiration), `iss` (issuer), and `aud` (audience).

### Node.js/Express Example

Here's a complete example of JWT validation middleware:

```typescript
import { expressjwt } from 'express-jwt';
import jwksRsa from 'jwks-rsa';

// Configure JWKS client to fetch public keys
const jwksClient = jwksRsa({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: 'https://sso.example.com/.well-known/jwks.json'
});

// Function to get signing key from JWKS
function getKey(header, callback) {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// JWT validation middleware
const requireAuth = expressjwt({
  secret: getKey,
  algorithms: ['RS256'],
  credentialsRequired: true,
  getToken: (req) => {
    if (req.headers.authorization?.startsWith('Bearer ')) {
      return req.headers.authorization.substring(7);
    }
    return null;
  }
});

// Use in your routes
app.get('/api/protected', requireAuth, (req, res) => {
  // req.auth contains the decoded JWT claims
  const { sub, email, org, service } = req.auth;
  res.json({ message: `Hello ${email}` });
});
```

### Manual Validation (Node.js)

If you prefer to validate manually without middleware:

```typescript
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';

const jwksClient = jwksRsa({
  jwksUri: 'https://sso.example.com/.well-known/jwks.json'
});

async function validateToken(token: string) {
  try {
    // Decode without verifying to get the kid
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header.kid) {
      throw new Error('Invalid token: missing kid');
    }

    // Get the public key for this kid
    const key = await jwksClient.getSigningKey(decoded.header.kid);
    const publicKey = key.getPublicKey();

    // Verify and decode the token
    const verified = jwt.verify(token, publicKey, {
      algorithms: ['RS256']
    });

    return verified; // Returns the decoded claims
  } catch (error) {
    console.error('Token validation failed:', error);
    throw error;
  }
}

// Usage
const claims = await validateToken(req.headers.authorization.split(' ')[1]);
console.log(claims.email, claims.org, claims.service);
```

### Other Languages

The same approach works in any language:

- **Python**: Use `PyJWT` with `python-jose` or `jwcrypto`
- **Go**: Use `golang-jwt/jwt` with JWKS support
- **Java**: Use `java-jwt` or Spring Security with JWKS
- **Ruby**: Use `jwt` gem with `jwks-ruby`

The key steps are always the same:
1. Fetch JWKS from `/.well-known/jwks.json`
2. Extract `kid` from JWT header
3. Find matching key in JWKS
4. Verify signature using the public key
5. Validate token claims (especially `exp`)

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
