# [AuthOS](https://authos.dev) SDK

[![npm version](https://img.shields.io/npm/v/@drmhse/sso-sdk)](https://www.npmjs.com/package/@drmhse/sso-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A zero-dependency, strongly-typed TypeScript SDK for [AuthOS](https://authos.dev), the multi-tenant authentication platform.

**[View Full Documentation →](https://drmhse.com/docs/sso/)**

## Features

- **Zero Dependencies** - Built on native `fetch` API
- **Strongly Typed** - Complete TypeScript definitions
- **Framework Agnostic** - Works in any JavaScript environment
- **Automatic Session Management** - Invisible token persistence and auto-refresh
- **Smart Token Handling** - Auto-inject tokens and handle 401 errors transparently
- **OAuth 2.0 Flows** - Support for GitHub, Google, Microsoft
- **Password Authentication** - Native email/password auth with MFA
- **Device Flow** - RFC 8628 for CLIs and headless apps
- **Multi-Factor Authentication** - TOTP-based 2FA with backup codes
- **Organization Management** - Multi-tenant with RBAC
- **Analytics & Audit Logs** - Track authentication and administrative actions
- **SAML 2.0** - Act as Identity Provider

## Installation

```bash
npm install @drmhse/sso-sdk
```

## Quick Start

```typescript
import { SsoClient } from '@drmhse/sso-sdk';

// Initialize the client - automatically loads tokens from localStorage
const sso = new SsoClient({
  baseURL: 'https://sso.example.com'
});

// Login - session is automatically saved
await sso.auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});

// Make authenticated requests - tokens auto-injected and auto-refreshed
const profile = await sso.user.getProfile();
console.log(profile.email);

const orgs = await sso.organizations.list();
console.log(orgs);
```

**New to the SDK?** Start with the **[Getting Started Guide →](https://drmhse.com/docs/sso/sdk/getting-started)** for a step-by-step tutorial showing how to authenticate users from scratch, handle token refresh, and implement logout.

**Essential Guides:**
- **[Authentication Flows](https://drmhse.com/docs/sso/sdk/guides/authentication-flows)** - OAuth, Device Flow, and Admin Login patterns
- **[Password Authentication](https://drmhse.com/docs/sso/sdk/guides/password-authentication)** - Registration, login, and password reset
- **[MFA Management](https://drmhse.com/docs/sso/sdk/guides/mfa-management)** - TOTP-based 2FA implementation
- **[Error Handling](https://drmhse.com/docs/sso/sdk/guides/error-handling)** - Best practices for handling API errors

## Authentication Examples

### OAuth Login

```typescript
// Redirect to OAuth provider
const loginUrl = sso.auth.getLoginUrl('github', {
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback'
});
window.location.href = loginUrl;

// Handle callback - initialize client with token from OAuth callback
const params = new URLSearchParams(window.location.search);
const accessToken = params.get('access_token');

if (accessToken) {
  // Initialize SDK with OAuth token - automatically stored
  const sso = new SsoClient({
    baseURL: 'https://sso.example.com',
    token: accessToken
  });
  // Token is now automatically stored and managed
  window.location.href = '/dashboard';
}
```

### Password Authentication

```typescript
// Register new user
await sso.auth.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  org_slug: 'acme-corp'
});

// Login with password - session automatically saved
await sso.auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});
// Tokens are now automatically stored and injected on all requests

// Enable MFA
const mfaSetup = await sso.user.mfa.setup();
console.log(mfaSetup.qr_code_svg); // Display QR code to user

// Verify and enable - automatically saves backup codes
const result = await sso.user.mfa.verify('123456'); // TOTP code from authenticator app
console.log('Backup codes:', result.backup_codes); // Save these securely!
```

### Device Flow (for CLIs)

```typescript
// In your CLI application
const deviceAuth = await sso.auth.deviceCode.request({
  client_id: 'cli-client',
  org: 'acme-corp',
  service: 'cli-tool'
});

console.log(`Visit: ${deviceAuth.verification_uri}`);
console.log(`Enter code: ${deviceAuth.user_code}`);

// Poll for token
const interval = setInterval(async () => {
  try {
    const tokens = await sso.auth.deviceCode.exchangeToken({
      device_code: deviceAuth.device_code,
      client_id: 'cli-client',
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
    });

    // Initialize SDK with the token - automatically stored
    const authenticatedSso = new SsoClient({
      baseURL: 'https://sso.example.com',
      token: tokens.access_token
    });

    clearInterval(interval);
    console.log('Authentication successful!');
  } catch (error) {
    // Continue polling...
  }
}, deviceAuth.interval * 1000);
```

### Token Refresh

**Automatic Token Refresh** - The SDK automatically refreshes expired tokens when it detects a 401 error:

```typescript
// No manual refresh needed! Just make your API calls
try {
  // If the access token is expired, the SDK will:
  // 1. Detect the 401 error
  // 2. Use the refresh token to get new tokens
  // 3. Retry the request automatically
  // 4. Return the result - you never see the 401!
  const profile = await sso.user.getProfile();
  console.log(profile);
} catch (error) {
  // You'll only see errors if refresh fails (e.g., refresh token expired)
  console.error('Session expired - please log in again');
  // Redirect to login
}

// Optional: Manually refresh if needed (advanced use case)
const currentRefreshToken = await sso.getToken();
if (currentRefreshToken) {
  const tokens = await sso.auth.refreshToken(currentRefreshToken);
  // Tokens automatically updated
}
```

## Organization Management

```typescript
// Create organization
const org = await sso.organizations.createPublic({
  name: 'Acme Corp',
  slug: 'acme-corp'
});

// Configure custom OAuth (BYOO - Bring Your Own OAuth)
await sso.organizations.oauthCredentials.set('acme-corp', 'github', {
  client_id: 'your-github-client-id',
  client_secret: 'your-github-client-secret'
});

// Invite team members
await sso.organizations.invitations.create('acme-corp', {
  email: 'member@acme.com',
  role: 'admin'
});

// Configure SMTP for transactional emails
await sso.organizations.setSmtp('acme-corp', {
  host: 'smtp.gmail.com',
  port: 587,
  username: 'noreply@acme.com',
  password: 'app-password',
  from_email: 'noreply@acme.com',
  from_name: 'Acme Corp'
});
```

## Subscription & Billing

The SDK provides provider-agnostic billing integration that works with both Stripe and Polar.

```typescript
// Check billing status
const billingInfo = await sso.organizations.billing.getInfo('acme-corp');
console.log(billingInfo.has_billing_account); // true/false
console.log(billingInfo.provider); // "stripe" or "polar"

// Open billing portal for subscription management
const portal = await sso.organizations.billing.createPortalSession('acme-corp', {
  return_url: 'https://app.acme.com/settings/billing'
});
// Redirect user to manage their subscription
window.location.href = portal.url;
```

### BYOP - Bring Your Own Payment

Organizations can configure their own billing provider credentials to charge their end-users:

```typescript
// Configure organization's own Stripe credentials
await sso.organizations.billingCredentials.set('acme-corp', 'stripe', {
  api_key: 'sk_live_...',
  webhook_secret: 'whsec_...',
  mode: 'live' // or 'test'
});

// Check credential status
const status = await sso.organizations.billingCredentials.get('acme-corp', 'stripe');
console.log(status.configured); // true
console.log(status.mode); // "live"

// Remove credentials
await sso.organizations.billingCredentials.delete('acme-corp', 'stripe');
```

## Services & API Keys

```typescript
// Create a service
const service = await sso.services.create('acme-corp', {
  name: 'Main Application',
  slug: 'main-app',
  redirect_uris: ['https://app.acme.com/callback']
});

// Create API key for service-to-service auth
const apiKey = await sso.services.apiKeys.create('acme-corp', 'main-app', {
  name: 'Production Backend',
  expires_at: '2026-01-01T00:00:00Z'
});

console.log('API Key (save this):', apiKey.key);

// Use API key for backend authentication
const backendClient = new SsoClient({
  baseURL: 'https://sso.example.com',
  apiKey: apiKey.key
});
```

## Analytics

```typescript
// Get login trends
const trends = await sso.analytics.getLoginTrends('acme-corp', {
  start_date: '2025-01-01',
  end_date: '2025-01-31'
});

// Get provider distribution
const byProvider = await sso.analytics.getLoginsByProvider('acme-corp');
console.log(byProvider); // [{ provider: 'github', count: 1523 }, ...]

// Get recent activity
const recentLogins = await sso.analytics.getRecentLogins('acme-corp', {
  limit: 20
});
```

## Error Handling

```typescript
import { SsoClient, SsoApiError } from '@drmhse/sso-sdk';

try {
  await sso.user.getProfile();
} catch (error) {
  if (error instanceof SsoApiError) {
    console.error(`API Error: ${error.message}`);
    console.error(`Status: ${error.status}`);
    console.error(`Code: ${error.errorCode}`);

    if (error.status === 401) {
      // Session expired (refresh token also expired)
      // Automatic refresh already tried and failed
      // Redirect to login
      window.location.href = '/login';
    } else if (error.status === 403) {
      // Forbidden - insufficient permissions
      console.error('You do not have permission to access this resource');
    }
  } else {
    console.error('Unexpected error:', error);
  }
}

// React to authentication state changes
sso.onAuthStateChange((isAuthenticated) => {
  if (!isAuthenticated) {
    // User logged out or session expired
    window.location.href = '/login';
  }
});
```

## Platform Administration

For platform owners managing [AuthOS](https://authos.dev):

```typescript
// Approve pending organization
await sso.platform.organizations.approve('org-id', {
  tier: 'professional',
  reason: 'Verified enterprise customer'
});

// Promote user to platform owner
await sso.platform.promoteOwner({
  email: 'admin@example.com'
});

// Get platform analytics
const overview = await sso.platform.analytics.getOverview();
console.log(overview); // { total_users, total_orgs, total_logins, ... }

// Search users across all organizations
const users = await sso.platform.users.search('user@example.com');
```

## TypeScript Support

The SDK is written in TypeScript and includes complete type definitions:

```typescript
import type {
  User,
  Organization,
  Service,
  LoginTrendPoint,
  RefreshTokenResponse,
  CreateServicePayload,
  UpdateServicePayload,
  LoginPayload,
  RegisterPayload,
  SsoApiError
} from '@drmhse/sso-sdk';

// Example using types
const createService = async (payload: CreateServicePayload): Promise<Service> => {
  return await sso.services.create('org-slug', payload);
};

const login = async (credentials: LoginPayload): Promise<RefreshTokenResponse> => {
  return await sso.auth.login(credentials);
};
```

## Validating JWTs in Your Backend

[AuthOS](https://authos.dev) uses RS256 (asymmetric) JWT signing. Your backend can validate tokens without sharing secrets:

```typescript
// Fetch JWKS from the SSO platform
const jwksUrl = 'https://sso.example.com/.well-known/jwks.json';
const response = await fetch(jwksUrl);
const jwks = await response.json();

// Use a JWT library to verify tokens
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({ jwksUri: jwksUrl });
const key = await client.getSigningKey(header.kid);
const publicKey = key.getPublicKey();

const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']
});
```

**[See Backend Validation Guide →](https://drmhse.com/docs/sso/api/concepts/token-validation)**

## Documentation

**[Complete documentation is available at drmhse.com/docs/sso](https://drmhse.com/docs/sso/)**

### Key Documentation Pages

- **[Getting Started](https://drmhse.com/docs/sso/sdk/getting-started)** - Installation and setup
- **[Authentication Flows](https://drmhse.com/docs/sso/sdk/guides/authentication-flows)** - OAuth, Device Flow, Admin Login
- **[Password Authentication](https://drmhse.com/docs/sso/sdk/guides/password-authentication)** - Register, Login, Reset Password
- **[MFA Management](https://drmhse.com/docs/sso/sdk/guides/mfa-management)** - TOTP setup and verification
- **[SDK Reference](https://drmhse.com/docs/sso/sdk/reference)** - Complete API reference
- **[API Reference](https://drmhse.com/docs/sso/api/reference)** - Backend API documentation

## Requirements

- **Node.js:** 18+ (for native fetch support)
- **Browsers:** All modern browsers with fetch support
- **TypeScript:** 4.5+ (optional, but recommended)

## License

MIT © [DRM HSE](https://github.com/drmhse)

## Support

- **Documentation:** [drmhse.com/docs/sso](https://drmhse.com/docs/sso/)
- **Issues:** [GitHub Issues](https://github.com/drmhse/sso/issues)
- **Email:** [info@drmhse.com](mailto:info@drmhse.com)
