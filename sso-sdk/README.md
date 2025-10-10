# SSO Platform SDK

A zero-dependency, strongly-typed TypeScript SDK for interacting with the multi-tenant SSO Platform API.

## Features

- **Zero Dependencies**: Built on native `fetch` API - no external dependencies
- **Framework Agnostic**: Pure TypeScript - works in any JavaScript environment
- **Strongly Typed**: Complete TypeScript definitions for all API endpoints
- **Stateless Design**: No internal state management - integrates with any state solution
- **Predictable Error Handling**: Custom `SsoApiError` class with structured error information
- **Modular & Tree-Shakable**: Import only what you need
- **Comprehensive Documentation**: Full TSDoc comments for excellent IDE support
- **Modern**: Supports Node.js 18+ and all modern browsers

## Installation

```bash
npm install @drmhse/sso-sdk
```

## Quick Start

```typescript
import { SsoClient } from '@drmhse/sso-sdk';

// Initialize the client
const sso = new SsoClient({
  baseURL: 'https://sso.example.com',
  token: localStorage.getItem('jwt') // Optional initial token
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
// Redirect user to OAuth provider
const loginUrl = sso.auth.getLoginUrl('github', {
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback'
});
window.location.href = loginUrl;

// In your callback handler
const token = new URLSearchParams(window.location.search).get('token');
if (token) {
  sso.setAuthToken(token);
  localStorage.setItem('jwt', token);
}
```

### Admin Login

```typescript
const adminUrl = sso.auth.getAdminLoginUrl('github', {
  org_slug: 'acme-corp' // Optional
});
window.location.href = adminUrl;
```

### Device Flow (for CLIs)

```typescript
// Step 1: Request device code
const deviceAuth = await sso.auth.deviceCode.request({
  client_id: 'cli-client-id',
  org: 'acme-corp',
  service: 'acme-cli'
});

console.log(`Visit ${deviceAuth.verification_uri}`);
console.log(`Enter code: ${deviceAuth.user_code}`);

// Step 2: Poll for token
const pollInterval = setInterval(async () => {
  try {
    const token = await sso.auth.deviceCode.exchangeToken({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceAuth.device_code,
      client_id: 'cli-client-id'
    });

    clearInterval(pollInterval);
    sso.setAuthToken(token.access_token);
    console.log('Authenticated!');
  } catch (error) {
    if (error.errorCode !== 'authorization_pending') {
      clearInterval(pollInterval);
      throw error;
    }
  }
}, deviceAuth.interval * 1000);
```

### Logout

```typescript
await sso.auth.logout();
sso.setAuthToken(null);
localStorage.removeItem('jwt');
```

## API Reference

### Analytics

The analytics module provides login tracking and metrics for organizations.

```typescript
// Get login trends over time
const trends = await sso.analytics.getLoginTrends('acme-corp', {
  start_date: '2025-01-01',
  end_date: '2025-01-31'
});

// Get logins grouped by service
const byService = await sso.analytics.getLoginsByService('acme-corp');

// Get logins grouped by OAuth provider
const byProvider = await sso.analytics.getLoginsByProvider('acme-corp');

// Get recent login events
const recent = await sso.analytics.getRecentLogins('acme-corp', {
  limit: 10
});
```

### Organizations

```typescript
// Create organization (public endpoint)
const org = await sso.organizations.createPublic({
  slug: 'acme-corp',
  name: 'Acme Corporation',
  owner_email: 'founder@acme.com'
});

// List user's organizations
const orgs = await sso.organizations.list({ status: 'active' });

// Get organization details
const details = await sso.organizations.get('acme-corp');

// Update organization
await sso.organizations.update('acme-corp', {
  name: 'Acme Corp Inc.'
});

// Manage members
const members = await sso.organizations.members.list('acme-corp');
await sso.organizations.members.updateRole('acme-corp', 'user-id', {
  role: 'admin'
});
await sso.organizations.members.remove('acme-corp', 'user-id');

// BYOO: Set custom OAuth credentials
await sso.organizations.oauthCredentials.set('acme-corp', 'github', {
  client_id: 'Iv1.abc123',
  client_secret: 'secret-value'
});

// Get configured OAuth credentials
const creds = await sso.organizations.oauthCredentials.get('acme-corp', 'github');
```

### End-User Management

Manage your organization's customers (end-users with subscriptions).

```typescript
// List all end-users for an organization
const endUsers = await sso.organizations.endUsers.list('acme-corp', {
  page: 1,
  limit: 20
});

// Get detailed information about a specific end-user
const endUser = await sso.organizations.endUsers.get('acme-corp', 'user-id');

// Revoke all active sessions for an end-user
const result = await sso.organizations.endUsers.revokeSessions('acme-corp', 'user-id');
```

### Services

```typescript
// Create service (returns service with provider grants and default plan)
const result = await sso.services.create('acme-corp', {
  slug: 'main-app',
  name: 'Main Application',
  service_type: 'web',
  github_scopes: ['user:email', 'read:org'],
  microsoft_scopes: ['User.Read', 'email'],
  google_scopes: ['openid', 'email', 'profile'],
  redirect_uris: ['https://app.acme.com/callback']
});
console.log(result.service.client_id);
console.log(result.usage.current_services);

// List services (returns services with usage metadata)
const result = await sso.services.list('acme-corp');
console.log(`Using ${result.usage.current_services} of ${result.usage.max_services} services`);
result.services.forEach(svc => console.log(svc.name, svc.client_id));

// Get service details (includes provider grants and plans)
const service = await sso.services.get('acme-corp', 'main-app');
console.log(service.service.redirect_uris);
console.log(service.plans);

// Update service
const updated = await sso.services.update('acme-corp', 'main-app', {
  name: 'Main Application v2',
  github_scopes: ['user:email', 'read:org', 'repo'],
  microsoft_scopes: ['User.Read', 'email', 'Mail.Read'],
  google_scopes: ['openid', 'email', 'profile', 'drive.readonly'],
  redirect_uris: ['https://app.acme.com/callback', 'https://app.acme.com/oauth']
});

// Delete service
await sso.services.delete('acme-corp', 'old-service');

// Manage plans
const plan = await sso.services.plans.create('acme-corp', 'main-app', {
  name: 'pro',
  description: 'Pro tier with advanced features',
  price_monthly: 29.99,
  features: ['api-access', 'advanced-analytics', 'priority-support']
});

// List all plans for a service
const plans = await sso.services.plans.list('acme-corp', 'main-app');
plans.forEach(plan => console.log(plan.name, plan.price_monthly));
```

### Invitations

```typescript
// Send invitation
const invitation = await sso.invitations.create('acme-corp', {
  invitee_email: 'newuser@example.com',
  role: 'member'
});

// List organization's invitations
const orgInvites = await sso.invitations.listForOrg('acme-corp');

// List user's invitations
const myInvites = await sso.invitations.listForUser();

// Accept invitation
await sso.invitations.accept('invitation-token');

// Decline invitation
await sso.invitations.decline('invitation-token');

// Cancel invitation
await sso.invitations.cancel('acme-corp', 'invitation-id');
```

### User Profile

```typescript
// Get profile
const profile = await sso.user.getProfile();

// Update profile
await sso.user.updateProfile({ email: 'newemail@example.com' });

// Get subscription
const subscription = await sso.user.getSubscription();
```

### Social Account Identities

Manage linked social accounts for the authenticated user.

```typescript
// List all linked social accounts
const identities = await sso.user.identities.list();

// Start linking a new social account
const { authorization_url } = await sso.user.identities.startLink('github');
window.location.href = authorization_url;

// Unlink a social account
await sso.user.identities.unlink('google');
```

### Provider Tokens

```typescript
// Get fresh OAuth token for external provider
const githubToken = await sso.auth.getProviderToken('github');
// Use githubToken.access_token to make GitHub API calls
```

### Platform Administration

Platform owner methods require a Platform Owner JWT.

```typescript
// List all organizations
const allOrgs = await sso.platform.organizations.list({
  status: 'pending',
  page: 1,
  limit: 50
});

// Approve organization
await sso.platform.organizations.approve('org-id', {
  tier_id: 'tier-starter'
});

// Reject organization
await sso.platform.organizations.reject('org-id', {
  reason: 'Does not meet requirements'
});

// Suspend/activate
await sso.platform.organizations.suspend('org-id');
await sso.platform.organizations.activate('org-id');

// Update tier
await sso.platform.organizations.updateTier('org-id', {
  tier_id: 'tier-pro',
  max_services: 20
});

// Promote platform owner
await sso.platform.promoteOwner({
  user_id: 'user-uuid-here'
});

// Demote platform owner to regular user
await sso.platform.demoteOwner('user-uuid-here');

// List available organization tiers
const tiers = await sso.platform.getTiers();

// Get audit log
const logs = await sso.platform.getAuditLog({
  action: 'organization.approved',
  limit: 100
});
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
    console.error(`Timestamp: ${error.timestamp}`);

    // Utility methods
    if (error.isAuthError()) {
      // Redirect to login
    }
    if (error.isNotFound()) {
      // Show 404 page
    }
    if (error.is('SERVICE_LIMIT_EXCEEDED')) {
      // Handle specific error
    }
    if (error.isForbidden()) {
      // Handle permission errors
    }
    if (error.isAuthError()) {
      // Handle authentication errors
    }
  }
}
```

## Framework Integration Examples

### Vue 3 + Pinia

```typescript
// stores/auth.ts
import { defineStore } from 'pinia';
import { SsoClient } from '@drmhse/sso-sdk';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('jwt'),
    user: null
  }),

  actions: {
    async login(token: string) {
      this.token = token;
      localStorage.setItem('jwt', token);
      sso.setAuthToken(token);
      await this.fetchUser();
    },

    async logout() {
      await sso.auth.logout();
      this.token = null;
      this.user = null;
      localStorage.removeItem('jwt');
      sso.setAuthToken(null);
    },

    async fetchUser() {
      this.user = await sso.user.getProfile();
    }
  }
});

// Global SSO instance
export const sso = new SsoClient({
  baseURL: import.meta.env.VITE_SSO_URL,
  token: localStorage.getItem('jwt')
});
```

### React + Context

```typescript
// SsoContext.tsx
import { createContext, useContext } from 'react';
import { SsoClient } from '@drmhse/sso-sdk';

const sso = new SsoClient({
  baseURL: process.env.REACT_APP_SSO_URL,
  token: localStorage.getItem('jwt')
});

const SsoContext = createContext(sso);

export const useSso = () => useContext(SsoContext);

export const SsoProvider = ({ children }) => (
  <SsoContext.Provider value={sso}>
    {children}
  </SsoContext.Provider>
);
```

## TypeScript

The SDK is written in TypeScript and includes complete type definitions. All types are exported:

```typescript
import type {
  Organization,
  Service,
  User,
  JwtClaims,
  OAuthProvider,
  SsoClientOptions,
  SsoApiError,
  AnalyticsQuery,
  LoginTrendPoint,
  LoginsByService,
  LoginsByProvider,
  RecentLogin,
  Invitation,
  Subscription,
  ProviderToken,
  UserProfile,
  PlatformOrganizationResponse,
  AuditLogEntry,
  // ... and many more types
} from '@drmhse/sso-sdk';
```

All API responses, request payloads, and configuration options are fully typed for excellent IDE support and compile-time safety.

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or pull request.
