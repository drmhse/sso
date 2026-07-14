# @drmhse/sso-sdk

[![npm version](https://img.shields.io/npm/v/@drmhse/sso-sdk)](https://www.npmjs.com/package/@drmhse/sso-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Core TypeScript SDK for AuthOS. It handles authentication flows, session persistence, token refresh, and the multi-tenant API surface used by the framework adapters.

This package is pre-1.0 and Beta. Pin an exact version and review the
[current AuthOS support matrix](https://github.com/drmhse/AuthOS/blob/main/PROJECT_STATUS.md).

Full documentation: [authos.dev/docs/sdk/](https://authos.dev/docs/sdk/)

AI agent skills: [authos.dev/docs/ai-agent-skills/](https://authos.dev/docs/ai-agent-skills/) and [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)

## Install

```bash
npm install @drmhse/sso-sdk
```

## Quick start

```ts
import { SsoClient } from '@drmhse/sso-sdk';

const sso = new SsoClient({
  baseURL: 'https://sso.example.com',
});

await sso.auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!',
  org_slug: 'acme-corp',
  service_slug: 'main-app',
});

const profile = await sso.user.getProfile();
console.log(profile.email);
```

## Common usage modes

### Platform administration

Use only `baseURL` when acting as a platform owner or admin tool:

```ts
const sso = new SsoClient({ baseURL: 'https://sso.example.com' });
```

### Tenant application

Redirect users to AuthOS hosted login for the standard web flow. AuthOS handles provider selection, HRD, password, magic link, passkeys, MFA, and recovery before returning tokens to your callback:

```ts
const loginUrl = sso.auth.getAuthorizeUrl({
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback',
});
```

Use `getLoginUrl(provider, ...)` only when you are intentionally building a custom provider-selection flow.

### Account security

Send users to the hosted account-security portal to manage MFA, passkeys, backup codes, and trusted devices on the AuthOS origin:

```ts
const securityUrl = sso.auth.getAccountSecurityUrl({
  org: 'acme-corp',
  service: 'main-app',
  return_to: 'https://app.acme.com/settings',
});
```

### Hosted auth context

```ts
const context = await sso.auth.getContext({
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback',
});
```

### Provider token handoff

```ts
const result = await sso.serviceApi.requestProviderToken({
  user_id: 'user-id',
  provider: 'github',
  scopes: ['repo'],
});
```

### Enterprise-managed authorization

For MCP and Cross-App Access style flows, exchange a service-scoped AuthOS JWT
for an ID-JAG, then redeem it for a resource-scoped bearer token:

```ts
const idJag = await sso.auth.enterprise.requestIdJag({
  client_id: 'service-client-id',
  audience: 'https://auth.example.com',
  resource: 'https://api.example.com/mcp',
  subject_token: serviceAccessToken,
});

const resourceToken = await sso.auth.enterprise.exchangeIdJag({
  client_id: 'service-client-id',
  client_secret: process.env.AUTHOS_SERVICE_CLIENT_SECRET!,
  assertion: idJag.access_token,
});
```

## Feature highlights

- Password, OAuth, magic-link, passkey, MFA, and device-flow authentication
- Hosted auth context for login surfaces
- Linked accounts and provider-token request completion flows
- Organization, service, analytics, audit-log, and platform-owner APIs
- Service API helpers including backend-only provider token retrieval
- Enterprise-managed authorization helpers for ID-JAG resource access

## Canonical references

- SDK getting started: [authos.dev/docs/sdk/getting-started/](https://authos.dev/docs/sdk/getting-started/)
- SDK reference: [authos.dev/docs/sdk/reference/](https://authos.dev/docs/sdk/reference/)
- API reference: [authos.dev/docs/api/reference/](https://authos.dev/docs/api/reference/)
