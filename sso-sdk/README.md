# @drmhse/sso-sdk

[![npm version](https://img.shields.io/npm/v/@drmhse/sso-sdk)](https://www.npmjs.com/package/@drmhse/sso-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Core TypeScript SDK for AuthOS. It handles authentication flows, session persistence, token refresh, and the multi-tenant API surface used by the framework adapters.

Full documentation: [authos.dev/docs/sdk/](https://authos.dev/docs/sdk/)

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

Pass organization and service context when you need hosted auth, BYOO, or service-scoped tokens:

```ts
const loginUrl = sso.auth.getLoginUrl('github', {
  org: 'acme-corp',
  service: 'main-app',
  redirect_uri: 'https://app.acme.com/callback',
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

## Feature highlights

- Password, OAuth, magic-link, passkey, MFA, and device-flow authentication
- Hosted auth context for login surfaces
- Linked accounts and provider-token request completion flows
- Organization, service, analytics, audit-log, and platform-owner APIs
- Service API helpers including backend-only provider token retrieval

## Canonical references

- SDK getting started: [authos.dev/docs/sdk/getting-started/](https://authos.dev/docs/sdk/getting-started/)
- SDK reference: [authos.dev/docs/sdk/reference/](https://authos.dev/docs/sdk/reference/)
- API reference: [authos.dev/docs/api/reference/](https://authos.dev/docs/api/reference/)
