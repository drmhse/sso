# @drmhse/authos-node

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-node)](https://www.npmjs.com/package/@drmhse/authos-node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Node.js server adapter for [AuthOS](https://authos.dev) - the multi-tenant authentication platform. Provides JWT verification, webhook signature validation, and Express middleware.

## Installation

```bash
npm install @drmhse/authos-node
```

For Express middleware:
```bash
npm install @drmhse/authos-node express
```

## Quick Start

### JWT Token Verification

Verify JWT tokens issued by AuthOS:

```ts
import { createTokenVerifier } from '@drmhse/authos-node';

const verifier = createTokenVerifier({
  baseURL: 'https://sso.example.com'
});

// Verify a token
const verified = await verifier.verifyToken(token);

console.log(verified.claims);
// {
//   sub: 'user_123',
//   email: 'user@example.com',
//   is_platform_owner: false,
//   org: 'acme-corp',
//   permissions: ['users:read', 'users:write']
// }
```

### TypeScript Integration

To get type support for `req.auth` in Express, you can extend the Request interface or use our utility type:

```ts
import { Request } from 'express';
import { TokenClaims } from '@drmhse/authos-node';

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      auth?: {
        claims: TokenClaims;
        token: string;
      };
    }
  }
}
```

### Express Middleware

Protect your Express routes with AuthOS authentication:

```ts
import { createAuthMiddleware } from '@drmhse/authos-node/express';
import express from 'express';

const app = express();

const { requireAuth, requirePermission } = createAuthMiddleware({
  baseURL: process.env.AUTHOS_URL!
});

// Public route
app.get('/', (req, res) => {
  res.json({ message: 'Hello world' });
});

// Protected route - requires valid JWT
app.get('/profile', requireAuth(), (req, res) => {
  // req.auth contains verified token info
  res.json({ user: req.auth?.claims });
});

// Protected route - requires specific permission
app.delete('/users/:id',
  requireAuth(),
  requirePermission('users:delete'),
  (req, res) => {
    res.json({ message: 'User deleted' });
  }
);

app.listen(3000);
```

The middleware looks for a Bearer token in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## Middleware Reference

### requireAuth(options?)

Requires a valid JWT token. Adds `req.auth` with verified token info.

```ts
app.get('/protected', requireAuth(), (req, res) => {
  const userId = req.auth?.claims.sub;
  res.json({ userId });
});
```

**Options:**
| Option | Type | Description |
|--------|------|-------------|
| `getToken` | `(req) => string` | Custom token extractor |

### requirePermission(permission, options?)

Requires the user to have a specific permission.

```ts
app.post('/admin/users',
  requireAuth(),
  requirePermission('users:create'),
  (req, res) => { ... }
);
```

**Options:**
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `message` | `string` | "Insufficient permissions" | Custom error message |

### requireAnyPermission(permissions, options?)

Requires the user to have at least one of the specified permissions.

```ts
app.get('/reports',
  requireAuth(),
  requireAnyPermission(['reports:read', 'reports:admin']),
  (req, res) => { ... }
);
```

### requireAllPermissions(permissions, options?)

Requires the user to have all of the specified permissions.

```ts
app.post('/admin/settings',
  requireAuth(),
  requireAllPermissions(['admin:access', 'settings:write']),
  (req, res) => { ... }
);
```

### requirePlatformOwner(options?)

Requires the user to be a platform owner.

```ts
app.get('/platform/settings',
  requireAuth(),
  requirePlatformOwner(),
  (req, res) => { ... }
);
```

### requireOrganization(slug, options?)

Requires the user to belong to a specific organization.

```ts
app.get('/org/:slug/data',
  requireAuth(),
  requireOrganization((req) => req.params.slug),
  (req, res) => { ... }
);
```

## Webhook Verification

Verify webhooks from AuthOS:

```ts
import { verifyWebhookSignature } from '@drmhse/authos-node';

app.post('/webhooks/authos', (req, res) => {
  const signature = req.headers['x-authos-signature'];
  const payload = JSON.stringify(req.body);

  try {
    const isValid = verifyWebhookSignature(payload, signature, {
      secret: process.env.WEBHOOK_SECRET!
    });

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Process webhook
    res.json({ received: true });
  } catch (err) {
    res.status(400).json({ error: 'Webhook verification failed' });
  }
});
```

### Creating Webhook Signatures

If you need to verify webhooks from your own services:

```ts
import { createWebhookSignature } from '@drmhse/authos-node';

const payload = JSON.stringify({ event: 'user.created' });
const signature = createWebhookSignature(payload, 'your_secret');
```

## API Reference

### createTokenVerifier(options)

Creates a JWT token verifier that fetches JWKS from AuthOS.

```ts
import { createTokenVerifier, clearJWKSCache } from '@drmhse/authos-node';

const verifier = createTokenVerifier({
  baseURL: 'https://sso.example.com',
  // Optional: cache time in seconds
  cacheTimeSeconds: 300
});

const verified = await verifier.verifyToken(token);

// Clear cache to force JWKS refresh
clearJWKSCache();
```

**Returns:**
- `verifyToken(token)` - Verifies a JWT and returns claims
- Claims include: `sub`, `email`, `is_platform_owner`, `org`, `permissions`

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_TOKEN` | No Bearer token provided |
| `INVALID_TOKEN` | Token is malformed or expired |
| `NOT_AUTHENTICATED` | No auth info on request |
| `PERMISSION_DENIED` | User lacks required permission |
| `NOT_PLATFORM_OWNER` | User is not a platform owner |
| `WRONG_ORGANIZATION` | User is not in required organization |

## License

MIT © DRM HSE
