# @drmhse/authos-node

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-node)](https://www.npmjs.com/package/@drmhse/authos-node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Node.js adapter for AuthOS with token verification and Express middleware helpers.

Full documentation: [authos.dev/docs/packages/authos-node/](https://authos.dev/docs/packages/authos-node/)

## Install

```bash
npm install @drmhse/authos-node
```

For Express middleware:

```bash
npm install @drmhse/authos-node express
```

## Quick start

```ts
import express from 'express';
import { createAuthMiddleware } from '@drmhse/authos-node/express';

const app = express();
const { requireAuth, requirePermission } = createAuthMiddleware({
  baseURL: 'https://sso.example.com',
});

app.get('/profile', requireAuth(), (req, res) => {
  res.json({ user: req.auth?.claims });
});

app.delete(
  '/users/:id',
  requireAuth(),
  requirePermission('users:delete'),
  (req, res) => {
    res.json({ ok: true });
  },
);
```

## Context helpers

Use the middleware that matches the JWT context you issue:

- `requirePlatformOwner()`
- `requireOrganization(...)`
- `requireService(...)`
- `requireTenant(org, service)`

See the docs site for verifier APIs, webhook helpers, and TypeScript details.
