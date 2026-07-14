# @drmhse/authos-node

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-node)](https://www.npmjs.com/package/@drmhse/authos-node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Node.js adapter for AuthOS with token verification and Express middleware helpers.

This package is pre-1.0 and Beta. Pin an exact version and review the
[current AuthOS support matrix](https://github.com/drmhse/AuthOS/blob/main/PROJECT_STATUS.md).

Full documentation: [authos.dev/docs/packages/authos-node/](https://authos.dev/docs/packages/authos-node/)

AI agent skills: [authos.dev/docs/ai-agent-skills/](https://authos.dev/docs/ai-agent-skills/) and [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)

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
  baseURL: process.env.AUTHOS_BASE_URL || 'http://localhost:3001',
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
