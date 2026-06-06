# @drmhse/authos-cli

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-cli)](https://www.npmjs.com/package/@drmhse/authos-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

CLI for scaffolding AuthOS integration components into React, Next.js, Vue, and Nuxt projects.

Full documentation: [authos.dev/docs/packages/authos-cli/](https://authos.dev/docs/packages/authos-cli/)

AI agent skills: [authos.dev/docs/ai-agent-skills/](https://authos.dev/docs/ai-agent-skills/) and [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)

## Install

```bash
npm install -g @drmhse/authos-cli
```

Or run without a global install:

```bash
npx @drmhse/authos-cli init
```

## Commands

### Initialize a project

```bash
authos init
```

This command detects the framework, installs the relevant adapter package, and sets up the base AuthOS configuration.
For Next.js it writes both `AUTHOS_BASE_URL` and `NEXT_PUBLIC_AUTHOS_URL` to `.env.local`; for Vite React/Vue it writes `AUTHOS_BASE_URL` and `VITE_AUTHOS_BASE_URL`.

### Add a component template

```bash
authos add login-form
authos add org-switcher
authos add user-profile
```

### Provision ACT

```bash
authos provision act \
  --base-url https://auth.example.com \
  --act-url https://act.example.com \
  --owner-email owner@example.com \
  --owner-password '...'
```

This command idempotently bootstraps the ACT organization, service, redirect URIs, GitHub scopes, and service API key. It can also write the one-time API key and AuthOS client ID to local files.

## Typical flow

```bash
authos init
authos add login-form
```

For a fresh standalone AuthOS install, use the URL printed by `sudo ./install.sh` or shown in the lite Platform Setup workspace. The default local URL is usually `http://localhost:3001` on the AuthOS host.

See the docs site for supported frameworks, template behavior, and troubleshooting.
