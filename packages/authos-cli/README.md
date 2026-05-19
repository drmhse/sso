# @drmhse/authos-cli

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-cli)](https://www.npmjs.com/package/@drmhse/authos-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

CLI for scaffolding AuthOS integration components into React, Next.js, Vue, and Nuxt projects.

Full documentation: [authos.dev/docs/packages/authos-cli/](https://authos.dev/docs/packages/authos-cli/)

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

See the docs site for supported frameworks, template behavior, and troubleshooting.
