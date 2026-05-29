# @drmhse/authos-vue

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-vue)](https://www.npmjs.com/package/@drmhse/authos-vue)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Vue 3 and Nuxt adapter for AuthOS.

Full documentation: [authos.dev/docs/packages/authos-vue/](https://authos.dev/docs/packages/authos-vue/)

AI agent skills: [authos.dev/docs/ai-agent-skills/](https://authos.dev/docs/ai-agent-skills/) and [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)

## Install

```bash
npm install @drmhse/authos-vue
```

## Quick start

```ts
import { createApp } from 'vue';
import { createAuthOS } from '@drmhse/authos-vue';
import App from './App.vue';

const app = createApp(App);

app.use(
  createAuthOS({
    baseURL: 'https://sso.example.com',
  }),
);

app.mount('#app');
```

```vue
<script setup>
import { SignIn, SignedIn, SignedOut, UserButton } from '@drmhse/authos-vue';
</script>

<template>
  <SignedOut>
    <SignIn />
  </SignedOut>
  <SignedIn>
    <UserButton />
  </SignedIn>
</template>
```

## Scoped tenant usage

```ts
app.use(
  createAuthOS({
    baseURL: 'https://sso.example.com',
    org: 'acme-corp',
    service: 'main-app',
    redirectUri: 'https://app.acme.com/callback',
  }),
);
```

## Includes

- Plugin factory `createAuthOS`
- Components such as `SignIn`, `SignUp`, `Callback`, `OAuthButton`, `Protect`, and `OrganizationSwitcher`
- Composables for auth state, profile data, organizations, and permissions

See the docs site for Nuxt details, slot APIs, and advanced integration patterns.
