# @drmhse/authos-vue

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-vue)](https://www.npmjs.com/package/@drmhse/authos-vue)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Vue 3 adapter for [AuthOS](https://authos.dev) - the multi-tenant authentication platform. Provides Vue composables, components, and Nuxt module.

## Installation

```bash
npm install @drmhse/authos-vue
```

Peer dependencies:
```bash
npm install vue
```

## Quick Start

### Vue App

Install the plugin and use the composables/components:

```ts
// main.ts
import { createApp } from 'vue';
import { createAuthOS } from '@drmhse/authos-vue';
import App from './App.vue';

const app = createApp(App);

app.use(createAuthOS({
  // Required: AuthOS API URL (e.g., https://sso.example.com)
  baseUrl: 'https://sso.example.com'
}));

app.mount('#app');
```

### Nuxt App

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ['@drmhse/authos-vue/nuxt']
});
```

## Components

### SignIn

Pre-built sign-in form with email/password and OAuth provider buttons.

```vue
<script setup lang="ts">
import { SignIn } from '@drmhse/authos-vue';

function handleSuccess() {
  console.log('Logged in!');
}

function handleError(err: Error) {
  console.error(err);
}
</script>

<template>
  <SignIn @success="handleSuccess" @error="handleError" />
</template>
```

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| `@success` | - | Fired after successful login |
| `@error` | `Error` | Fired on login error |

### SignUp

Registration form for new users.

```vue
<script setup lang="ts">
import { SignUp } from '@drmhse/authos-vue';
</script>

<template>
  <SignUp />
</template>
```

**Events:** Same as `SignIn`

### UserButton

User menu button that shows avatar/name and dropdown with profile/signout.

```vue
<script setup lang="ts">
import { UserButton } from '@drmhse/authos-vue';
</script>

<template>
  <header>
    <UserButton />
  </header>
</template>
```

### OrganizationSwitcher

Dropdown to switch between organizations (for multi-tenant users).

```vue
<script setup lang="ts">
import { OrganizationSwitcher } from '@drmhse/authos-vue';
</script>

<template>
  <aside>
    <OrganizationSwitcher />
  </aside>
</template>
```

### Protect

Conditional rendering based on user permissions.

```vue
<script setup lang="ts">
import { Protect } from '@drmhse/authos-vue';
</script>

<template>
  <Protect permission="admin:access">
    <template #default>
      <AdminDashboard />
    </template>
    <template #fallback>
      <p>Access denied. Admins only.</p>
    </template>
  </Protect>
</template>
```

**Props:**
| Prop | Type | Description |
|------|------|-------------|
| `permission` | `string` | Required permission to access content |
| `fallback` | `slot` | Shown when user lacks permission |
| `default` | `slot` | Protected content |

## Composables

### useAuthOS

Access the AuthOS client directly.

```vue
<script setup lang="ts">
import { useAuthOS } from '@drmhse/authos-vue';

const { client, isAuthenticated, isLoading } = useAuthOS();

async function handleLogout() {
  await client.auth.logout();
}
</script>

<template>
  <div v-if="isLoading">Loading...</div>
  <div v-else-if="!isAuthenticated">Please log in</div>
  <div v-else>
    <button @click="handleLogout">Logout</button>
  </div>
</template>
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `client` | `SsoClient` | The AuthOS SDK client |
| `isLoading` | `Ref<boolean>` | True while checking auth state |
| `isAuthenticated` | `Ref<boolean>` | True if user is logged in |

### useUser

Get the current user's profile.

```vue
<script setup lang="ts">
import { useUser } from '@drmhse/authos-vue';

const { user, isLoading } = useUser();
</script>

<template>
  <div v-if="isLoading">Loading...</div>
  <div v-else>Welcome, {{ user?.email }}</div>
</template>
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `user` | `Ref<UserProfile | null>` | Current user profile |
| `isLoading` | `Ref<boolean>` | True while checking auth state |

### useOrganization

Get the current organization and list of organizations.

```vue
<script setup lang="ts">
import { useOrganization } from '@drmhse/authos-vue';

const { currentOrganization, organizations, switchOrganization } = useOrganization();
</script>

<template>
  <div>
    <h3>{{ currentOrganization?.name }}</h3>
    <ul>
      <li v-for="org in organizations" :key="org.id">
        {{ org.name }}
      </li>
    </ul>
  </div>
</template>
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `currentOrganization` | `Ref<Organization | null>` | Current organization |
| `organizations` | `Ref<Organization[]>` | All user's organizations |
| `switchOrganization` | `(slug: string) => Promise<void>` | Switch to a different org |
| `isSwitching` | `Ref<boolean>` | True while switching |

## Nuxt Module

When using the Nuxt module, the plugin is auto-installed and provides additional server utilities:

```vue
<!-- app.vue -->
<script setup lang="ts">
// Plugin is auto-installed, composables work automatically
import { useUser } from '@drmhse/authos-vue';

const { user } = useUser();
</script>

<template>
  <div v-if="user">
    Welcome, {{ user.email }}
  </div>
</template>
```

### Nuxt Auth Middleware

Protect pages with the auth middleware:

```ts
// middleware/auth.ts
import { authMiddleware } from '@drmhse/authos-vue/nuxt';

export default authMiddleware({
  redirectTo: '/login'
});
```

Then use in your pages:

```vue
<script setup>
definePageMeta({
  middleware: ['auth']
});
</script>

<template>
  <div>Protected page</div>
</template>
```

### Server-Side Usage

```ts
// server/api/user.get.ts
import { currentUser } from '@drmhse/authos-vue/nuxt';

export default defineEventHandler(async (event) => {
  const user = await currentUser(event);

  if (!user) {
    throw createError({
      statusCode: 401,
      message: 'Unauthorized'
    });
  }

  return user;
});
```

## SsoClient API

The underlying client from `@drmhse/sso-sdk`. See [SDK docs](https://www.npmjs.com/package/@drmhse/sso-sdk) for full API.

```ts
const { client } = useAuthOS();

// Authentication
await client.auth.login({ email, password });
await client.auth.logout();
await client.auth.register({ email, password, org_slug });

// User
await client.user.getProfile();
await client.user.updateProfile({ name });
await client.user.changePassword({ old, new });

// Organizations
await client.organizations.list();
await client.organizations.get(slug);

// And more...
```

## License

MIT © DRM HSE
