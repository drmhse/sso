# @drmhse/authos-react

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-react)](https://www.npmjs.com/package/@drmhse/authos-react)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

React adapter for [AuthOS](https://authos.dev) - the multi-tenant authentication platform. Provides React hooks, components, and Next.js integration.

## Installation

```bash
npm install @drmhse/authos-react
```

Peer dependencies:
```bash
npm install react react-dom
```

## Quick Start

Wrap your app with `AuthOSProvider`, then use the hooks and components throughout your app.

```tsx
import { AuthOSProvider } from '@drmhse/authos-react';

function App() {
  return (
    <AuthOSProvider
      config={{
        baseURL: 'https://sso.example.com'
      }}
    >
      <YourApp />
    </AuthOSProvider>
  );
}
```

## Components

### SignIn

Pre-built sign-in form with email/password and OAuth provider buttons.

```tsx
import { SignIn } from '@drmhse/authos-react';

function LoginPage() {
  return (
    <SignIn
      onSuccess={() => console.log('Logged in!')}
      onError={(err) => console.error(err)}
    />
  );
}
```

**Props:**
| Prop | Type | Description |
|------|------|-------------|
| `onSuccess` | `() => void` | Callback after successful login |
| `onError` | `(error: Error) => void` | Callback on login error |

### SignUp

Registration form for new users.

```tsx
import { SignUp } from '@drmhse/authos-react';

function RegisterPage() {
  return (
    <SignUp
      onSuccess={() => console.log('Registered!')}
      onError={(err) => console.error(err)}
    />
  );
}
```

**Props:** Same as `SignIn`

### UserButton

User menu button that shows avatar/name and dropdown with profile/signout.

```tsx
import { UserButton } from '@drmhse/authos-react';

function Header() {
  return <UserButton />;
}
```

### OrganizationSwitcher

Dropdown to switch between organizations (for multi-tenant users).

```tsx
import { OrganizationSwitcher } from '@drmhse/authos-react';

function Sidebar() {
  return <OrganizationSwitcher />;
}
```

### Protect

Conditional rendering based on user permissions.

```tsx
import { Protect } from '@drmhse/authos-react';

function AdminPanel() {
  return (
    <Protect
      permission="admin:access"
      fallback={<p>Access denied. Admins only.</p>}
    >
      <AdminDashboard />
    </Protect>
  );
}
```

**Props:**
| Prop | Type | Description |
|------|------|-------------|
| `permission` | `string` | Required permission to access content |
| `fallback` | `ReactNode` | Shown when user lacks permission |
| `children` | `ReactNode` | Protected content |

## Hooks

### useAuthOS

Access the AuthOS client directly.

```tsx
import { useAuthOS } from '@drmhse/authos-react';

function Profile() {
  const { client, isAuthenticated, isLoading } = useAuthOS();

  if (isLoading) return <div>Loading...</div>;
  if (!isAuthenticated) return <div>Please log in</div>;

  const handleLogout = async () => {
    await client.auth.logout();
  };

  return (
    <div>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
}
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `client` | `SsoClient` | The AuthOS SDK client |
| `isLoading` | `boolean` | True while checking auth state |
| `isAuthenticated` | `boolean` | True if user is logged in |

### useUser

Get the current user's profile.

```tsx
import { useUser } from '@drmhse/authos-react';

function UserProfile() {
  const { user, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;
  return <div>Welcome, {user?.email}</div>;
}
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `user` | `UserProfile \| null` | Current user profile |
| `isLoading` | `boolean` | True while checking auth state |

### useOrganization

Get the current organization and list of organizations.

```tsx
import { useOrganization } from '@drmhse/authos-react';

function OrgInfo() {
  const { currentOrganization, organizations } = useOrganization();

  return (
    <div>
      <h3>{currentOrganization?.name}</h3>
      <ul>
        {organizations.map((org) => (
          <li key={org.id}>{org.name}</li>
        ))}
      </ul>
    </div>
  );
}
```

**Returns:**
| Property | Type | Description |
|----------|------|-------------|
| `currentOrganization` | `Organization \| null` | Current organization |
| `organizations` | `Organization[]` | All user's organizations |
| `switchOrganization` | `(slug: string) => Promise<void>` | Switch to a different org |
| `isSwitching` | `boolean` | True while switching |

### usePermission, useAnyPermission, useAllPermissions

Check user permissions.

```tsx
import { usePermission } from '@drmhse/authos-react';

function AdminButton() {
  const canAccessAdmin = usePermission('admin:access');

  if (!canAccessAdmin) return null;

  return <button>Admin Panel</button>;
}
```

## Next.js Integration

For Next.js App Router, use the middleware and server utilities:

```tsx
// middleware.ts
import { authMiddleware } from '@drmhse/authos-react/nextjs';

export default authMiddleware();
```

```tsx
// app/dashboard/page.tsx
import { currentUser } from '@drmhse/authos-react/nextjs';

export default async function Dashboard() {
  const user = await currentUser();

  if (!user) {
    return <div>Please log in</div>;
  }

  return <div>Welcome, {user.email}</div>;
}
```

## API Reference

### AuthOSProvider Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `config.baseURL` | `string` | **required** | AuthOS API URL (e.g., `https://sso.example.com`) |
| `config.storage` | `TokenStorage` | `localStorage` | Custom token storage |
| `config.autoRefresh` | `boolean` | `true` | Auto-refresh expired tokens |
| `config.onAuthStateChange` | `(user) => void` | - | Callback when auth state changes |

### SsoClient

The underlying client from `@drmhse/sso-sdk`. See [SDK docs](https://www.npmjs.com/package/@drmhse/sso-sdk) for full API.

```tsx
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
