# @drmhse/authos-react

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-react)](https://www.npmjs.com/package/@drmhse/authos-react)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

React and Next.js adapter for AuthOS.

Full documentation: [authos.dev/docs/packages/authos-react/](https://authos.dev/docs/packages/authos-react/)

## Install

```bash
npm install @drmhse/authos-react
```

## Quick start

```tsx
import {
  AuthOSProvider,
  SignIn,
  SignedIn,
  SignedOut,
  UserButton,
} from '@drmhse/authos-react';

export function App() {
  return (
    <AuthOSProvider config={{ baseURL: 'https://sso.example.com' }}>
      <SignedOut>
        <SignIn />
      </SignedOut>
      <SignedIn>
        <UserButton />
      </SignedIn>
    </AuthOSProvider>
  );
}
```

## Scoped tenant usage

```tsx
<AuthOSProvider
  config={{
    baseURL: 'https://sso.example.com',
    org: 'acme-corp',
    service: 'main-app',
    redirectUri: 'https://app.acme.com/callback',
  }}
>
  <SignIn providers={['github', 'google']} />
</AuthOSProvider>
```

## Includes

- `AuthOSProvider`
- `SignIn`, `SignUp`, `Callback`, `OAuthButton`
- `SignedIn`, `SignedOut`, `UserButton`
- Hooks such as `useAuthOS`, `useUser`, and permission helpers

See the docs site for component props, Next.js notes, and advanced patterns.
