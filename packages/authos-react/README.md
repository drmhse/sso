# @drmhse/authos-react

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-react)](https://www.npmjs.com/package/@drmhse/authos-react)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

React and Next.js adapter for AuthOS.

Full documentation: [authos.dev/docs/packages/authos-react/](https://authos.dev/docs/packages/authos-react/)

AI agent skills: [authos.dev/docs/ai-agent-skills/](https://authos.dev/docs/ai-agent-skills/) and [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)

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

For Next.js client components, expose the AuthOS origin with a public env var:

```env
NEXT_PUBLIC_AUTHOS_URL=http://localhost:3001
```

```tsx
<AuthOSProvider config={{ baseURL: process.env.NEXT_PUBLIC_AUTHOS_URL! }}>
  {children}
</AuthOSProvider>
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
