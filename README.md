# AuthOS

**The open-source, multi-tenant authentication platform for B2B2C applications.**

[AuthOS](https://authos.dev) provides a production-grade identity infrastructure with a focus on performance, security, and developer experience. Built with a high-performance Rust backend and comprehensive TypeScript SDKs, it handles complex authentication flows so you don't have to.

## Repository Structure

This monorepo contains the core backend API and the ecosystem of client libraries:

| Path | Package | Description |
|------|---------|-------------|
| **[`api/`](./api)** | Core Backend | High-performance Rust (Axum) API handling auth, users, and organizations. |
| **[`sso-sdk/`](./sso-sdk)** | `@drmhse/sso-sdk` | Zero-dependency, framework-agnostic TypeScript client. |
| **[`packages/authos-react/`](./packages/authos-react)** | `@drmhse/authos-react` | React & Next.js adapters with hooks, components, and middleware. |
| **[`packages/authos-vue/`](./packages/authos-vue)** | `@drmhse/authos-vue` | Vue 3 & Nuxt adapters with composables and components. |
| **[`packages/authos-node/`](./packages/authos-node)** | `@drmhse/authos-node` | Node.js server adapter (Express middleware, webhook verification). |
| **[`packages/authos-cli/`](./packages/authos-cli)** | `@drmhse/authos-cli` | CLI tool for scaffolding AuthOS components into your app. |

## Key Features

*   **Multi-Tenant Architecture**: Built from the ground up for B2B applications. Users belong to organizations with specific roles and permissions.
*   **Authentication Methods**:
    *   Email/Password (Argon2 hashing)
    *   OAuth2 / Social Login (GitHub, Google, Microsoft)
    *   **Passkeys** (WebAuthn/FIDO2)
    *   Magic Links (Passwordless)
    *   Enterprise SSO / OIDC (Bring Your Own Auth)
*   **Security**:
    *   **MFA**: TOTP (Authenticator apps) and Backup Codes.
    *   **Risk Engine**: Adaptive authentication based on IP velocity, impossible travel, and device fingerprinting.
    *   **Device Trust**: Management and revocation of user devices.
*   **Integration**:
    *   **Billing**: Native support for Stripe and Polar.
    *   **SCIM 2.0**: Automated user provisioning from external IdPs.
    *   **SIEM Streaming**: Stream audit logs to Datadog, Splunk, Elastic, or S3.
    *   **Webhooks**: Event-driven architecture with signed payloads.

## Getting Started

### 1. Run the Backend API

The core of AuthOS is the Rust API. You need Rust (1.89+) installed.

```bash
cd api

# 1. Setup environment
cp .env.example .env
# Edit .env to add your database URL (defaults to SQLite) and keys

# 2. Run the server
cargo run --release
```

The API will start at `http://localhost:3000`.

### 2. Integrate the Frontend

You can scaffold a new integration using the CLI, or install specific packages manually.

#### Using the CLI (Recommended)

```bash
# Initialize AuthOS in your React/Vue/Next.js/Nuxt project root
npx @drmhse/authos-cli init

# Add pre-built components (Login Form, User Profile, etc.)
npx @drmhse/authos-cli add login-form
npx @drmhse/authos-cli add user-profile
```

#### Manual Installation

**React / Next.js:**
```bash
npm install @drmhse/authos-react
```

```tsx
import { AuthOSProvider } from '@drmhse/authos-react';

export default function App() {
  return (
    <AuthOSProvider config={{ baseURL: 'http://localhost:3000' }}>
      <YourApp />
    </AuthOSProvider>
  );
}
```

**Vue / Nuxt:**
```bash
npm install @drmhse/authos-vue
```

**Node.js / Express:**
```bash
npm install @drmhse/authos-node
```

## Development Workflow

### Prerequisites
*   **Rust**: v1.89+
*   **Node.js**: v18+
*   **Database**: SQLite (default), PostgreSQL, or MySQL.

### Building Packages

To build the SDK and all adapter packages:

```bash
# In the root directory
npm install
npm run build
```

This uses `tsup` to build distributable bundles for all packages in `packages/` and `sso-sdk/`.

## Security

*   **Tokens**: Uses short-lived JWTs (RS256) and rotating Refresh Tokens.
*   **Storage**: Client SDKs manage token persistence securely (Cookies for SSR, LocalStorage/Memory for SPA).
*   **Encryption**: Sensitive data (OAuth secrets, SMTP credentials) is encrypted at rest (AES-GCM).

## License

*   **API**: [AGPL-3.0](./api/LICENSE)
*   **SDKs & Packages**: [MIT](./sso-sdk/LICENSE)
