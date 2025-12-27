# @drmhse/authos-cli

[![npm version](https://img.shields.io/npm/v/@drmhse/authos-cli)](https://www.npmjs.com/package/@drmhse/authos-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

CLI tool for scaffolding [AuthOS](https://authos.dev) authentication components in your project.

## Installation

```bash
npm install @drmhse/authos-cli -g
```

Or use without installing globally:

```bash
npx @drmhse/authos-cli init
```

## Commands

### `authos init`

Initialize AuthOS in your project. This command detects your framework (React, Next.js, Vue, Nuxt) and sets up the appropriate configuration.

```bash
authos init
```

The `init` command will:
1. Detect your framework from package.json dependencies
2. Install the appropriate AuthOS adapter package (`@drmhse/authos-react` or `@drmhse/authos-vue`)
3. Set up the AuthOS provider/plugin in your app

### `authos add`

Generate and add AuthOS components to your project.

```bash
authos add <template>
```

**Available templates:**
- `login-form` - Styled login form with email/password and MFA support
- `org-switcher` - Dropdown for switching between organizations
- `user-profile` - User avatar button with dropdown menu

## Examples

### React / Next.js Project

```bash
# Initialize AuthOS in a Next.js project
authos init

# Add a login form component
authos add login-form

# Add organization switcher
authos add org-switcher

# Add user profile component
authos add user-profile
```

### Vue / Nuxt Project

```bash
# Initialize AuthOS in a Nuxt project
authos init

# Add components
authos add login-form
authos add org-switcher
authos add user-profile
```

## Templates

### login-form

A styled login form component with:
- Email and password fields
- MFA (TOTP) support
- Loading states
- Error handling

### org-switcher

A dropdown component for switching between organizations when a user belongs to multiple organizations.

### user-profile

A user avatar button with:
- Avatar display (with fallback to initials)
- Dropdown menu showing user info
- Sign out functionality

## Programmatic Usage

You can also use the CLI programmatically:

```ts
import { initCommand, addCommand, getAvailableTemplates } from '@drmhse/authos-cli';

// Get available templates
const templates = getAvailableTemplates();
console.log(templates); // ['login-form', 'org-switcher', 'user-profile']

// Initialize AuthOS
await initCommand({
  projectDir: process.cwd(),
  framework: 'next'
});

// Add a component
await addCommand({
  projectDir: process.cwd(),
  template: 'login-form'
});
```

## Troubleshooting

### Framework Detection Failed

If `authos init` fails to detect your framework:

1. Ensure you are in the root directory of your project (where `package.json` is).
2. Manually specify the framework when initializing:

```bash
# For Next.js/React
authos init --framework next

# For Nuxt/Vue
authos init --framework nuxt
```

### Component Installation Errors

If `authos add` fails to write files:

1. Check that you have a `components/` directory in your project.
2. Ensure you have write permissions in your project directory.
3. Try running with verbose logging (if available) or check console output for specific error messages.

## License

MIT © DRM HSE
