# SSO Platform - Web Client

Admin dashboard for the multi-tenant SSO platform. Built with Vue 3, Pinia, Vue Router, and Tailwind CSS.

## Features

- **Authentication Flow**: OAuth-based admin login with GitHub, Google, and Microsoft
- **Platform Owner Dashboard**: Manage organizations and platform-level settings
- **Organization Dashboard**: Manage services, team members, and settings
- **Role-Based Access Control**: Different views and permissions based on user roles

## Tech Stack

- **Framework**: Vue.js 3 (Composition API with `<script setup>`)
- **State Management**: Pinia
- **Routing**: Vue Router
- **HTTP SDK**: `@drmhse/sso-sdk` (locally linked, powered by Axios)
- **Styling**: Tailwind CSS + Headless UI

## Prerequisites

- Node.js 18+ and npm
- The SSO SDK built and linked (see `../sso-sdk`)
- Running SSO API backend (see `../api`)

## Setup

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Link the local SDK** (if not already linked):
   ```bash
   cd ../sso-sdk
   npm link
   cd ../web-client
   npm link @drmhse/sso-sdk
   ```

3. **Configure environment variables**:

   Copy `.env.development` and update the API URL if needed:
   ```bash
   VITE_API_BASE_URL=http://localhost:3000
   ```

4. **Start the development server**:
   ```bash
   npm run dev
   ```

   The application will be available at `http://localhost:5173`

## Project Structure

```
/web-client
├── src/
│   ├── api/              # SDK singleton instance
│   ├── assets/           # Static assets
│   ├── components/       # Reusable UI components
│   ├── composables/      # Reusable composition functions
│   ├── layouts/          # Layout components
│   ├── router/           # Vue Router configuration
│   ├── stores/           # Pinia state stores
│   ├── utils/            # Utility functions
│   ├── views/            # Page components
│   ├── App.vue           # Root component
│   └── main.js           # Application entry point
├── public/               # Public static files
├── .env.development      # Development environment variables
├── .env.production       # Production environment variables
└── package.json
```

## Implementation Status

### Phase 0: Core Authentication (✅ Complete)
- ✅ Project setup with Vue 3, Pinia, Vue Router, Tailwind CSS
- ✅ SDK integration (locally linked)
- ✅ Authentication store with JWT handling
- ✅ Router with navigation guards
- ✅ Login, Callback, and Home views
- ✅ Layout system (AppLayout, AuthLayout)
- ✅ Permission composable for role-based access
- ✅ Notification system

### Phase 1: Organization & Team Management (Pending)
- Organization onboarding flow
- Platform owner approval workflow
- Team member management
- Invitation system

### Phase 2: Service Management (Pending)
- Service CRUD operations
- BYOO (Bring Your Own OAuth) credentials
- Service configuration

### Phase 3: User Management (Pending)
- End-user management for organizations

### Phase 4: Billing (Pending)
- Billing dashboard
- Plan management
- Stripe integration

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build locally

## Authentication Flow

1. User navigates to `/login`
2. User clicks on OAuth provider button (GitHub, Google, or Microsoft)
3. Application generates admin login URL via SDK
4. User is redirected to OAuth provider
5. After authentication, provider redirects to `/callback?token=...`
6. Callback view extracts token and stores it
7. User profile is fetched and stored in Pinia auth store
8. Home view redirects based on user role:
   - Platform owners → `/platform/dashboard`
   - Organization members → `/orgs/{slug}/dashboard`
   - New users → `/signup`

## Key Architectural Decisions

1. **SDK Singleton**: Single instance of `SsoClient` shared across the app
2. **Pinia as State Layer**: All API calls go through Pinia stores
3. **Component-Store Separation**: Views don't call SDK directly
4. **Permission Composable**: Centralized role-checking logic
5. **Layout System**: Dynamic layout based on route metadata

## Development Notes

- The SDK is locally linked - rebuild it when making SDK changes
- All routes requiring authentication have `meta: { requiresAuth: true }`
- Platform-only routes have `meta: { requiresPlatformOwner: true }`
- JWT tokens are stored in localStorage as `sso_token`
- Token validation happens on app initialization via navigation guard

## Next Steps

See `../frontend_implementation_plan.md` for detailed implementation phases.
