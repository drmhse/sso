// Plugin
export { createAuthOS } from './plugin';

// Types
export type {
  AuthOSState,
  AuthOSContext,
  AuthOSPluginOptions,
  SupportedOAuthProvider,
  AppearanceVariables,
  AppearanceOptions,
} from './types';
export { AUTH_OS_INJECTION_KEY } from './types';

// Composables
export { useAuthOS } from './composables/useAuthOS';
export { useUser } from './composables/useUser';
export { useOrganization } from './composables/useOrganization';
export { usePermission, useAnyPermission, useAllPermissions } from './composables/usePermission';

// Components
export { AuthOSProvider } from './components/AuthOSProvider';
export { SignIn } from './components/SignIn';
export type { SignInSlotProps } from './components/SignIn';
export { SignUp } from './components/SignUp';
export type { SignUpSlotProps } from './components/SignUp';
export { OrganizationSwitcher } from './components/OrganizationSwitcher';
export type { OrganizationSwitcherSlotProps } from './components/OrganizationSwitcher';
export { UserButton } from './components/UserButton';
export type { UserButtonSlotProps } from './components/UserButton';
export { Protect } from './components/Protect';
export { OAuthButton } from './components/OAuthButton';
export type { OAuthButtonSlotProps } from './components/OAuthButton';
export { SignedIn } from './components/SignedIn';
export { SignedOut } from './components/SignedOut';
export { MagicLinkSignIn } from './components/MagicLinkSignIn';
export { PasskeySignIn } from './components/PasskeySignIn';
export { Callback } from './components/Callback';
export type { CallbackSlotProps } from './components/Callback';

// Re-export useful types from SDK
export type { SsoClient, UserProfile, OrganizationResponse, TokenStorage } from '@drmhse/sso-sdk';
export { SsoApiError, AuthErrorCodes, BrowserStorage, MemoryStorage } from '@drmhse/sso-sdk';
