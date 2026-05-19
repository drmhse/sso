// Provider
export { AuthOSProvider, useAuthOSContext } from './context';

// Hooks
export { useAuthOS } from './hooks/useAuthOS';
export { useUser } from './hooks/useUser';
export { useOrganization } from './hooks/useOrganization';
export { usePermission, useAnyPermission, useAllPermissions } from './hooks/usePermission';

// Components
export { SignIn } from './components/SignIn';
export { SignUp } from './components/SignUp';
export { OrganizationSwitcher } from './components/OrganizationSwitcher';
export { UserButton } from './components/UserButton';
export { Protect } from './components/Protect';
export { OAuthButton } from './components/OAuthButton';
export { SignedIn } from './components/SignedIn';
export { SignedOut } from './components/SignedOut';
export { MagicLinkSignIn } from './components/MagicLinkSignIn';
export type { MagicLinkSignInProps } from './components/MagicLinkSignIn';
export { PasskeySignIn } from './components/PasskeySignIn';
export type { PasskeySignInProps } from './components/PasskeySignIn';
export { Callback } from './components/Callback';

// Types
export type {
  // Provider and context types
  AuthOSConfig,
  AuthOSProviderProps,
  AuthOSContextState,
  // Component props
  SignInProps,
  SignUpProps,
  OrganizationSwitcherProps,
  UserButtonProps,
  ProtectProps,
  OAuthButtonProps,
  SignedInProps,
  SignedOutProps,
  CallbackProps,
  // Utility types
  SupportedOAuthProvider,
} from './types';

// Re-export commonly used types from the SDK
export type { UserProfile, Organization, SsoClientOptions } from '@drmhse/sso-sdk';
export { SsoClient, SsoApiError, AuthErrorCodes } from '@drmhse/sso-sdk';
