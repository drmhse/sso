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

// Types
export type {
  AuthOSProviderProps,
  AuthOSContextState,
  SignInProps,
  SignUpProps,
  OrganizationSwitcherProps,
  UserButtonProps,
  ProtectProps,
} from './types';

// Re-export commonly used types from the SDK
export type { UserProfile, Organization, SsoClientOptions } from '@drmhse/sso-sdk';
export { SsoClient, SsoApiError, AuthErrorCodes } from '@drmhse/sso-sdk';
