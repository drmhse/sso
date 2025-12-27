import type { SsoClient, SsoClientOptions, UserProfile, Organization } from '@drmhse/sso-sdk';

/**
 * Configuration options for the AuthOS React provider
 */
export interface AuthOSProviderProps {
  /**
   * SDK configuration options
   */
  config: SsoClientOptions;
  /**
   * React children
   */
  children: React.ReactNode;
  /**
   * Optional: Provide an existing SsoClient instance instead of creating a new one
   */
  client?: SsoClient;
  /**
   * Optional: Initial session token from server-side (for SSR hydration).
   * When provided, skips the initial loading state on the client.
   * Typically passed from cookies() in Next.js server components.
   */
  initialSessionToken?: string;
}

/**
 * Authentication context state
 */
export interface AuthOSContextState {
  /** The underlying SDK client instance */
  client: SsoClient;
  /** Current authenticated user, or null if not authenticated */
  user: UserProfile | null;
  /** Whether the user is authenticated */
  isAuthenticated: boolean;
  /** Whether the initial auth check is still loading */
  isLoading: boolean;
  /** Current active organization context */
  organization: Organization | null;
  /** Set the current user (internal use) */
  setUser: (user: UserProfile | null) => void;
  /** Set the current organization (internal use) */
  setOrganization: (org: Organization | null) => void;
  /** Refresh the current user data from the server */
  refreshUser: () => Promise<void>;
}

/**
 * Props for the SignIn component
 */
export interface SignInProps {
  /** Callback when sign-in is successful */
  onSuccess?: (user: UserProfile) => void;
  /** Callback when sign-in fails */
  onError?: (error: Error) => void;
  /** Whether to show the "forgot password" link */
  showForgotPassword?: boolean;
  /** Whether to show the "sign up" link */
  showSignUp?: boolean;
  /** Custom class name for the form container */
  className?: string;
}

/**
 * Props for the SignUp component
 */
export interface SignUpProps {
  /** Callback when sign-up is successful */
  onSuccess?: () => void;
  /** Callback when sign-up fails */
  onError?: (error: Error) => void;
  /** Organization slug for registration context */
  orgSlug?: string;
  /** Whether to show the "sign in" link */
  showSignIn?: boolean;
  /** Custom class name for the form container */
  className?: string;
}

/**
 * Props for the OrganizationSwitcher component
 */
export interface OrganizationSwitcherProps {
  /** Callback when organization is switched */
  onSwitch?: (org: Organization) => void;
  /** Custom class name for the switcher container */
  className?: string;
  /** Render prop for custom organization item rendering */
  renderItem?: (org: Organization, isActive: boolean) => React.ReactNode;
}

/**
 * Props for the UserButton component
 */
export interface UserButtonProps {
  /** Custom class name for the button container */
  className?: string;
  /** Whether to show the user's email */
  showEmail?: boolean;
  /** Callback after successful logout */
  onLogout?: () => void;
}

/**
 * Props for the Protect component
 */
export interface ProtectProps {
  /** Required permission to access children */
  permission?: string;
  /** Required role to access children */
  role?: 'owner' | 'admin' | 'member';
  /** Fallback content when access is denied */
  fallback?: React.ReactNode;
  /** React children to render when access is granted */
  children: React.ReactNode;
}
