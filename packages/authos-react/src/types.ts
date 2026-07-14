import type { SsoClient, SsoClientOptions, UserProfile, Organization } from '@drmhse/sso-sdk';

/**
 * Extended configuration options for the AuthOS React provider.
 *
 * Supports two modes:
 * - **Platform-level**: Just `baseURL` for platform owners/admins (email/password only)
 * - **Multi-tenant**: With `org` and `service` for tenant apps (enables OAuth)
 */
export interface AuthOSConfig extends SsoClientOptions {
  /**
   * Organization slug for OAuth flows.
   * Only required when using OAuth login buttons.
   * Omit for platform-level access.
   * @example 'acme-corp'
   */
  org?: string;

  /**
   * Service slug for OAuth flows.
   * Only required when using OAuth login buttons.
   * Omit for platform-level access.
   * @example 'main-app'
   */
  service?: string;

  /**
   * Redirect URI after OAuth authentication.
   * Defaults to current window location origin + '/callback'.
   * @example 'https://app.example.com/callback'
   */
  redirectUri?: string;

  /**
   * URL to redirect to after successful sign-in.
   * If not set, user stays on current page.
   * @example '/dashboard'
   */
  afterSignInUrl?: string;

  /**
   * URL to redirect to after successful sign-up.
   * If not set, user stays on current page.
  /**
   * URL to redirect to after successful sign-up.
   * If not set, user stays on current page.
   * @example '/onboarding'
   */
  afterSignUpUrl?: string;

  /**
   * Appearance customization options.
   * Use to override default theme colors, fonts, and styling.
   * @example
   * ```ts
   * appearance: {
   *   variables: {
   *     colorPrimary: '#0066cc',
   *     borderRadius: '0.25rem',
   *   }
   * }
   * ```
   */
  appearance?: AppearanceOptions;
}

/**
 * Appearance variables for customizing the visual theme.
 * All properties are optional and use CSS color/size values.
 */
export interface AppearanceVariables {
  /** Primary brand color (e.g., '#6366f1') */
  colorPrimary?: string;
  /** Primary color on hover */
  colorPrimaryHover?: string;
  /** Text color on primary background */
  colorPrimaryForeground?: string;
  /** Error/danger color */
  colorDanger?: string;
  /** Success color */
  colorSuccess?: string;
  /** Warning color */
  colorWarning?: string;
  /** Main background color */
  colorBackground?: string;
  /** Surface/card background color */
  colorSurface?: string;
  /** Main text color */
  colorForeground?: string;
  /** Muted/secondary text color */
  colorMuted?: string;
  /** Border color */
  colorBorder?: string;
  /** Input background color */
  colorInput?: string;
  /** Input border color */
  colorInputBorder?: string;
  /** Focus ring color */
  colorRing?: string;
  /** Font family */
  fontFamily?: string;
  /** Base font size */
  fontSize?: string;
  /** Border radius */
  borderRadius?: string;
}

/**
 * Appearance configuration for customizing component styling.
 */
export interface AppearanceOptions {
  /** CSS variable overrides */
  variables?: AppearanceVariables;
}

/**
 * Configuration options for the AuthOS React provider
 */
export interface AuthOSProviderProps {
  /**
   * SDK and OAuth configuration options.
   * At minimum, requires `baseURL`. For OAuth flows, also set `org` and `service`.
   */
  config: AuthOSConfig;
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
  /** The provider configuration */
  config: AuthOSConfig;
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
  /**
   * OAuth providers to display as buttons.
   * Set to false to hide all OAuth buttons, or provide an array of providers.
   * @default false (no OAuth buttons shown by default)
   * @example ['github', 'google', 'microsoft']
   */
  providers?: ('github' | 'google' | 'microsoft')[] | false;
  /**
   * Show a divider between OAuth and email/password forms.
   * Only visible when providers are enabled.
   * @default true
   */
  showDivider?: boolean;
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
  /** Service slug for registration context (used with orgSlug for tenant attribution) */
  serviceSlug?: string;
  /** Whether to show the "sign in" link */
  showSignIn?: boolean;
  /** Custom class name for the form container */
  className?: string;
  /**
   * OAuth providers to display as buttons.
   * Set to false to hide all OAuth buttons, or provide an array of providers.
   * @default false (no OAuth buttons shown by default)
   * @example ['github', 'google', 'microsoft']
   */
  providers?: ('github' | 'google' | 'microsoft')[] | false;
  /**
   * Show a divider between OAuth and email/password forms.
   * Only visible when providers are enabled.
   * @default true
   */
  showDivider?: boolean;
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

/**
 * Supported OAuth providers
 */
export type SupportedOAuthProvider = 'github' | 'google' | 'microsoft';

/**
 * Props for the OAuthButton component
 */
export interface OAuthButtonProps {
  /** OAuth provider to authenticate with */
  provider: SupportedOAuthProvider;
  /** Button content. Defaults to "Continue with {Provider}" */
  children?: React.ReactNode;
  /** Custom class name for the button */
  className?: string;
  /** Callback when OAuth redirect is initiated */
  onRedirect?: () => void;
  /** Whether the button is disabled */
  disabled?: boolean;
}

/**
 * Props for the SignedIn component.
 * Renders children only when the user is authenticated.
 */
export interface SignedInProps {
  /** Content to render when user is signed in */
  children: React.ReactNode;
}

/**
 * Props for the SignedOut component.
 * Renders children only when the user is not authenticated.
 */
export interface SignedOutProps {
  /** Content to render when user is signed out */
  children: React.ReactNode;
}

/**
 * Props for the Callback component
 */
export interface CallbackProps {
  /** Callback when session is successfully set */
  onSuccess?: () => void;
  /** Callback when session setting fails */
  onError?: (error: Error) => void;
  /** Custom render function for the callback state */
  children?: (props: { error: string | null }) => React.ReactNode;
}
