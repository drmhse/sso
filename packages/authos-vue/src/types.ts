import type { SsoClient, UserProfile, OrganizationResponse, TokenStorage } from '@drmhse/sso-sdk';

export interface AuthOSState {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  currentOrganization: OrganizationResponse | null;
  organizations: OrganizationResponse[];
}

export interface AuthOSContext {
  client: SsoClient;
  state: AuthOSState;
  /** The plugin configuration options */
  options: AuthOSPluginOptions;
}

/**
 * Configuration options for the AuthOS Vue plugin.
 *
 * Supports two modes:
 * - **Platform-level**: Just `baseURL` for platform owners/admins (email/password only)
 * - **Multi-tenant**: With `org` and `service` for tenant apps (enables OAuth)
 *
 * @example Platform-level access
 * ```ts
 * app.use(createAuthOS({
 *   baseURL: 'https://sso.example.com',
 * }));
 * ```
 *
 * @example Multi-tenant with OAuth
 * ```ts
 * app.use(createAuthOS({
 *   baseURL: 'https://sso.example.com',
 *   org: 'my-org',
 *   service: 'my-app',
 * }));
 * ```
 */
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

export interface AuthOSPluginOptions {
  /**
   * Base URL of the AuthOS API service.
   * @example 'https://sso.example.com'
   */
  baseURL: string;

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
   * Custom storage provider (optional).
   * Defaults to localStorage in browser, Memory in SSR.
   */
  storage?: TokenStorage;

  /**
   * Automatically refresh expired tokens.
   * @default true
   */
  autoRefresh?: boolean;

  /**
   * Initial session token from server-side (for SSR hydration).
   * When provided, skips the initial loading state on the client.
   * Typically passed from cookies in Nuxt server components.
   */
  initialToken?: string;

  /**
   * URL to redirect to after successful sign-in.
   * @example '/dashboard'
   */
  afterSignInUrl?: string;

  /**
   * URL to redirect to after successful sign-up.
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

export const AUTH_OS_INJECTION_KEY = Symbol('authOS');

/**
 * Supported OAuth providers
 */
export type SupportedOAuthProvider = 'github' | 'google' | 'microsoft';
