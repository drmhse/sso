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
}

export interface AuthOSPluginOptions {
  baseUrl: string;
  storage?: TokenStorage;
  autoRefresh?: boolean;
  /**
   * Initial session token from server-side (for SSR hydration).
   * When provided, skips the initial loading state on the client.
   * Typically passed from cookies in Nuxt server components.
   */
  initialToken?: string;
}

export const AUTH_OS_INJECTION_KEY = Symbol('authOS');
