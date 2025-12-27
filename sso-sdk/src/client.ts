import { HttpClient, createHttpAgent } from './http';
import { SessionManager } from './session';
import { TokenStorage, resolveStorage } from './storage';
import { AnalyticsModule } from './modules/analytics';
import { AuthModule } from './modules/auth';
import { UserModule } from './modules/user';
import { OrganizationsModule } from './modules/organizations';
import { ServicesModule } from './modules/services';
import { InvitationsModule } from './modules/invitations';
import { PlatformModule } from './modules/platform';
import { ServiceApiModule } from './modules/serviceApi';
import { PermissionsModule } from './modules/permissions';
import { PasskeysModule } from './modules/passkeys';
import { MagicLinks } from './modules/magic';
import { PrivacyModule } from './modules/privacy';

/**
 * Configuration options for the SSO client
 */
export interface SsoClientOptions {
  /**
   * Base URL of the SSO API service
   */
  baseURL: string;

  /**
   * Optional JWT token to initialize with (for user authentication)
   */
  token?: string;

  /**
   * Optional API key for service-to-service authentication
   */
  apiKey?: string;

  /**
   * Custom storage provider (optional).
   * Defaults to localStorage in browser, Memory in Node.
   */
  storage?: TokenStorage;

  /**
   * Prefix for storage keys. Default: 'sso_'
   */
  storagePrefix?: string;
}

/**
 * Main SSO client class.
 * This is the entry point for all SDK operations.
 *
 * @example
 * ```typescript
 * const sso = new SsoClient({
 *   baseURL: 'https://sso.example.com',
 *   token: localStorage.getItem('sso_access_token')
 * });
 *
 * // Use the modules
 * const user = await sso.user.getProfile();
 * const orgs = await sso.organizations.list();
 * ```
 */
export class SsoClient {
  public http: HttpClient;
  private session: SessionManager;

  /**
   * Analytics and login tracking methods
   */
  public readonly analytics: AnalyticsModule;

  /**
   * Authentication and OAuth flow methods
   */
  public readonly auth: AuthModule;

  /**
   * User profile and subscription methods
   */
  public readonly user: UserModule;

  /**
   * Organization management methods
   */
  public readonly organizations: OrganizationsModule;

  /**
   * Service management methods
   */
  public readonly services: ServicesModule;

  /**
   * Invitation management methods
   */
  public readonly invitations: InvitationsModule;

  /**
   * Platform owner administration methods
   */
  public readonly platform: PlatformModule;

  /**
   * Service API methods (requires API key authentication)
   */
  public readonly serviceApi: ServiceApiModule;

  /**
   * Permission checking and management methods
   */
  public readonly permissions: PermissionsModule;

  /**
   * WebAuthn/Passkey authentication methods
   */
  public readonly passkeys: PasskeysModule;

  /**
   * Magic link authentication methods
   */
  public readonly magicLinks: MagicLinks;

  /**
   * Privacy and GDPR compliance methods
   */
  public readonly privacy: PrivacyModule;

  constructor(options: SsoClientOptions) {
    this.http = createHttpAgent(options.baseURL);

    // Initialize Session Manager
    this.session = new SessionManager(
      resolveStorage(options.storage),
      async (refreshToken) => {
        const res = await this.http.post('/api/auth/refresh', { refresh_token: refreshToken });
        return res.data;
      },
      { storageKeyPrefix: options.storagePrefix || 'sso_' }
    );

    // Link HTTP client to Session Manager
    this.http.setSessionManager(this.session);

    // Instantiate all modules
    // Note: Pass 'this.session' to AuthModule so login can update state directly
    this.analytics = new AnalyticsModule(this.http);
    this.auth = new AuthModule(this.http, this.session);
    this.user = new UserModule(this.http);
    this.organizations = new OrganizationsModule(this.http);
    this.services = new ServicesModule(this.http);
    this.invitations = new InvitationsModule(this.http);
    this.platform = new PlatformModule(this.http);
    this.serviceApi = new ServiceApiModule(this.http);
    this.permissions = new PermissionsModule(this.http);
    this.passkeys = new PasskeysModule(this.http);
    this.magicLinks = new MagicLinks(this.http);
    this.privacy = new PrivacyModule(this.http);

    // Handle initial configuration
    if (options.apiKey) {
      this.setApiKey(options.apiKey);
    }

    // Async init - if we have a token in options, set it, otherwise try load from storage
    if (options.token) {
      this.session.setSession({ access_token: options.token });
    } else {
      // We can't await in constructor, but we kick it off
      this.session.loadSession().catch(console.error);
    }
  }

  /**
   * Sets the JWT for all subsequent authenticated requests.
   * Pass null to clear the token.
   *
   * NOTE: For OAuth callback flows, prefer using setSession() which properly
   * updates the SessionManager. This method updates both the HTTP headers
   * AND the SessionManager for backward compatibility.
   *
   * @param token The JWT string, or null to clear
   *
   * @example
   * ```typescript
   * // Set token
   * sso.setAuthToken(jwt);
   *
   * // Clear token
   * sso.setAuthToken(null);
   * ```
   */
  public setAuthToken(token: string | null): void {
    if (token) {
      this.http.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Also update SessionManager so getToken() returns the correct value
      this.session.setSession({ access_token: token });
    } else {
      delete this.http.defaults.headers.common['Authorization'];
      this.session.clearSession();
    }
  }

  /**
   * Sets the session tokens for OAuth callback flows.
   * This properly updates the SessionManager and persists tokens to storage.
   *
   * @param tokens Object containing access_token and optionally refresh_token
   *
   * @example
   * ```typescript
   * // After OAuth callback
   * await sso.setSession({
   *   access_token: accessToken,
   *   refresh_token: refreshToken
   * });
   * ```
   */
  public async setSession(tokens: { access_token: string; refresh_token?: string }): Promise<void> {
    await this.session.setSession(tokens);
  }

  /**
   * Sets the API key for service-to-service authentication.
   * Pass null to clear the API key.
   *
   * @param apiKey The API key string, or null to clear
   *
   * @example
   * ```typescript
   * // Set API key
   * sso.setApiKey('sk_live_abcd1234...');
   *
   * // Clear API key
   * sso.setApiKey(null);
   * ```
   */
  public setApiKey(apiKey: string | null): void {
    if (apiKey) {
      this.http.defaults.headers.common['X-Api-Key'] = apiKey;
    } else {
      delete this.http.defaults.headers.common['X-Api-Key'];
    }
  }

  /**
   * Gets the current base URL
   */
  public getBaseURL(): string {
    return this.http.defaults.baseURL || '';
  }

  /**
   * Gets the JWKS (JSON Web Key Set) URL for JWT verification.
   * Use this for stateless token verification in edge functions or middleware.
   *
   * @returns The full URL to the .well-known/jwks.json endpoint
   *
   * @example
   * ```typescript
   * const jwksUrl = sso.getJwksUrl();
   * // Returns: "https://sso.example.com/.well-known/jwks.json"
   * ```
   */
  public getJwksUrl(): string {
    const baseUrl = this.getBaseURL().replace(/\/$/, '');
    return `${baseUrl}/.well-known/jwks.json`;
  }

  /**
   * Check if the user is currently authenticated
   */
  public isAuthenticated(): boolean {
    return this.session.isAuthenticated();
  }

  /**
   * Subscribe to authentication state changes.
   * Useful for updating UI when login/logout/expiration occurs.
   *
   * @param listener Callback function that receives the authentication state
   * @returns Unsubscribe function
   *
   * @example
   * ```typescript
   * const unsubscribe = sso.onAuthStateChange((isAuth) => {
   *   console.log(isAuth ? 'User is logged in' : 'User is logged out');
   * });
   *
   * // Later, to stop listening
   * unsubscribe();
   * ```
   */
  public onAuthStateChange(listener: (isAuthenticated: boolean) => void) {
    return this.session.subscribe(listener);
  }

  /**
   * Manually retrieve the current access token
   *
   * @returns The current access token, or null if not authenticated
   */
  public async getToken(): Promise<string | null> {
    return this.session.getToken();
  }
}
