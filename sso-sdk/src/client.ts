import { HttpClient, createHttpAgent } from './http';
import { AuthModule } from './modules/auth';
import { UserModule } from './modules/user';
import { OrganizationsModule } from './modules/organizations';
import { ServicesModule } from './modules/services';
import { InvitationsModule } from './modules/invitations';
import { PlatformModule } from './modules/platform';

/**
 * Configuration options for the SSO client
 */
export interface SsoClientOptions {
  /**
   * Base URL of the SSO API service
   */
  baseURL: string;

  /**
   * Optional JWT token to initialize with
   */
  token?: string;
}

/**
 * Main SSO client class.
 * This is the entry point for all SDK operations.
 *
 * @example
 * ```typescript
 * const sso = new SsoClient({
 *   baseURL: 'https://sso.example.com',
 *   token: localStorage.getItem('jwt')
 * });
 *
 * // Use the modules
 * const user = await sso.user.getProfile();
 * const orgs = await sso.organizations.list();
 * ```
 */
export class SsoClient {
  private http: HttpClient;

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

  constructor(options: SsoClientOptions) {
    this.http = createHttpAgent(options.baseURL);

    if (options.token) {
      this.setAuthToken(options.token);
    }

    // Instantiate all modules
    this.auth = new AuthModule(this.http);
    this.user = new UserModule(this.http);
    this.organizations = new OrganizationsModule(this.http);
    this.services = new ServicesModule(this.http);
    this.invitations = new InvitationsModule(this.http);
    this.platform = new PlatformModule(this.http);
  }

  /**
   * Sets the JWT for all subsequent authenticated requests.
   * Pass null to clear the token.
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
    } else {
      delete this.http.defaults.headers.common['Authorization'];
    }
  }

  /**
   * Gets the current base URL
   */
  public getBaseURL(): string {
    return this.http.defaults.baseURL || '';
  }
}
