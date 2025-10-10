import { HttpClient } from '../http';
import {
  OAuthProvider,
  DeviceCodeRequest,
  DeviceCodeResponse,
  TokenRequest,
  TokenResponse,
  LoginUrlParams,
  AdminLoginUrlParams,
  ProviderToken,
} from '../types';

/**
 * Authentication and OAuth flow methods
 */
export class AuthModule {
  constructor(private http: HttpClient) {}

  /**
   * Constructs the OAuth login URL for end-users.
   * This does not perform the redirect; the consuming application
   * should redirect the user's browser to this URL.
   *
   * @param provider The OAuth provider to use
   * @param params Login parameters (org, service, redirect_uri)
   * @returns The full URL to redirect the user to
   *
   * @example
   * ```typescript
   * const url = sso.auth.getLoginUrl('github', {
   *   org: 'acme-corp',
   *   service: 'main-app',
   *   redirect_uri: 'https://app.acme.com/callback'
   * });
   * window.location.href = url;
   * ```
   */
  public getLoginUrl(provider: OAuthProvider, params: LoginUrlParams): string {
    const baseURL = this.http.defaults.baseURL || '';
    const searchParams = new URLSearchParams({
      org: params.org,
      service: params.service,
    });

    if (params.redirect_uri) {
      searchParams.append('redirect_uri', params.redirect_uri);
    }

    return `${baseURL}/auth/${provider}?${searchParams.toString()}`;
  }

  /**
   * Constructs the OAuth login URL for platform/organization admins.
   * This uses the platform's dedicated OAuth credentials.
   *
   * @param provider The OAuth provider to use
   * @param params Optional admin login parameters
   * @returns The full URL to redirect the admin to
   *
   * @example
   * ```typescript
   * const url = sso.auth.getAdminLoginUrl('github', {
   *   org_slug: 'acme-corp'
   * });
   * window.location.href = url;
   * ```
   */
  public getAdminLoginUrl(provider: OAuthProvider, params?: AdminLoginUrlParams): string {
    const baseURL = this.http.defaults.baseURL || '';
    const searchParams = new URLSearchParams();

    if (params?.org_slug) {
      searchParams.append('org_slug', params.org_slug);
    }

    const queryString = searchParams.toString();
    return `${baseURL}/auth/admin/${provider}${queryString ? `?${queryString}` : ''}`;
  }

  /**
   * Device Flow: Request a device code for CLI/device authentication.
   *
   * @param payload Device code request payload
   * @returns Device code response with user code and verification URI
   *
   * @example
   * ```typescript
   * const response = await sso.auth.deviceCode.request({
   *   client_id: 'service-client-id',
   *   org: 'acme-corp',
   *   service: 'acme-cli'
   * });
   * console.log(`Visit ${response.verification_uri} and enter code: ${response.user_code}`);
   * ```
   */
  public deviceCode = {
    /**
     * Request a device code
     */
    request: async (payload: DeviceCodeRequest): Promise<DeviceCodeResponse> => {
      const response = await this.http.post<DeviceCodeResponse>('/auth/device/code', payload);
      return response.data;
    },

    /**
     * Exchange a device code for a JWT token.
     * This should be polled by the device/CLI after displaying the user code.
     *
     * @param payload Token request payload
     * @returns Token response with JWT
     *
     * @example
     * ```typescript
     * // Poll every 5 seconds
     * const interval = setInterval(async () => {
     *   try {
     *     const token = await sso.auth.deviceCode.exchangeToken({
     *       grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
     *       device_code: deviceCode,
     *       client_id: 'service-client-id'
     *     });
     *     clearInterval(interval);
     *     sso.setAuthToken(token.access_token);
     *   } catch (error) {
     *     if (error.errorCode !== 'authorization_pending') {
     *       clearInterval(interval);
     *       throw error;
     *     }
     *   }
     * }, 5000);
     * ```
     */
    exchangeToken: async (payload: TokenRequest): Promise<TokenResponse> => {
      const response = await this.http.post<TokenResponse>('/auth/token', payload);
      return response.data;
    },
  };

  /**
   * Logout the current user by revoking their JWT.
   * After calling this, you should clear the token from storage
   * and call `sso.setAuthToken(null)`.
   *
   * @example
   * ```typescript
   * await sso.auth.logout();
   * sso.setAuthToken(null);
   * localStorage.removeItem('jwt');
   * ```
   */
  public async logout(): Promise<void> {
    await this.http.post('/api/auth/logout');
  }

  /**
   * Get a fresh provider access token for the authenticated user.
   * This will automatically refresh the token if it's expired.
   *
   * @param provider The OAuth provider
   * @returns Fresh provider token
   *
   * @example
   * ```typescript
   * const token = await sso.auth.getProviderToken('github');
   * // Use token.access_token to make GitHub API calls
   * ```
   */
  public async getProviderToken(provider: OAuthProvider): Promise<ProviderToken> {
    const response = await this.http.get<ProviderToken>(`/api/provider-token/${provider}`);
    return response.data;
  }
}
