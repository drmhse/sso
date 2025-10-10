import { HttpClient } from '../http';
import { UserProfile, UpdateUserProfilePayload, Subscription, Identity, StartLinkResponse } from '../types';

/**
 * Identity (social account linking) methods
 */
class IdentitiesModule {
  constructor(private http: HttpClient) {}

  /**
   * List all social accounts linked to the authenticated user.
   *
   * @returns Array of linked identities
   *
   * @example
   * ```typescript
   * const identities = await sso.user.identities.list();
   * console.log(identities); // [{ provider: 'github' }, { provider: 'google' }]
   * ```
   */
  public async list(): Promise<Identity[]> {
    const response = await this.http.get<Identity[]>('/api/user/identities');
    return response.data;
  }

  /**
   * Start linking a new social account to the authenticated user.
   * Returns an authorization URL that the user should be redirected to.
   *
   * @param provider The OAuth provider to link (e.g., 'github', 'google', 'microsoft')
   * @returns Object containing the authorization URL
   *
   * @example
   * ```typescript
   * const { authorization_url } = await sso.user.identities.startLink('github');
   * window.location.href = authorization_url; // Redirect user to complete OAuth
   * ```
   */
  public async startLink(provider: string): Promise<StartLinkResponse> {
    const response = await this.http.post<StartLinkResponse>(`/api/user/identities/${provider}/link`, {});
    return response.data;
  }

  /**
   * Unlink a social account from the authenticated user.
   * Note: Cannot unlink the last remaining identity to prevent account lockout.
   *
   * @param provider The OAuth provider to unlink (e.g., 'github', 'google', 'microsoft')
   *
   * @example
   * ```typescript
   * await sso.user.identities.unlink('google');
   * ```
   */
  public async unlink(provider: string): Promise<void> {
    await this.http.delete(`/api/user/identities/${provider}`);
  }
}

/**
 * User profile and subscription methods
 */
export class UserModule {
  public readonly identities: IdentitiesModule;

  constructor(private http: HttpClient) {
    this.identities = new IdentitiesModule(http);
  }

  /**
   * Get the profile of the currently authenticated user.
   * The response includes context from the JWT (org, service).
   *
   * @returns User profile
   *
   * @example
   * ```typescript
   * const profile = await sso.user.getProfile();
   * console.log(profile.email, profile.org, profile.service);
   * ```
   */
  public async getProfile(): Promise<UserProfile> {
    const response = await this.http.get<UserProfile>('/api/user');
    return response.data;
  }

  /**
   * Update the authenticated user's profile.
   *
   * @param payload Update payload
   * @returns Updated user profile
   *
   * @example
   * ```typescript
   * const updated = await sso.user.updateProfile({
   *   email: 'newemail@example.com'
   * });
   * ```
   */
  public async updateProfile(payload: UpdateUserProfilePayload): Promise<UserProfile> {
    const response = await this.http.patch<UserProfile>('/api/user', payload);
    return response.data;
  }

  /**
   * Get the current user's subscription details for the service in their JWT.
   *
   * @returns Subscription details
   *
   * @example
   * ```typescript
   * const subscription = await sso.user.getSubscription();
   * console.log(subscription.plan, subscription.features);
   * ```
   */
  public async getSubscription(): Promise<Subscription> {
    const response = await this.http.get<Subscription>('/api/subscription');
    return response.data;
  }
}
