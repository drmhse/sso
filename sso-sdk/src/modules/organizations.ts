import { HttpClient } from '../http';
import {
  OAuthProvider,
  OrganizationResponse,
  CreateOrganizationPayload,
  CreateOrganizationResponse,
  UpdateOrganizationPayload,
  ListOrganizationsParams,
  OrganizationMember,
  MemberListResponse,
  UpdateMemberRolePayload,
  TransferOwnershipPayload,
  SetOAuthCredentialsPayload,
  OAuthCredentials,
  EndUserListResponse,
  EndUserDetailResponse,
  ListEndUsersParams,
  RevokeSessionsResponse,
} from '../types';

/**
 * Organization management methods
 */
export class OrganizationsModule {
  constructor(private http: HttpClient) {}

  /**
   * Create a new organization (public endpoint).
   * The organization will be created with 'pending' status and requires
   * platform owner approval before becoming active.
   *
   * @param payload Organization creation payload
   * @returns Created organization with owner and membership details
   *
   * @example
   * ```typescript
   * const result = await sso.organizations.createPublic({
   *   slug: 'acme-corp',
   *   name: 'Acme Corporation',
   *   owner_email: 'founder@acme.com'
   * });
   * ```
   */
  public async createPublic(payload: CreateOrganizationPayload): Promise<CreateOrganizationResponse> {
    const response = await this.http.post<CreateOrganizationResponse>('/api/organizations', payload);
    return response.data;
  }

  /**
   * List all organizations the authenticated user is a member of.
   *
   * @param params Optional query parameters for filtering and pagination
   * @returns Array of organization responses
   *
   * @example
   * ```typescript
   * const orgs = await sso.organizations.list({
   *   status: 'active',
   *   page: 1,
   *   limit: 20
   * });
   * ```
   */
  public async list(params?: ListOrganizationsParams): Promise<OrganizationResponse[]> {
    const response = await this.http.get<OrganizationResponse[]>('/api/organizations', { params });
    return response.data;
  }

  /**
   * Get detailed information for a specific organization.
   *
   * @param orgSlug Organization slug
   * @returns Organization details
   *
   * @example
   * ```typescript
   * const org = await sso.organizations.get('acme-corp');
   * console.log(org.organization.name, org.membership_count);
   * ```
   */
  public async get(orgSlug: string): Promise<OrganizationResponse> {
    const response = await this.http.get<OrganizationResponse>(`/api/organizations/${orgSlug}`);
    return response.data;
  }

  /**
   * Update organization details.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param payload Update payload
   * @returns Updated organization details
   *
   * @example
   * ```typescript
   * const updated = await sso.organizations.update('acme-corp', {
   *   name: 'Acme Corporation Inc.',
   *   max_services: 20
   * });
   * ```
   */
  public async update(orgSlug: string, payload: UpdateOrganizationPayload): Promise<OrganizationResponse> {
    const response = await this.http.patch<OrganizationResponse>(
      `/api/organizations/${orgSlug}`,
      payload
    );
    return response.data;
  }

  /**
   * Member management methods
   */
  public members = {
    /**
     * List all members of an organization.
     *
     * @param orgSlug Organization slug
     * @returns Member list response with pagination metadata
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.members.list('acme-corp');
     * console.log(`Total members: ${result.total}`);
     * result.members.forEach(m => console.log(m.email, m.role));
     * ```
     */
    list: async (orgSlug: string): Promise<MemberListResponse> => {
      const response = await this.http.get<MemberListResponse>(
        `/api/organizations/${orgSlug}/members`
      );
      return response.data;
    },

    /**
     * Update a member's role.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param userId User ID to update
     * @param payload Role update payload
     * @returns Updated member details
     *
     * @example
     * ```typescript
     * await sso.organizations.members.updateRole('acme-corp', 'user-id', {
     *   role: 'admin'
     * });
     * ```
     */
    updateRole: async (
      orgSlug: string,
      userId: string,
      payload: UpdateMemberRolePayload
    ): Promise<OrganizationMember> => {
      const response = await this.http.patch<OrganizationMember>(
        `/api/organizations/${orgSlug}/members/${userId}`,
        payload
      );
      return response.data;
    },

    /**
     * Remove a member from the organization.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param userId User ID to remove
     *
     * @example
     * ```typescript
     * await sso.organizations.members.remove('acme-corp', 'user-id');
     * ```
     */
    remove: async (orgSlug: string, userId: string): Promise<void> => {
      await this.http.post(`/api/organizations/${orgSlug}/members/${userId}`);
    },

    /**
     * Transfer organization ownership to another member.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param payload Transfer payload with new owner ID
     *
     * @example
     * ```typescript
     * await sso.organizations.members.transferOwnership('acme-corp', {
     *   new_owner_user_id: 'new-owner-id'
     * });
     * ```
     */
    transferOwnership: async (orgSlug: string, payload: TransferOwnershipPayload): Promise<void> => {
      await this.http.post(`/api/organizations/${orgSlug}/members/transfer-ownership`, payload);
    },
  };

  /**
   * End-user management methods
   * Manage organization's customers (end-users with subscriptions)
   */
  public endUsers = {
    /**
     * List all end-users for an organization.
     * Returns users who have identities (logged in) or subscriptions for the organization's services.
     *
     * @param orgSlug Organization slug
     * @param params Optional query parameters for pagination and filtering
     * @param params.service_slug Optional service slug to filter users by a specific service
     * @returns Paginated list of end-users with their subscriptions and identities
     *
     * @example
     * ```typescript
     * // List all end-users across all services
     * const allUsers = await sso.organizations.endUsers.list('acme-corp', {
     *   page: 1,
     *   limit: 20
     * });
     * 
     * // Filter by specific service
     * const serviceUsers = await sso.organizations.endUsers.list('acme-corp', {
     *   service_slug: 'my-app',
     *   page: 1,
     *   limit: 20
     * });
     * console.log(`Total end-users: ${allUsers.total}`);
     * ```
     */
    list: async (
      orgSlug: string,
      params?: ListEndUsersParams
    ): Promise<EndUserListResponse> => {
      const response = await this.http.get<EndUserListResponse>(
        `/api/organizations/${orgSlug}/users`,
        { params }
      );
      return response.data;
    },

    /**
     * Get detailed information about a specific end-user.
     *
     * @param orgSlug Organization slug
     * @param userId User ID
     * @returns End-user details with subscriptions, identities, and session count
     *
     * @example
     * ```typescript
     * const endUser = await sso.organizations.endUsers.get('acme-corp', 'user-id');
     * console.log(`Active sessions: ${endUser.session_count}`);
     * ```
     */
    get: async (orgSlug: string, userId: string): Promise<EndUserDetailResponse> => {
      const response = await this.http.get<EndUserDetailResponse>(
        `/api/organizations/${orgSlug}/users/${userId}`
      );
      return response.data;
    },

    /**
     * Revoke all active sessions for an end-user.
     * Requires admin or owner role.
     * This will force the user to re-authenticate.
     *
     * @param orgSlug Organization slug
     * @param userId User ID
     * @returns Response with number of revoked sessions
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.endUsers.revokeSessions('acme-corp', 'user-id');
     * console.log(`Revoked ${result.revoked_count} sessions`);
     * ```
     */
    revokeSessions: async (
      orgSlug: string,
      userId: string
    ): Promise<RevokeSessionsResponse> => {
      const response = await this.http.delete<RevokeSessionsResponse>(
        `/api/organizations/${orgSlug}/users/${userId}/sessions`
      );
      return response.data;
    },
  };

  /**
   * BYOO (Bring Your Own OAuth) credential management
   */
  public oauthCredentials = {
    /**
     * Set or update custom OAuth credentials for a provider.
     * This enables white-labeled authentication using the organization's
     * own OAuth application.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param provider OAuth provider
     * @param payload OAuth credentials
     * @returns Created/updated credentials (without secret)
     *
     * @example
     * ```typescript
     * await sso.organizations.oauthCredentials.set('acme-corp', 'github', {
     *   client_id: 'Iv1.abc123',
     *   client_secret: 'secret-value'
     * });
     * ```
     */
    set: async (
      orgSlug: string,
      provider: OAuthProvider,
      payload: SetOAuthCredentialsPayload
    ): Promise<OAuthCredentials> => {
      const response = await this.http.post<OAuthCredentials>(
        `/api/organizations/${orgSlug}/oauth-credentials/${provider}`,
        payload
      );
      return response.data;
    },

    /**
     * Get the configured OAuth credentials for a provider.
     * The secret is never returned.
     *
     * @param orgSlug Organization slug
     * @param provider OAuth provider
     * @returns OAuth credentials (without secret)
     *
     * @example
     * ```typescript
     * const creds = await sso.organizations.oauthCredentials.get('acme-corp', 'github');
     * console.log(creds.client_id);
     * ```
     */
    get: async (orgSlug: string, provider: OAuthProvider): Promise<OAuthCredentials> => {
      const response = await this.http.get<OAuthCredentials>(
        `/api/organizations/${orgSlug}/oauth-credentials/${provider}`
      );
      return response.data;
    },
  };
}
