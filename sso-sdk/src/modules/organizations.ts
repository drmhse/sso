import { HttpClient } from '../http';
import {
  OAuthProvider,
  OrganizationResponse,
  CreateOrganizationPayload,
  CreateOrganizationResponse,
  SelectOrganizationResponse,
  UpdateOrganizationPayload,
  ListOrganizationsParams,
  OrganizationMember,
  MemberListResponse,
  MemberServiceAccess,
  UpdateMemberRolePayload,
  UpdateMemberServiceAccessPayload,
  TransferOwnershipPayload,
  SetOAuthCredentialsPayload,
  OAuthCredentials,
  EndUserListResponse,
  EndUserDetailResponse,
  ListEndUsersParams,
  RevokeSessionsResponse,
  SetSmtpRequest,
  SmtpConfigResponse,
  DomainConfiguration,
  SetCustomDomainRequest,
  DomainVerificationResponse,
  DomainVerificationResult,
  BrandingConfiguration,
  UpdateBrandingRequest,
  GetRiskSettingsResponse,
  UpdateRiskSettingsRequest,
  UpdateRiskSettingsResponse,
  CreateSiemConfigRequest,
  UpdateSiemConfigRequest,
  SiemConfigResponse,
  ListSiemConfigsResponse,
  TestConnectionResponse,
  CreateScimTokenRequest,
  CreateScimTokenResponse,
  ListScimTokensResponse,
  Invitation,
  CreateInvitationPayload,
  CreateInvitationResponse,
  RiskEventResponse,
  RiskEventsQuery,
  RoleResponse,
  CreateRoleRequest,
  UpdateRoleRequest,
} from '../types';
import { AuditLogsModule } from './organizations/audit';
import { WebhooksModule } from './organizations/webhooks';
import { DomainRoutesModule } from './organizations/domain-routes';
import { UpstreamProvidersModule } from './organizations/upstream-providers';

/**
 * Organization management methods
 */
export class OrganizationsModule {
  constructor(private http: HttpClient) {
    this.auditLogs = new AuditLogsModule(http);
    this.webhooks = new WebhooksModule(http);
    this.domainRoutes = new DomainRoutesModule(http);
    this.upstreamProviders = new UpstreamProvidersModule(http);
  }

  /**
   * Audit logs management
   */
  public auditLogs: AuditLogsModule;

  /**
   * Webhooks management
   */
  public webhooks: WebhooksModule;
  public domainRoutes: DomainRoutesModule;

  /**
   * Upstream provider (Enterprise SSO) management
   */
  public upstreamProviders: UpstreamProvidersModule;

  /**
   * Create a new organization (requires authentication).
   * The authenticated user becomes the organization owner.
   * Returns JWT tokens with organization context, eliminating the need to re-authenticate.
   *
   * @param payload Organization creation payload
   * @returns Created organization with owner, membership, and JWT tokens
   *
   * @example
   * ```typescript
   * const result = await sso.organizations.create({
   *   slug: 'acme-corp',
   *   name: 'Acme Corporation'
   * });
   * // Store the new tokens with org context
   * authStore.setTokens(result.access_token, result.refresh_token);
   * ```
   */
  public async create(payload: CreateOrganizationPayload): Promise<CreateOrganizationResponse> {
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
   * Select/switch to a different organization context.
   * Issues a new JWT token with the organization context.
   *
   * This allows users to seamlessly switch between organizations
   * they are members of without re-authenticating.
   *
   * @param orgSlug Organization slug to switch to
   * @returns New tokens with organization context
   *
   * @example
   * ```typescript
   * // Switch to a different organization
   * const result = await sso.organizations.select('acme-corp');
   *
   * // The SDK automatically updates the session with new tokens
   * // API calls will now be made in the context of 'acme-corp'
   * ```
   */
  public async select(orgSlug: string): Promise<SelectOrganizationResponse> {
    const response = await this.http.post<SelectOrganizationResponse>(
      `/api/organizations/${orgSlug}/select`
    );
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
   * Delete an organization and all its associated data.
   * This is a destructive operation that cannot be undone.
   * Requires 'owner' role.
   *
   * All related data will be cascaded deleted including:
   * - Members and invitations
   * - Services and plans
   * - Subscriptions
   * - OAuth credentials
   * - Audit logs
   *
   * @param orgSlug Organization slug
   *
   * @example
   * ```typescript
   * await sso.organizations.delete('acme-corp');
   * ```
   */
  public async delete(orgSlug: string): Promise<void> {
    await this.http.delete(`/api/organizations/${orgSlug}`);
  }

  /**
   * SCIM token management methods
   */
  public scim = {
    /**
     * Create a new SCIM token.
     * The token is only returned once upon creation.
     */
    createToken: async (
      orgSlug: string,
      payload: CreateScimTokenRequest
    ): Promise<CreateScimTokenResponse> => {
      const response = await this.http.post<CreateScimTokenResponse>(
        `/api/organizations/${orgSlug}/scim-tokens`,
        payload
      );
      return response.data;
    },

    /**
     * List all SCIM tokens.
     */
    listTokens: async (orgSlug: string): Promise<ListScimTokensResponse> => {
      const response = await this.http.get<ListScimTokensResponse>(
        `/api/organizations/${orgSlug}/scim-tokens`
      );
      return response.data;
    },

    /**
     * Revoke a SCIM token.
     */
    revokeToken: async (orgSlug: string, tokenId: string): Promise<void> => {
      await this.http.post(`/api/organizations/${orgSlug}/scim-tokens/${tokenId}/revoke`);
    },

    /**
     * Delete a SCIM token.
     */
    deleteToken: async (orgSlug: string, tokenId: string): Promise<void> => {
      await this.http.delete(`/api/organizations/${orgSlug}/scim-tokens/${tokenId}`);
    },
  };

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
     * Add a member to the organization (Invite + Accept).
     * This is a convenience method that creates an invitation and immediately accepts it.
     * Useful for testing and admin operations.
     *
     * @param orgSlug Organization slug
     * @param payload Member details (email, role)
     * @returns The created invitation
     */
    add: async (
      orgSlug: string,
      payload: CreateInvitationPayload
    ): Promise<Invitation> => {
      // 1. Create invitation
      const response = await this.http.post<CreateInvitationResponse>(
        `/api/organizations/${orgSlug}/invitations`,
        payload
      );

      const invitation = response.data.invitation;

      // 2. Accept invitation
      await this.http.post(
        `/api/organizations/${orgSlug}/invitations/${invitation.id}/accept`
      );

      return invitation;
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
     * List a member's direct per-service access grants.
     */
    listServiceAccess: async (
      orgSlug: string,
      userId: string
    ): Promise<MemberServiceAccess[]> => {
      const response = await this.http.get<MemberServiceAccess[]>(
        `/api/organizations/${orgSlug}/members/${userId}/service-access`
      );
      return response.data;
    },

    /**
     * Replace a member's direct per-service access grants.
     */
    updateServiceAccess: async (
      orgSlug: string,
      userId: string,
      payload: UpdateMemberServiceAccessPayload
    ): Promise<MemberServiceAccess[]> => {
      const response = await this.http.put<MemberServiceAccess[]>(
        `/api/organizations/${orgSlug}/members/${userId}/service-access`,
        payload
      );
      return response.data;
    },

    /**
     * Transfer organization ownership to another member.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param payload Transfer payload with the new owner's email
     *
     * @example
     * ```typescript
     * await sso.organizations.members.transferOwnership('acme-corp', {
     *   new_owner_email: 'new-owner@example.com'
     * });
     * ```
     */
    transferOwnership: async (orgSlug: string, payload: TransferOwnershipPayload): Promise<void> => {
      await this.http.post(`/api/organizations/${orgSlug}/transfer-ownership`, payload);
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

  // ============================================================================
  // SMTP MANAGEMENT
  // ============================================================================

  /**
   * Configure SMTP settings for an organization.
   * Only owners and admins can configure SMTP.
   * The organization will use these settings for sending transactional emails
   * (registration, password reset, etc.).
   *
   * @param orgSlug Organization slug
   * @param config SMTP configuration
   * @returns Success message
   *
   * @example
   * ```typescript
   * await sso.organizations.setSmtp('acme-corp', {
   *   host: 'smtp.gmail.com',
   *   port: 587,
   *   username: 'notifications@acme.com',
   *   password: 'your-app-password',
   *   from_email: 'notifications@acme.com',
   *   from_name: 'Acme Corp'
   * });
   * ```
   */
  public async setSmtp(orgSlug: string, config: SetSmtpRequest): Promise<{ message: string }> {
    const response = await this.http.post<{ message: string }>(
      `/api/organizations/${orgSlug}/smtp`,
      config
    );
    return response.data;
  }

  /**
   * Get SMTP configuration for an organization.
   * Only owners and admins can view SMTP settings.
   * Password is never returned for security reasons.
   *
   * @param orgSlug Organization slug
   * @returns SMTP configuration (without password)
   *
   * @example
   * ```typescript
   * const config = await sso.organizations.getSmtp('acme-corp');
   * if (config.configured) {
   *   console.log('SMTP host:', config.host);
   * }
   * ```
   */
  public async getSmtp(orgSlug: string): Promise<SmtpConfigResponse> {
    const response = await this.http.get<SmtpConfigResponse>(
      `/api/organizations/${orgSlug}/smtp`
    );
    return response.data;
  }

  /**
   * Delete SMTP configuration for an organization.
   * The organization will revert to using platform-level SMTP.
   * Only owners and admins can delete SMTP settings.
   *
   * @param orgSlug Organization slug
   * @returns Success message
   *
   * @example
   * ```typescript
   * await sso.organizations.deleteSmtp('acme-corp');
   * // Organization now uses platform SMTP
   * ```
   */
  public async deleteSmtp(orgSlug: string): Promise<{ message: string }> {
    const response = await this.http.delete<{ message: string }>(
      `/api/organizations/${orgSlug}/smtp`
    );
    return response.data;
  }

  // ============================================================================
  // CUSTOM DOMAINS & BRANDING
  // ============================================================================

  /**
   * Set a custom domain for an organization.
   * This enables white-labeling by allowing the organization to use their own domain
   * (e.g., auth.acme.com) instead of the platform's domain.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param request Custom domain request
   * @returns Domain verification instructions
   *
   * @example
   * ```typescript
   * const verification = await sso.organizations.setCustomDomain('acme-corp', {
   *   domain: 'auth.acme.com'
   * });
   * console.log('Verification token:', verification.verification_token);
   * verification.verification_methods.forEach(method => {
   *   console.log(method.method, method.instructions);
   * });
   * ```
   */
  public async setCustomDomain(
    orgSlug: string,
    request: SetCustomDomainRequest
  ): Promise<DomainVerificationResponse> {
    const response = await this.http.post<DomainVerificationResponse>(
      `/api/organizations/${orgSlug}/domain`,
      request
    );
    return response.data;
  }

  /**
   * Verify a custom domain by checking DNS TXT record or HTTP file.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @returns Verification result
   *
   * @example
   * ```typescript
   * const result = await sso.organizations.verifyCustomDomain('acme-corp');
   * if (result.verified) {
   *   console.log('Domain verified successfully!');
   * } else {
   *   console.log('Verification failed:', result.message);
   * }
   * ```
   */
  public async verifyCustomDomain(orgSlug: string): Promise<DomainVerificationResult> {
    const response = await this.http.post<DomainVerificationResult>(
      `/api/organizations/${orgSlug}/domain/verify`
    );
    return response.data;
  }

  /**
   * Get custom domain configuration for an organization.
   *
   * @param orgSlug Organization slug
   * @returns Domain configuration
   *
   * @example
   * ```typescript
   * const config = await sso.organizations.getDomainConfiguration('acme-corp');
   * if (config.custom_domain && config.domain_verified) {
   *   console.log('Custom domain active:', config.custom_domain);
   * }
   * ```
   */
  public async getDomainConfiguration(orgSlug: string): Promise<DomainConfiguration> {
    const response = await this.http.get<DomainConfiguration>(
      `/api/organizations/${orgSlug}/domain`
    );
    return response.data;
  }

  /**
   * Delete custom domain configuration.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   *
   * @example
   * ```typescript
   * await sso.organizations.deleteCustomDomain('acme-corp');
   * // Organization reverts to using platform domain
   * ```
   */
  public async deleteCustomDomain(orgSlug: string): Promise<void> {
    await this.http.delete(`/api/organizations/${orgSlug}/domain`);
  }

  /**
   * Update branding configuration (logo and primary color).
   * This controls the visual appearance of authentication pages.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param request Branding configuration
   * @returns Updated branding configuration
   *
   * @example
   * ```typescript
   * await sso.organizations.updateBranding('acme-corp', {
   *   logo_url: 'https://cdn.acme.com/logo.png',
   *   primary_color: '#FF5733'
   * });
   * ```
   */
  public async updateBranding(
    orgSlug: string,
    request: UpdateBrandingRequest
  ): Promise<BrandingConfiguration> {
    const response = await this.http.patch<BrandingConfiguration>(
      `/api/organizations/${orgSlug}/branding`,
      request
    );
    return response.data;
  }

  /**
   * Get branding configuration for an organization.
   *
   * @param orgSlug Organization slug
   * @returns Branding configuration
   *
   * @example
   * ```typescript
   * const branding = await sso.organizations.getBranding('acme-corp');
   * if (branding.logo_url) {
   *   console.log('Logo URL:', branding.logo_url);
   * }
   * ```
   */
  public async getBranding(orgSlug: string): Promise<BrandingConfiguration> {
    const response = await this.http.get<BrandingConfiguration>(
      `/api/organizations/${orgSlug}/branding`
    );
    return response.data;
  }

  /**
   * Get public branding configuration (no authentication required).
   * This endpoint is used by login pages to display organization branding.
   *
   * @param orgSlug Organization slug
   * @returns Branding configuration
   *
   * @example
   * ```typescript
   * // Can be called without authentication
   * const branding = await sso.organizations.getPublicBranding('acme-corp');
   * ```
   */
  public async getPublicBranding(orgSlug: string): Promise<BrandingConfiguration> {
    const response = await this.http.get<BrandingConfiguration>(
      `/api/organizations/${orgSlug}/branding/public`
    );
    return response.data;
  }

  // ============================================================================
  // RISK SETTINGS
  // ============================================================================

  /**
   * Risk settings management methods
   */
  public riskSettings = {
    /**
     * Get risk settings for an organization.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @returns Risk settings configuration
     *
     * @example
     * ```typescript
     * const settings = await sso.organizations.riskSettings.get('acme-corp');
     * console.log('Enforcement mode:', settings.enforcement_mode);
     * console.log('Low threshold:', settings.low_threshold);
     * ```
     */
    get: async (orgSlug: string): Promise<GetRiskSettingsResponse> => {
      const response = await this.http.get<GetRiskSettingsResponse>(
        `/api/organizations/${orgSlug}/risk-settings`
      );
      return response.data;
    },

    /**
     * Update risk settings for an organization.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param payload Risk settings update payload
     * @returns Updated risk settings
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.riskSettings.update('acme-corp', {
     *   enforcement_mode: 'challenge',
     *   low_threshold: 30,
     *   medium_threshold: 70,
     *   new_device_score: 20,
     *   impossible_travel_score: 50
     * });
     * console.log(result.message);
     * ```
     */
    update: async (
      orgSlug: string,
      payload: UpdateRiskSettingsRequest
    ): Promise<UpdateRiskSettingsResponse> => {
      const response = await this.http.put<UpdateRiskSettingsResponse>(
        `/api/organizations/${orgSlug}/risk-settings`,
        payload
      );
      return response.data;
    },

    /**
     * Reset risk settings to default values.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @returns Reset confirmation with default values
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.riskSettings.reset('acme-corp');
     * console.log('Risk settings reset to defaults');
     * ```
     */
    reset: async (orgSlug: string): Promise<UpdateRiskSettingsResponse> => {
      const response = await this.http.post<UpdateRiskSettingsResponse>(
        `/api/organizations/${orgSlug}/risk-settings/reset`
      );
      return response.data;
    },
  };

  // ============================================================================
  // SIEM CONFIGURATIONS
  // ============================================================================

  /**
   * SIEM (Security Information and Event Management) configuration methods
   */
  public siem = {
    /**
     * Create a new SIEM configuration.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param payload SIEM configuration payload
     * @returns Created SIEM configuration
     *
     * @example
     * ```typescript
     * const config = await sso.organizations.siem.create('acme-corp', {
     *   name: 'Datadog Integration',
     *   provider_type: 'Datadog',
     *   endpoint_url: 'https://http-intake.logs.datadoghq.com/v1/input',
     *   api_key: 'dd-api-key',
     *   batch_size: 100
     * });
     * ```
     */
    create: async (
      orgSlug: string,
      payload: CreateSiemConfigRequest
    ): Promise<SiemConfigResponse> => {
      const response = await this.http.post<SiemConfigResponse>(
        `/api/organizations/${orgSlug}/siem-configs`,
        payload
      );
      return response.data;
    },

    /**
     * List all SIEM configurations for an organization.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @returns List of SIEM configurations
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.siem.list('acme-corp');
     * console.log(`Total SIEM configs: ${result.total}`);
     * result.siem_configs.forEach(config => {
     *   console.log(config.name, config.provider_type, config.enabled);
     * });
     * ```
     */
    list: async (orgSlug: string): Promise<ListSiemConfigsResponse> => {
      const response = await this.http.get<ListSiemConfigsResponse>(
        `/api/organizations/${orgSlug}/siem-configs`
      );
      return response.data;
    },

    /**
     * Get a specific SIEM configuration.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param configId SIEM configuration ID
     * @returns SIEM configuration
     *
     * @example
     * ```typescript
     * const config = await sso.organizations.siem.get('acme-corp', 'config-id');
     * console.log(config.name, config.endpoint_url);
     * ```
     */
    get: async (orgSlug: string, configId: string): Promise<SiemConfigResponse> => {
      const response = await this.http.get<SiemConfigResponse>(
        `/api/organizations/${orgSlug}/siem-configs/${configId}`
      );
      return response.data;
    },

    /**
     * Update a SIEM configuration.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param configId SIEM configuration ID
     * @param payload Update payload
     * @returns Updated SIEM configuration
     *
     * @example
     * ```typescript
     * const updated = await sso.organizations.siem.update('acme-corp', 'config-id', {
     *   enabled: false,
     *   batch_size: 200
     * });
     * ```
     */
    update: async (
      orgSlug: string,
      configId: string,
      payload: UpdateSiemConfigRequest
    ): Promise<SiemConfigResponse> => {
      const response = await this.http.put<SiemConfigResponse>(
        `/api/organizations/${orgSlug}/siem-configs/${configId}`,
        payload
      );
      return response.data;
    },

    /**
     * Delete a SIEM configuration.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param configId SIEM configuration ID
     *
     * @example
     * ```typescript
     * await sso.organizations.siem.delete('acme-corp', 'config-id');
     * console.log('SIEM configuration deleted');
     * ```
     */
    delete: async (orgSlug: string, configId: string): Promise<void> => {
      await this.http.delete(`/api/organizations/${orgSlug}/siem-configs/${configId}`);
    },

    /**
     * Test connection to a SIEM endpoint.
     * Sends a test event to verify the configuration.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param configId SIEM configuration ID
     * @returns Test result
     *
     * @example
     * ```typescript
     * const result = await sso.organizations.siem.test('acme-corp', 'config-id');
     * if (result.success) {
     *   console.log('Connection successful:', result.message);
     * } else {
     *   console.error('Connection failed:', result.message);
     * }
     * ```
     */
    test: async (orgSlug: string, configId: string): Promise<TestConnectionResponse> => {
      const response = await this.http.post<TestConnectionResponse>(
        `/api/organizations/${orgSlug}/siem-configs/${configId}/test`
      );
      return response.data;
    },
  };

  // ============================================================================
  // BILLING
  // ============================================================================

  /**
   * Billing and subscription management methods
   */
  public billing = {
    /**
     * Get billing information for an organization.
     * Returns whether a billing account exists and which provider is being used.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @returns Billing information
     *
     * @example
     * ```typescript
     * const info = await sso.organizations.billing.getInfo('acme-corp');
     * if (info.has_billing_account) {
     *   console.log('Billing provider:', info.provider);
     * }
     * ```
     */
    getInfo: async (orgSlug: string): Promise<{ has_billing_account: boolean; provider: string | null }> => {
      const response = await this.http.get<{ has_billing_account: boolean; provider: string | null }>(
        `/api/organizations/${orgSlug}/billing/info`
      );
      return response.data;
    },

    /**
     * Create a billing portal session.
     * Redirects the user to the billing provider's self-service portal to manage their subscription,
     * update payment methods, view invoices, etc.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param returnUrl URL to redirect the user to after they leave the portal
     * @returns Object containing the portal session URL
     *
     * @example
     * ```typescript
     * const session = await sso.organizations.billing.createPortalSession('acme-corp', {
     *   return_url: 'https://app.acme.com/billing'
     * });
     * // Redirect user to billing portal
     * window.location.href = session.url;
     * ```
     */
    createPortalSession: async (
      orgSlug: string,
      payload: { return_url: string }
    ): Promise<{ url: string }> => {
      const response = await this.http.post<{ url: string }>(
        `/api/organizations/${orgSlug}/billing/portal`,
        payload
      );
      return response.data;
    },
  };

  /**
   * Security & Risk insights
   */
  public security = {
    /**
     * Get risk events for an organization.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param params Query parameters
     */
    getRiskEvents: async (
      orgSlug: string,
      params?: RiskEventsQuery
    ): Promise<RiskEventResponse[]> => {
      const response = await this.http.get<RiskEventResponse[]>(
        `/api/organizations/${orgSlug}/risk-events`,
        { params }
      );
      return response.data;
    },
  };

  /**
   * Role management methods
   */
  public roles = {
    /**
     * List all custom roles for an organization.
     */
    list: async (orgSlug: string): Promise<RoleResponse[]> => {
      const response = await this.http.get<RoleResponse[]>(
        `/api/organizations/${orgSlug}/roles`
      );
      return response.data;
    },

    /**
     * Get details of a specific role.
     */
    get: async (orgSlug: string, roleId: string): Promise<RoleResponse> => {
      const response = await this.http.get<RoleResponse>(
        `/api/organizations/${orgSlug}/roles/${roleId}`
      );
      return response.data;
    },

    /**
     * Create a new custom role.
     */
    create: async (orgSlug: string, payload: CreateRoleRequest): Promise<RoleResponse> => {
      const response = await this.http.post<RoleResponse>(
        `/api/organizations/${orgSlug}/roles`,
        payload
      );
      return response.data;
    },

    /**
     * Update an existing role.
     */
    update: async (
      orgSlug: string,
      roleId: string,
      payload: UpdateRoleRequest
    ): Promise<RoleResponse> => {
      const response = await this.http.put<RoleResponse>(
        `/api/organizations/${orgSlug}/roles/${roleId}`,
        payload
      );
      return response.data;
    },

    /**
     * Delete a role.
     */
    delete: async (orgSlug: string, roleId: string): Promise<void> => {
      await this.http.delete(`/api/organizations/${orgSlug}/roles/${roleId}`);
    },
  };

  // ============================================================================
  // BYOP - BRING YOUR OWN PAYMENT
  // ============================================================================

  /**
   * BYOP (Bring Your Own Payment) credential management.
   * Allows organizations to configure their own billing provider credentials
   * to charge their end-users directly.
   */
  public billingCredentials = {
    /**
     * Get the status of billing credentials for a provider.
     * Returns whether credentials are configured and the mode (test/live).
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param provider Billing provider ('stripe' or 'polar')
     * @returns Credential configuration status
     *
     * @example
     * ```typescript
     * const status = await sso.organizations.billingCredentials.get('acme-corp', 'stripe');
     * if (status.configured) {
     *   console.log('Mode:', status.mode); // 'test' or 'live'
     *   console.log('Enabled:', status.enabled);
     * }
     * ```
     */
    get: async (
      orgSlug: string,
      provider: 'stripe' | 'polar'
    ): Promise<{
      configured: boolean;
      provider: string;
      mode: 'test' | 'live' | null;
      enabled: boolean;
    }> => {
      const response = await this.http.get<{
        configured: boolean;
        provider: string;
        mode: 'test' | 'live' | null;
        enabled: boolean;
      }>(`/api/organizations/${orgSlug}/billing-credentials/${provider}`);
      return response.data;
    },

    /**
     * Set or update billing credentials for a provider.
     * Enables the organization to charge their end-users using their own
     * payment provider account.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param provider Billing provider ('stripe' or 'polar')
     * @param payload Billing credentials
     *
     * @example
     * ```typescript
     * await sso.organizations.billingCredentials.set('acme-corp', 'stripe', {
     *   api_key: 'sk_live_...',
     *   webhook_secret: 'whsec_...',
     *   mode: 'live'
     * });
     * ```
     */
    set: async (
      orgSlug: string,
      provider: 'stripe' | 'polar',
      payload: {
        api_key: string;
        webhook_secret: string;
        mode: 'test' | 'live';
      }
    ): Promise<void> => {
      await this.http.post(
        `/api/organizations/${orgSlug}/billing-credentials/${provider}`,
        payload
      );
    },

    /**
     * Delete billing credentials for a provider.
     * The organization will no longer be able to charge end-users directly.
     * Requires 'owner' role.
     *
     * @param orgSlug Organization slug
     * @param provider Billing provider ('stripe' or 'polar')
     *
     * @example
     * ```typescript
     * await sso.organizations.billingCredentials.delete('acme-corp', 'stripe');
     * ```
     */
    delete: async (
      orgSlug: string,
      provider: 'stripe' | 'polar'
    ): Promise<void> => {
      await this.http.delete(
        `/api/organizations/${orgSlug}/billing-credentials/${provider}`
      );
    },
  };
}
