import { HttpClient } from '../http';
import {
  Organization,
  OrganizationTier,
  PlatformOrganizationsListResponse,
  ListPlatformOrganizationsParams,
  ApproveOrganizationPayload,
  RejectOrganizationPayload,
  UpdateOrganizationTierPayload,
  PromotePlatformOwnerPayload,
  AuditLogEntry,
  GetAuditLogParams,
  PlatformOverviewMetrics,
  OrganizationStatusBreakdown,
  GrowthTrendPoint,
  LoginActivityPoint,
  TopOrganization,
  RecentOrganization,
  PlatformAnalyticsDateRangeParams,
  ImpersonateRequest,
  ImpersonateResponse,
} from '../types';

/**
 * Platform owner administration methods.
 * All methods require a Platform Owner JWT.
 */
export class PlatformModule {
  constructor(private http: HttpClient) { }

  /**
   * List all available organization tiers.
   *
   * @returns Array of organization tiers
   *
   * @example
   * ```typescript
   * const tiers = await sso.platform.getTiers();
   * console.log(tiers); // [{ id: 'tier_free', display_name: 'Free Tier', ... }]
   * ```
   */
  public async getTiers(): Promise<OrganizationTier[]> {
    const response = await this.http.get<OrganizationTier[]>('/api/platform/tiers');
    return response.data;
  }

  /**
   * Organization management for platform owners
   */
  public organizations = {
    /**
     * List all organizations on the platform with optional filters.
     *
     * @param params Optional query parameters for filtering
     * @returns Platform organizations list with pagination info
     *
     * @example
     * ```typescript
     * const result = await sso.platform.organizations.list({
     *   status: 'pending',
     *   page: 1,
     *   limit: 50
     * });
     * console.log(result.total, result.organizations);
     * ```
     */
    list: async (params?: ListPlatformOrganizationsParams): Promise<PlatformOrganizationsListResponse> => {
      const response = await this.http.get<PlatformOrganizationsListResponse>(
        '/api/platform/organizations',
        { params }
      );
      return response.data;
    },

    /**
     * Approve a pending organization and assign it a tier.
     *
     * @param orgId Organization ID
     * @param payload Approval payload with tier assignment
     * @returns Approved organization
     *
     * @example
     * ```typescript
     * const approved = await sso.platform.organizations.approve('org-id', {
     *   tier_id: 'tier-starter'
     * });
     * ```
     */
    approve: async (
      orgId: string,
      payload: ApproveOrganizationPayload
    ): Promise<Organization> => {
      const response = await this.http.post<Organization>(
        `/api/platform/organizations/${orgId}/approve`,
        payload
      );
      return response.data;
    },

    /**
     * Reject a pending organization with a reason.
     *
     * @param orgId Organization ID
     * @param payload Rejection payload with reason
     * @returns Rejected organization
     *
     * @example
     * ```typescript
     * await sso.platform.organizations.reject('org-id', {
     *   reason: 'Does not meet platform requirements'
     * });
     * ```
     */
    reject: async (
      orgId: string,
      payload: RejectOrganizationPayload
    ): Promise<Organization> => {
      const response = await this.http.post<Organization>(
        `/api/platform/organizations/${orgId}/reject`,
        payload
      );
      return response.data;
    },

    /**
     * Suspend an active organization.
     *
     * @param orgId Organization ID
     * @returns Suspended organization
     *
     * @example
     * ```typescript
     * await sso.platform.organizations.suspend('org-id');
     * ```
     */
    suspend: async (orgId: string): Promise<Organization> => {
      const response = await this.http.post<Organization>(
        `/api/platform/organizations/${orgId}/suspend`
      );
      return response.data;
    },

    /**
     * Re-activate a suspended organization.
     *
     * @param orgId Organization ID
     * @returns Activated organization
     *
     * @example
     * ```typescript
     * await sso.platform.organizations.activate('org-id');
     * ```
     */
    activate: async (orgId: string): Promise<Organization> => {
      const response = await this.http.post<Organization>(
        `/api/platform/organizations/${orgId}/activate`
      );
      return response.data;
    },

    /**
     * Update an organization's tier and resource limits.
     *
     * @param orgId Organization ID
     * @param payload Tier update payload
     * @returns Updated organization
     *
     * @example
     * ```typescript
     * await sso.platform.organizations.updateTier('org-id', {
     *   tier_id: 'tier-pro',
     *   max_services: 20,
     *   max_users: 100
     * });
     * ```
     */
    updateTier: async (
      orgId: string,
      payload: UpdateOrganizationTierPayload
    ): Promise<Organization> => {
      const response = await this.http.patch<Organization>(
        `/api/platform/organizations/${orgId}/tier`,
        payload
      );
      return response.data;
    },

    /**
     * Update an organization's feature overrides.
     *
     * @param orgId Organization ID
     * @param payload Feature override flags
     * @returns Updated organization
     *
     * @example
     * ```typescript
     * await sso.platform.organizations.updateFeatures('org-id', {
     *   allow_saml: true,
     *   allow_scim: false,
     *   allow_custom_domain: true,
     *   allow_custom_branding: false
     * });
     * ```
     */
    updateFeatures: async (
      orgId: string,
      payload: {
        allow_saml?: boolean;
        allow_saml_idp?: boolean;
        allow_scim?: boolean;
        allow_custom_domain?: boolean;
        allow_custom_branding?: boolean;
        allow_branding?: boolean;
        allow_advanced_risk_engine?: boolean;
        allow_siem_integration?: boolean;
        allow_siem?: boolean;
        allow_webhooks?: boolean;
        allow_passkeys?: boolean;
        allow_overage?: boolean;
      }
    ): Promise<Organization> => {
      const response = await this.http.patch<Organization>(
        `/api/platform/organizations/${orgId}/features`,
        payload
      );
      return response.data;
    },

    /**
     * Delete an organization and all its associated data.
     * This is a destructive operation that cannot be undone.
     * Only platform owners can delete organizations.
     *
     * All related data will be cascaded deleted including:
     * - Members and invitations
     * - Services and plans
     * - Subscriptions
     * - OAuth credentials
     * - Audit logs
     *
     * @param orgId Organization ID
     * @returns Success confirmation
     *
     * @example
     * ```typescript
     * const result = await sso.platform.organizations.delete('org-id');
     * console.log(result.message); // 'Organization deleted successfully'
     * ```
     */
    delete: async (orgId: string): Promise<{ success: boolean, message: string }> => {
      const response = await this.http.delete<{ success: boolean, message: string }>(
        `/api/platform/organizations/${orgId}`
      );
      return response.data;
    },
  };

  /**
   * Promote an existing user to platform owner.
   *
   * @param payload Promotion payload with user ID
   *
   * @example
   * ```typescript
   * await sso.platform.promoteOwner({
   *   user_id: 'user-uuid-here'
   * });
   * ```
   */
  public async promoteOwner(payload: PromotePlatformOwnerPayload): Promise<void> {
    await this.http.post('/api/platform/owners', payload);
  }

  /**
   * Demote a platform owner to regular user.
   *
   * @param userId The ID of the user to demote
   *
   * @example
   * ```typescript
   * await sso.platform.demoteOwner('user-uuid-here');
   * ```
   */
  public async demoteOwner(userId: string): Promise<void> {
    await this.http.delete(`/api/platform/owners/${userId}`);
  }

  /**
   * User MFA management methods for platform administrators
   */
  public users = {
    /**
     * Get MFA status for a specific user.
     *
     * @param userId The ID of the user
     * @returns MFA status information
     *
     * @example
     * ```typescript
     * const mfaStatus = await sso.platform.users.getMfaStatus('user-uuid-here');
     * console.log(mfaStatus.enabled, mfaStatus.has_backup_codes);
     * ```
     */
    getMfaStatus: async (userId: string): Promise<{ enabled: boolean, has_backup_codes: boolean }> => {
      const response = await this.http.get<{ enabled: boolean, has_backup_codes: boolean }>(`/api/platform/users/${userId}/mfa/status`);
      return response.data;
    },

    /**
     * List all users on the platform with pagination.
     *
     * @param options Pagination options
     * @returns List of users and total count
     *
     * @example
     * ```typescript
     * const result = await sso.platform.users.list({ limit: 10, offset: 0 });
     * console.log(result.users);
     * ```
     */
    list: async (options?: { limit?: number; offset?: number }): Promise<import('../types/platform').PlatformUserListResponse> => {
      const response = await this.http.get<import('../types/platform').PlatformUserListResponse>('/api/platform/users', { params: options });
      return response.data;
    },

    /**
     * Get a single platform user by ID.
     */
    get: async (userId: string): Promise<{
      id: string;
      email: string;
      is_platform_owner: boolean;
      created_at: string;
    }> => {
      const response = await this.http.get<{
        id: string;
        email: string;
        is_platform_owner: boolean;
        created_at: string;
      }>(`/api/platform/users/${userId}`);
      return response.data;
    },

    /**
     * Search users by email address or user ID.
     *
     * @param query The search query (email or user ID)
     * @param limit Optional maximum number of results (default: 10, max: 50)
     * @returns Array of matching users
     *
     * @example
     * ```typescript
     * const users = await sso.platform.users.search('john@example.com');
     * console.log(users); // [{ id: 'user-uuid', email: 'john@example.com', ... }]
     *
     * // Search by user ID
     * const users = await sso.platform.users.search('user-uuid-here');
     *
     * // Limit results
     * const users = await sso.platform.users.search('john@', { limit: 5 });
     * ```
     */
    search: async (query: string, options?: { limit?: number }): Promise<Array<{
      id: string;
      email: string;
      is_platform_owner: boolean;
      created_at: string;
    }>> => {
      const params = {
        q: query.trim(),
        limit: options?.limit ? Math.min(options.limit, 50) : undefined
      };

      const response = await this.http.get<Array<{
        id: string;
        email: string;
        is_platform_owner: boolean;
        created_at: string;
      }>>('/api/platform/users/search', { params });

      return response.data;
    },

    /**
     * Force disable MFA for a user (emergency access).
     *
     * @param userId The ID of the user
     * @returns Success confirmation
     *
     * @example
     * ```typescript
     * await sso.platform.users.forceDisableMfa('user-uuid-here');
     * console.log('MFA disabled for user');
     * ```
     */
    forceDisableMfa: async (userId: string): Promise<{ success: boolean, message: string }> => {
      const response = await this.http.delete<{ success: boolean, message: string }>(`/api/platform/users/${userId}/mfa`);
      return response.data;
    },
  };

  /**
   * Retrieve the platform-wide audit log with optional filters.
   *
   * @param params Optional query parameters for filtering
   * @returns Array of audit log entries
   *
   * @example
   * ```typescript
   * const logs = await sso.platform.getAuditLog({
   *   action: 'organization.approved',
   *   start_date: '2024-01-01',
   *   limit: 100
   * });
   * ```
   */
  public async getAuditLog(params?: GetAuditLogParams): Promise<AuditLogEntry[]> {
    const response = await this.http.get<AuditLogEntry[]>('/api/platform/audit-log', { params });
    return response.data;
  }

  /**
   * Platform analytics methods
   */
  public analytics = {
    /**
     * Get platform overview metrics.
     *
     * @returns Platform overview metrics
     *
     * @example
     * ```typescript
     * const metrics = await sso.platform.analytics.getOverview();
     * console.log(metrics.total_organizations, metrics.total_users);
     * ```
     */
    getOverview: async (): Promise<PlatformOverviewMetrics> => {
      const response = await this.http.get<PlatformOverviewMetrics>('/api/platform/analytics/overview');
      return response.data;
    },

    /**
     * Get organization status breakdown.
     *
     * @returns Organization count by status
     *
     * @example
     * ```typescript
     * const breakdown = await sso.platform.analytics.getOrganizationStatus();
     * console.log(breakdown.pending, breakdown.active);
     * ```
     */
    getOrganizationStatus: async (): Promise<OrganizationStatusBreakdown> => {
      const response = await this.http.get<OrganizationStatusBreakdown>(
        '/api/platform/analytics/organization-status'
      );
      return response.data;
    },

    /**
     * Get platform growth trends over time.
     *
     * @param params Optional date range parameters
     * @returns Array of growth trend data points
     *
     * @example
     * ```typescript
     * const trends = await sso.platform.analytics.getGrowthTrends({
     *   start_date: '2024-01-01',
     *   end_date: '2024-01-31'
     * });
     * ```
     */
    getGrowthTrends: async (params?: PlatformAnalyticsDateRangeParams): Promise<GrowthTrendPoint[]> => {
      const response = await this.http.get<GrowthTrendPoint[]>(
        '/api/platform/analytics/growth-trends',
        { params }
      );
      return response.data;
    },

    /**
     * Get platform-wide login activity trends.
     *
     * @param params Optional date range parameters
     * @returns Array of login activity data points
     *
     * @example
     * ```typescript
     * const activity = await sso.platform.analytics.getLoginActivity({
     *   start_date: '2024-01-01',
     *   end_date: '2024-01-31'
     * });
     * ```
     */
    getLoginActivity: async (params?: PlatformAnalyticsDateRangeParams): Promise<LoginActivityPoint[]> => {
      const response = await this.http.get<LoginActivityPoint[]>(
        '/api/platform/analytics/login-activity',
        { params }
      );
      return response.data;
    },

    /**
     * Get top organizations by activity.
     *
     * @returns Array of top organizations
     *
     * @example
     * ```typescript
     * const topOrgs = await sso.platform.analytics.getTopOrganizations();
     * console.log(topOrgs[0].login_count_30d);
     * ```
     */
    getTopOrganizations: async (): Promise<TopOrganization[]> => {
      const response = await this.http.get<TopOrganization[]>(
        '/api/platform/analytics/top-organizations'
      );
      return response.data;
    },

    /**
     * Get recently created organizations.
     *
     * @param params Optional query parameters
     * @returns Array of recent organizations
     *
     * @example
     * ```typescript
     * const recent = await sso.platform.analytics.getRecentOrganizations({
     *   limit: 10
     * });
     * ```
     */
    getRecentOrganizations: async (params?: GetAuditLogParams): Promise<RecentOrganization[]> => {
      const response = await this.http.get<RecentOrganization[]>(
        '/api/platform/analytics/recent-organizations',
        { params }
      );
      return response.data;
    },
  };

  /**
   * Impersonate a user (Platform Owner or Org Admin only).
   * Returns a short-lived JWT (15 minutes) that allows acting as the target user.
   *
   * Security:
   * - Platform Owners can impersonate any user
   * - Organization Admins can only impersonate users within their organization
   * - All impersonation actions are logged to the platform audit log with HIGH severity
   * - Tokens contain RFC 8693 actor claim for full audit trail
   *
   * @param payload Impersonation details (user_id and reason)
   * @returns Impersonation token and user context
   *
   * @example
   * ```typescript
   * const result = await sso.platform.impersonateUser({
   *   user_id: 'user-uuid-123',
   *   reason: 'Investigating support ticket #456'
   * });
   *
   * // Use the returned token to create a new client acting as the user
   * const userClient = new SsoClient({
   *   baseURL: 'https://sso.example.com',
   *   token: result.token
   * });
   *
   * // Now all requests with userClient are made as the target user
   * const profile = await userClient.user.getProfile();
   * console.log('Acting as:', result.target_user.email);
   * ```
   */
  public async impersonateUser(payload: ImpersonateRequest): Promise<ImpersonateResponse> {
    const response = await this.http.post<ImpersonateResponse>('/api/platform/impersonate', payload);
    return response.data;
  }

  /**
   * Get platform operational counters for jobs, webhooks, and SIEM delivery.
   */
  public async getOperationsStatus(): Promise<{
    jobs_pending: number;
    jobs_running: number;
    jobs_failed: number;
    webhook_deliveries_failed: number;
    siem_configs_enabled: number;
    siem_configs_with_failures: number;
  }> {
    const response = await this.http.get<{
      jobs_pending: number;
      jobs_running: number;
      jobs_failed: number;
      webhook_deliveries_failed: number;
      siem_configs_enabled: number;
      siem_configs_with_failures: number;
    }>('/api/platform/operations/status');
    return response.data;
  }
}
