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
} from '../types';

/**
 * Platform owner administration methods.
 * All methods require a Platform Owner JWT.
 */
export class PlatformModule {
  constructor(private http: HttpClient) {}

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
}
