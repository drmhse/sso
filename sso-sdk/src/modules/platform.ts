import { HttpClient } from '../http';
import {
  Organization,
  PlatformOrganizationsListResponse,
  ListPlatformOrganizationsParams,
  ApproveOrganizationPayload,
  RejectOrganizationPayload,
  UpdateOrganizationTierPayload,
  PromotePlatformOwnerPayload,
  AuditLogEntry,
  GetAuditLogParams,
} from '../types';

/**
 * Platform owner administration methods.
 * All methods require a Platform Owner JWT.
 */
export class PlatformModule {
  constructor(private http: HttpClient) {}

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
}
