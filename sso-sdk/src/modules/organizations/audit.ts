import { HttpClient } from '../../http';
import {
  AuditLogResponse,
  EventTypeInfo,
  AuditLogQueryParams,
} from '../../types';

/**
 * Organization audit logs management methods
 */
export class AuditLogsModule {
  constructor(private http: HttpClient) {}

  /**
   * Get audit logs for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param params Optional query parameters for filtering and pagination
   * @returns Paginated audit log response
   *
   * @example
   * ```typescript
   * // Get all audit logs
   * const logs = await sso.organizations.auditLogs.get('acme-corp');
   *
   * // Filter by specific action
   * const userLogs = await sso.organizations.auditLogs.get('acme-corp', {
   *   action: 'user.role_updated',
   *   page: 1,
   *   limit: 20
   * });
   *
   * // Filter by target
   * const serviceLogs = await sso.organizations.auditLogs.get('acme-corp', {
   *   target_type: 'service',
   *   target_id: 'service-123'
   * });
   * ```
   */
  public async get(
    orgSlug: string,
    params?: AuditLogQueryParams
  ): Promise<AuditLogResponse> {
    const response = await this.http.get<AuditLogResponse>(
      `/api/organizations/${orgSlug}/audit-log`,
      { params }
    );
    return response.data;
  }

  /**
   * Get available audit event types for filtering.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @returns Array of event type information
   *
   * @example
   * ```typescript
   * const eventTypes = await sso.organizations.auditLogs.getEventTypes('acme-corp');
   *
   * // Group by category for UI display
   * const byCategory = eventTypes.reduce((acc, event) => {
   *   if (!acc[event.category]) {
   *     acc[event.category] = [];
   *   }
   *   acc[event.category].push(event);
   *   return acc;
   * }, {});
   * ```
   */
  public async getEventTypes(orgSlug: string): Promise<EventTypeInfo[]> {
    const response = await this.http.get<EventTypeInfo[]>(
      `/api/organizations/${orgSlug}/audit-log/event-types`
    );
    return response.data;
  }
}