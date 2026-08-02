import { HttpClient } from '../http';
import { ExportUserDataResponse, ForgetUserRequest, ForgetUserResponse } from '../types';

/**
 * Privacy and GDPR compliance methods
 */
export class PrivacyModule {
  constructor(private http: HttpClient) {}

  /**
   * Export all user data (GDPR Right to Access).
   * Users can export their own data. Cross-user export requires platform-owner
   * authority or ownership of every organization the target belongs to.
   *
   * @param userId User ID to export data for
   * @returns Complete user data export including memberships, login events, identities, MFA events, and passkeys
   *
   * @example
   * ```typescript
   * const userData = await sso.privacy.exportData('user-id');
   * console.log(`Exported ${userData.login_events_count} login events`);
   * console.log(`User has ${userData.memberships.length} organization memberships`);
   * ```
   */
  public async exportData(userId: string): Promise<ExportUserDataResponse> {
    const response = await this.http.get<ExportUserDataResponse>(`/api/privacy/export/${userId}`);
    return response.data;
  }

  /**
   * Anonymize user data (GDPR Right to be Forgotten).
   * Cross-user anonymization requires platform-owner authority or ownership of
   * every organization the target belongs to. Self-service anonymization
   * requires a current password or MFA code.
   * Platform owners cannot be anonymized.
   *
   * This operation:
   * - Soft-deletes the user account
   * - Hard-deletes PII from identities and passkeys tables
   * - Preserves audit logs for compliance
   *
   * @param userId User ID to anonymize
   * @returns Anonymization confirmation response
   *
   * @example
   * ```typescript
   * const result = await sso.privacy.forgetUser('user-id');
   * console.log(result.message);
   * // "User data has been anonymized. PII has been removed while preserving audit logs."
   * ```
   */
  public async forgetUser(
    userId: string,
    payload: ForgetUserRequest = {}
  ): Promise<ForgetUserResponse> {
    const response = await this.http.delete<ForgetUserResponse>(
      `/api/privacy/forget/${userId}`,
      payload
    );
    return response.data;
  }
}
