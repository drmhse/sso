import { HttpClient } from '../http';
import {
  LoginTrendPoint,
  LoginsByService,
  LoginsByProvider,
  RecentLogin,
  AnalyticsQuery,
} from '../types';

/**
 * Analytics and login tracking methods
 */
export class AnalyticsModule {
  constructor(private http: HttpClient) {}

  /**
   * Get login trends over time.
   * Returns daily login counts grouped by date.
   *
   * @param orgSlug Organization slug
   * @param params Optional query parameters (date range)
   * @returns Array of login trend data points
   *
   * @example
   * ```typescript
   * const trends = await sso.analytics.getLoginTrends('acme-corp', {
   *   start_date: '2025-01-01',
   *   end_date: '2025-01-31'
   * });
   * trends.forEach(point => console.log(point.date, point.count));
   * ```
   */
  public async getLoginTrends(
    orgSlug: string,
    params?: AnalyticsQuery
  ): Promise<LoginTrendPoint[]> {
    const response = await this.http.get<LoginTrendPoint[]>(
      `/api/organizations/${orgSlug}/analytics/login-trends`,
      { params }
    );
    return response.data;
  }

  /**
   * Get login counts grouped by service.
   * Shows which services have the most authentication activity.
   *
   * @param orgSlug Organization slug
   * @param params Optional query parameters (date range)
   * @returns Array of login counts per service
   *
   * @example
   * ```typescript
   * const byService = await sso.analytics.getLoginsByService('acme-corp', {
   *   start_date: '2025-01-01',
   *   end_date: '2025-01-31'
   * });
   * byService.forEach(s => console.log(s.service_name, s.count));
   * ```
   */
  public async getLoginsByService(
    orgSlug: string,
    params?: AnalyticsQuery
  ): Promise<LoginsByService[]> {
    const response = await this.http.get<LoginsByService[]>(
      `/api/organizations/${orgSlug}/analytics/logins-by-service`,
      { params }
    );
    return response.data;
  }

  /**
   * Get login counts grouped by OAuth provider.
   * Shows which authentication providers are being used (GitHub, Google, Microsoft).
   *
   * @param orgSlug Organization slug
   * @param params Optional query parameters (date range)
   * @returns Array of login counts per provider
   *
   * @example
   * ```typescript
   * const byProvider = await sso.analytics.getLoginsByProvider('acme-corp', {
   *   start_date: '2025-01-01',
   *   end_date: '2025-01-31'
   * });
   * byProvider.forEach(p => console.log(p.provider, p.count));
   * ```
   */
  public async getLoginsByProvider(
    orgSlug: string,
    params?: AnalyticsQuery
  ): Promise<LoginsByProvider[]> {
    const response = await this.http.get<LoginsByProvider[]>(
      `/api/organizations/${orgSlug}/analytics/logins-by-provider`,
      { params }
    );
    return response.data;
  }

  /**
   * Get the most recent login events.
   *
   * @param orgSlug Organization slug
   * @param params Optional query parameters (limit)
   * @returns Array of recent login events
   *
   * @example
   * ```typescript
   * const recentLogins = await sso.analytics.getRecentLogins('acme-corp', {
   *   limit: 10
   * });
   * recentLogins.forEach(login => {
   *   console.log(login.user_id, login.provider, login.created_at);
   * });
   * ```
   */
  public async getRecentLogins(
    orgSlug: string,
    params?: AnalyticsQuery
  ): Promise<RecentLogin[]> {
    const response = await this.http.get<RecentLogin[]>(
      `/api/organizations/${orgSlug}/analytics/recent-logins`,
      { params }
    );
    return response.data;
  }
}
