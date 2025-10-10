import { HttpClient } from '../http';
import {
  Service,
  ServiceResponse,
  ServiceListResponse,
  CreateServicePayload,
  CreateServiceResponse,
  UpdateServicePayload,
  Plan,
  CreatePlanPayload,
} from '../types';

/**
 * Service management methods
 */
export class ServicesModule {
  constructor(private http: HttpClient) {}

  /**
   * Create a new service for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param payload Service creation payload
   * @returns Created service with details
   *
   * @example
   * ```typescript
   * const result = await sso.services.create('acme-corp', {
   *   slug: 'main-app',
   *   name: 'Main Application',
   *   service_type: 'web',
   *   github_scopes: ['user:email', 'read:org'],
   *   redirect_uris: ['https://app.acme.com/callback']
   * });
   * console.log(result.service.client_id);
   * ```
   */
  public async create(orgSlug: string, payload: CreateServicePayload): Promise<CreateServiceResponse> {
    const response = await this.http.post<CreateServiceResponse>(
      `/api/organizations/${orgSlug}/services`,
      payload
    );
    return response.data;
  }

  /**
   * List all services for an organization.
   *
   * @param orgSlug Organization slug
   * @returns Service list response with usage metadata
   *
   * @example
   * ```typescript
   * const result = await sso.services.list('acme-corp');
   * console.log(`Using ${result.usage.current_services} of ${result.usage.max_services} services`);
   * result.services.forEach(svc => console.log(svc.name, svc.client_id));
   * ```
   */
  public async list(orgSlug: string): Promise<ServiceListResponse> {
    const response = await this.http.get<ServiceListResponse>(`/api/organizations/${orgSlug}/services`);
    return response.data;
  }

  /**
   * Get detailed information for a specific service.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   * @returns Service with provider grants and plans
   *
   * @example
   * ```typescript
   * const service = await sso.services.get('acme-corp', 'main-app');
   * console.log(service.service.redirect_uris);
   * console.log(service.plans);
   * ```
   */
  public async get(orgSlug: string, serviceSlug: string): Promise<ServiceResponse> {
    const response = await this.http.get<ServiceResponse>(
      `/api/organizations/${orgSlug}/services/${serviceSlug}`
    );
    return response.data;
  }

  /**
   * Update service configuration.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   * @param payload Update payload
   * @returns Updated service
   *
   * @example
   * ```typescript
   * const updated = await sso.services.update('acme-corp', 'main-app', {
   *   name: 'Main Application v2',
   *   redirect_uris: ['https://app.acme.com/callback', 'https://app.acme.com/oauth']
   * });
   * ```
   */
  public async update(
    orgSlug: string,
    serviceSlug: string,
    payload: UpdateServicePayload
  ): Promise<Service> {
    const response = await this.http.patch<Service>(
      `/api/organizations/${orgSlug}/services/${serviceSlug}`,
      payload
    );
    return response.data;
  }

  /**
   * Delete a service.
   * Requires 'owner' role.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   *
   * @example
   * ```typescript
   * await sso.services.delete('acme-corp', 'old-app');
   * ```
   */
  public async delete(orgSlug: string, serviceSlug: string): Promise<void> {
    await this.http.delete(`/api/organizations/${orgSlug}/services/${serviceSlug}`);
  }

  /**
   * Plan management methods
   */
  public plans = {
    /**
     * Create a new subscription plan for a service.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param payload Plan creation payload
     * @returns Created plan
     *
     * @example
     * ```typescript
     * const plan = await sso.services.plans.create('acme-corp', 'main-app', {
     *   name: 'pro',
     *   description: 'Pro tier with advanced features',
     *   price_monthly: 29.99,
     *   features: ['api-access', 'advanced-analytics', 'priority-support']
     * });
     * ```
     */
    create: async (
      orgSlug: string,
      serviceSlug: string,
      payload: CreatePlanPayload
    ): Promise<Plan> => {
      const response = await this.http.post<Plan>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans`,
        payload
      );
      return response.data;
    },

    /**
     * List all plans for a service.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Array of plans
     *
     * @example
     * ```typescript
     * const plans = await sso.services.plans.list('acme-corp', 'main-app');
     * plans.forEach(plan => console.log(plan.name, plan.price_monthly));
     * ```
     */
    list: async (orgSlug: string, serviceSlug: string): Promise<Plan[]> => {
      const response = await this.http.get<Plan[]>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans`
      );
      return response.data;
    },
  };
}
