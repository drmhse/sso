import { HttpClient } from '../../http';
import {
  UpstreamProvider,
  CreateUpstreamProviderPayload,
  UpdateUpstreamProviderPayload,
} from '../../types';

/**
 * Upstream Provider (Enterprise SSO) management methods
 */
export class UpstreamProvidersModule {
  constructor(private http: HttpClient) {}

  /**
   * List all upstream providers for an organization.
   *
   * @param orgSlug Organization slug
   * @returns Array of upstream providers
   */
  public async list(orgSlug: string): Promise<UpstreamProvider[]> {
    const response = await this.http.get<UpstreamProvider[]>(
      `/api/organizations/${orgSlug}/upstream-providers`
    );
    return response.data;
  }

  /**
   * Get a specific upstream provider.
   *
   * @param orgSlug Organization slug
   * @param providerId Provider ID
   * @returns Upstream provider details
   */
  public async get(orgSlug: string, providerId: string): Promise<UpstreamProvider> {
    const response = await this.http.get<UpstreamProvider>(
      `/api/organizations/${orgSlug}/upstream-providers/${providerId}`
    );
    return response.data;
  }

  /**
   * Create a new upstream provider.
   *
   * @param orgSlug Organization slug
   * @param payload Provider configuration
   * @returns Created upstream provider
   */
  public async create(
    orgSlug: string,
    payload: CreateUpstreamProviderPayload
  ): Promise<UpstreamProvider> {
    const response = await this.http.post<UpstreamProvider>(
      `/api/organizations/${orgSlug}/upstream-providers`,
      payload
    );
    return response.data;
  }

  /**
   * Update an existing upstream provider.
   *
   * @param orgSlug Organization slug
   * @param providerId Provider ID
   * @param payload Update payload
   * @returns Updated upstream provider
   */
  public async update(
    orgSlug: string,
    providerId: string,
    payload: UpdateUpstreamProviderPayload
  ): Promise<UpstreamProvider> {
    const response = await this.http.patch<UpstreamProvider>(
      `/api/organizations/${orgSlug}/upstream-providers/${providerId}`,
      payload
    );
    return response.data;
  }

  /**
   * Delete an upstream provider.
   *
   * @param orgSlug Organization slug
   * @param providerId Provider ID or connection_id
   */
  public async delete(orgSlug: string, providerId: string): Promise<void> {
    await this.http.delete(`/api/organizations/${orgSlug}/upstream-providers/${providerId}`);
  }
}
