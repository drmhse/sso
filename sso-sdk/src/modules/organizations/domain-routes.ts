import { HttpClient } from '../../http';
import {
  DomainRoute,
  CreateDomainRoutePayload,
  UpdateDomainRoutePayload,
} from '../../types';

/**
 * Upstream domain routing (Home Realm Discovery).
 *
 * A route claims an email domain for an organization and decides which identity
 * provider its users authenticate with. A route only takes effect once
 * {@link DomainRoutesModule.verify} confirms the DNS TXT record, so a tenant
 * cannot capture logins for a domain it does not control.
 */
export class DomainRoutesModule {
  constructor(private http: HttpClient) {}

  /**
   * List the organization's domain routes.
   *
   * @param orgSlug Organization slug
   * @returns Every route, verified or not
   *
   * @example
   * ```typescript
   * const routes = await sso.organizations.domainRoutes.list('acme');
   * const pending = routes.filter((route) => !route.verified);
   * ```
   */
  public async list(orgSlug: string): Promise<DomainRoute[]> {
    const response = await this.http.get<DomainRoute[]>(
      `/api/organizations/${orgSlug}/domain-routes`
    );
    return response.data;
  }

  /**
   * Claim a domain for the organization.
   *
   * The route is created unverified and carries the `verification_token` to
   * publish as a DNS TXT record before calling {@link verify}.
   *
   * @param orgSlug Organization slug
   * @param payload Domain, optional upstream provider, and login policy
   * @returns The created route, including its verification token
   *
   * @example
   * ```typescript
   * const route = await sso.organizations.domainRoutes.create('acme', {
   *   domain: 'acme.com',
   *   upstream_provider_id: 'prov_123',
   *   login_policy: 'upstream_only',
   * });
   * console.log(route.verification_token);
   * ```
   */
  public async create(
    orgSlug: string,
    payload: CreateDomainRoutePayload
  ): Promise<DomainRoute> {
    const response = await this.http.post<DomainRoute>(
      `/api/organizations/${orgSlug}/domain-routes`,
      payload
    );
    return response.data;
  }

  /**
   * Update a route's provider mapping or login policy.
   *
   * @param orgSlug Organization slug
   * @param domainId Domain route id
   * @param payload Fields to change
   * @returns The updated route
   */
  public async update(
    orgSlug: string,
    domainId: string,
    payload: UpdateDomainRoutePayload
  ): Promise<DomainRoute> {
    const response = await this.http.patch<DomainRoute>(
      `/api/organizations/${orgSlug}/domain-routes/${domainId}`,
      payload
    );
    return response.data;
  }

  /**
   * Re-check the DNS TXT record and mark the route verified if it matches.
   *
   * @param orgSlug Organization slug
   * @param domainId Domain route id
   * @returns The route with its current verification state
   *
   * @example
   * ```typescript
   * const route = await sso.organizations.domainRoutes.verify('acme', 'dr_1');
   * if (!route.verified) console.log('TXT record not visible yet');
   * ```
   */
  public async verify(orgSlug: string, domainId: string): Promise<DomainRoute> {
    const response = await this.http.post<DomainRoute>(
      `/api/organizations/${orgSlug}/domain-routes/${domainId}/verify`
    );
    return response.data;
  }

  /**
   * Remove a domain route. Users on that domain fall back to local auth.
   *
   * @param orgSlug Organization slug
   * @param domainId Domain route id
   */
  public async delete(orgSlug: string, domainId: string): Promise<void> {
    await this.http.delete(
      `/api/organizations/${orgSlug}/domain-routes/${domainId}`
    );
  }
}
