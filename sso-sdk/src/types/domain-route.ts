/**
 * Upstream domain routing: maps a verified email domain to the identity
 * provider its users must authenticate with (Home Realm Discovery).
 */

/**
 * How users on a routed domain are allowed to authenticate.
 *
 * - `password_allowed` - local password login stays available.
 * - `upstream_only` - only the mapped upstream provider is accepted.
 * - `password_fallback_if_provider_unavailable` - upstream first, local
 *   password only while the provider cannot be reached.
 */
export type DomainLoginPolicy =
  | 'password_allowed'
  | 'upstream_only'
  | 'password_fallback_if_provider_unavailable';

export interface DomainRoute {
  id: string;
  domain: string;
  /** Mapped upstream provider, or `null` when the domain is routed to local auth. */
  upstream_provider_id: string | null;
  login_policy: DomainLoginPolicy;
  /** DNS TXT value that must be published to prove domain ownership. */
  verification_token: string;
  verified: boolean;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateDomainRoutePayload {
  domain: string;
  upstream_provider_id?: string | null;
  login_policy?: DomainLoginPolicy;
}

export interface UpdateDomainRoutePayload {
  upstream_provider_id?: string | null;
  login_policy?: DomainLoginPolicy;
}
