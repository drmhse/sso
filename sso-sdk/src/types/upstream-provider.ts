/**
 * Upstream Provider (Enterprise SSO) types
 */

export type UpstreamProviderType = 'oidc' | 'oauth2' | 'saml';

export interface UpstreamProvider {
  id: string;
  connection_id: string;
  name: string;
  provider_type: UpstreamProviderType;
  enabled: boolean;
  client_id: string;
  issuer: string | null;
  authorization_url: string | null;
  created_at: string;
}

export interface CreateUpstreamProviderPayload {
  connection_id: string;
  name: string;
  provider_type: UpstreamProviderType;
  client_id: string;
  client_secret?: string;
  issuer?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  discovery_url?: string;
  scopes?: string;
  metadata?: any;
  enabled?: boolean;
}

export interface UpdateUpstreamProviderPayload {
  name?: string;
  enabled?: boolean;
}
