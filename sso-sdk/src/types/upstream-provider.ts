/**
 * Upstream Provider (Enterprise SSO) types
 */

export type UpstreamProviderType = 'oidc' | 'oauth2' | 'saml';

export interface UpstreamProvider {
  id: string;
  org_id: string;
  connection_id: string;
  name: string;
  provider_type: UpstreamProviderType;
  enabled: boolean;
  client_id: string;
  issuer?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  discovery_url?: string;
  scopes?: string;
  metadata?: any;
  created_at: string;
  updated_at: string;
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
  client_id?: string;
  client_secret?: string;
  issuer?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  discovery_url?: string;
  scopes?: string;
  metadata?: any;
}
