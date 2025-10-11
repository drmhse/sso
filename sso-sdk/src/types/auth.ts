import { OAuthProvider } from './common';

/**
 * Device code request payload
 */
export interface DeviceCodeRequest {
  client_id: string;
  org: string;
  service: string;
}

/**
 * Device code response
 */
export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

/**
 * Device verify response - returns context for initiating OAuth flow
 */
export interface DeviceVerifyResponse {
  org_slug: string;
  service_slug: string;
  available_providers: string[];
}

/**
 * Token request payload for device flow
 */
export interface TokenRequest {
  grant_type: 'urn:ietf:params:oauth:grant-type:device_code';
  device_code: string;
  client_id: string;
}

/**
 * Token response
 */
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
}

/**
 * Parameters for constructing login URL
 */
export interface LoginUrlParams {
  /**
   * Organization slug
   */
  org: string;

  /**
   * Service slug
   */
  service: string;

  /**
   * Optional redirect URI (must be registered with the service)
   */
  redirect_uri?: string;

  /**
   * Optional user code for device flow authorization
   */
  user_code?: string;
}

/**
 * Parameters for constructing admin login URL
 */
export interface AdminLoginUrlParams {
  /**
   * Optional organization slug to manage
   */
  org_slug?: string;
  /**
   * Optional user code for device flow authorization
   */
  user_code?: string;
}

/**
 * Provider token response
 */
export interface ProviderToken {
  access_token: string;
  refresh_token?: string;
  expires_at: string;
  scopes: string[];
  provider: OAuthProvider;
}
