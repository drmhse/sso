import { OAuthProvider } from './common';
import { RiskAssessment } from './risk';

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

  /**
   * Optional connection ID for enterprise IdP routing (from HRD lookup).
   * When provided, routes user to specific upstream provider instead of using default OAuth.
   * Example: "azure-ad-connection", "okta-enterprise"
   */
  connection_id?: string;
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

/**
 * Refresh token request payload
 */
export interface RefreshTokenRequest {
  refresh_token: string;
}

/**
 * Refresh token response
 */
export interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  /**
   * Risk assessment details (only present if risk engine is enabled)
   */
  risk_assessment?: RiskAssessment;
}

/**
 * Registration request payload
 */
export interface RegisterRequest {
  email: string;
  password: string;
  org_slug?: string; // Optional: use organization-specific SMTP
}

/**
 * Registration response
 */
export interface RegisterResponse {
  message: string;
}

/**
 * Login request payload
 */
export interface LoginRequest {
  email: string;
  password: string;
}

/**
 * Forgot password request payload
 */
export interface ForgotPasswordRequest {
  email: string;
  org_slug?: string; // Optional: use organization-specific SMTP
}

/**
 * Forgot password response
 */
export interface ForgotPasswordResponse {
  message: string;
}

/**
 * Reset password request payload
 */
export interface ResetPasswordRequest {
  token: string;
  new_password: string;
}

/**
 * Reset password response
 */
export interface ResetPasswordResponse {
  message: string;
}

/**
 * Resend verification request payload
 */
export interface ResendVerificationRequest {
  email: string;
}

/**
 * Resend verification response
 */
export interface ResendVerificationResponse {
  message: string;
}

/**
 * MFA verification request payload
 */
export interface MfaVerificationRequest {
  preauth_token: string;
  code: string;
}

/**
 * MFA verification response (same as refresh token response)
 */
export interface MfaVerificationResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * Home Realm Discovery (HRD) request payload
 */
export interface LookupEmailRequest {
  /**
   * Email address to lookup
   */
  email: string;
}

/**
 * Home Realm Discovery (HRD) response
 */
export interface LookupEmailResponse {
  /**
   * The connection ID to use for authentication, if any.
   * If present, use this to route the user to their enterprise IdP.
   */
  connection_id: string | null;

  /**
   * The name of the upstream provider, for display purposes.
   * Example: "Acme Corp Azure AD", "Partner Okta"
   */
  provider_name: string | null;

  /**
   * Whether the email domain is verified.
   * true = domain is verified and owned by an organization
   * false = domain is not verified, use default auth flow
   */
  domain_verified: boolean;

  /**
   * The authentication method to use:
   * - "upstream": Route to enterprise IdP via connection_id
   * - "password": Use email/password authentication
   * - "oauth": Use default OAuth providers (GitHub, Google, Microsoft)
   */
  auth_method: 'upstream' | 'password' | 'oauth';
}
