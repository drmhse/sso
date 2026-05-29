import type { JwtClaims } from '@drmhse/sso-sdk';

/**
 * Configuration options for the AuthOS Node.js adapter
 */
export interface AuthOSNodeOptions {
  /**
   * Base URL of the AuthOS API service
   */
  baseURL: string;

  /**
   * Cache TTL for JWKS in milliseconds. Default: 1 hour (3600000ms)
   */
  jwksCacheTTL?: number;

  /**
   * Required audience (aud) claim for application tokens.
   * Service tokens use the format `service:<org_slug>/<service_slug>`.
   */
  audience?: string;

  /**
   * Required issuer (iss) claim. Defaults to baseURL without a trailing slash.
   */
  issuer?: string;

  /**
   * Allow requireAuth() to run without an expected audience.
   * This is intended only for legacy migrations.
   */
  allowMissingAudience?: boolean;
}

/**
 * JSON Web Key structure
 */
export interface JWK {
  kty: string;
  kid: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
}

/**
 * JSON Web Key Set structure
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * Verified token result
 */
export interface VerifiedToken {
  /**
   * The decoded JWT claims
   */
  claims: JwtClaims;

  /**
   * The raw token string
   */
  token: string;
}

/**
 * Express request with auth context attached
 */
export interface AuthenticatedRequest {
  auth: VerifiedToken;
}

/**
 * Token verification options
 */
export interface VerifyTokenOptions {
  /**
   * Required audience (aud) claim
   */
  audience?: string;

  /**
   * Required issuer (iss) claim
   */
  issuer?: string;

  /**
   * Clock tolerance in seconds for exp/iat validation. Default: 0
   */
  clockTolerance?: number;
}

/**
 * Webhook verification options
 */
export interface WebhookVerifyOptions {
  /**
   * Tolerance window in milliseconds for timestamp validation. Default: 5 minutes (300000ms)
   */
  tolerance?: number;
}

/**
 * Express middleware options for requireAuth
 */
export interface RequireAuthOptions extends VerifyTokenOptions {
  /**
   * Custom function to extract token from request.
   * Default: extracts from Authorization: Bearer header
   */
  getToken?: (req: unknown) => string | null;
}

/**
 * Express middleware options for requirePermission
 */
export interface RequirePermissionOptions {
  /**
   * Custom 403 error message
   */
  message?: string;
}
