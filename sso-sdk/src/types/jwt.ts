/**
 * JWT Claims payload structure
 */
export interface JwtClaims {
  /**
   * Subject - the user ID
   */
  sub: string;

  /**
   * User's email address
   */
  email: string;

  /**
   * Whether the user is a platform owner
   */
  is_platform_owner: boolean;

  /**
   * Organization slug (present in Org and Service JWTs)
   */
  org?: string;

  /**
   * Service slug (present only in Service JWTs)
   */
  service?: string;

  /**
   * Subscription plan name
   */
  plan?: string;

  /**
   * List of enabled features
   */
  features?: string[];

  /**
   * Expiration timestamp (Unix epoch)
   */
  exp: number;

  /**
   * Issued at timestamp (Unix epoch)
   */
  iat: number;
}
