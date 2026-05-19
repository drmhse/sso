/**
 * Standard authentication error codes returned by the AuthOS API.
 * Use these to reliably switch UI states based on error type.
 */
export enum AuthErrorCodes {
  /** Multi-factor authentication is required to complete login */
  MFA_REQUIRED = 'MFA_REQUIRED',
  /** User must select or create an organization */
  ORG_REQUIRED = 'ORG_REQUIRED',
  /** The provided credentials are invalid */
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  /** The refresh token is invalid or has been revoked */
  REFRESH_TOKEN_INVALID = 'REFRESH_TOKEN_INVALID',
  /** The requested resource was not found */
  NOT_FOUND = 'NOT_FOUND',
  /** The user is not authorized to perform this action */
  UNAUTHORIZED = 'UNAUTHORIZED',
  /** The user does not have permission for this resource */
  FORBIDDEN = 'FORBIDDEN',
  /** The JWT token has expired */
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  /** The request failed validation */
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  /** The email address is already registered */
  EMAIL_ALREADY_EXISTS = 'EMAIL_ALREADY_EXISTS',
  /** Email verification is required */
  EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED',
  /** The account has been suspended */
  ACCOUNT_SUSPENDED = 'ACCOUNT_SUSPENDED',
  /** The organization has been suspended */
  ORG_SUSPENDED = 'ORG_SUSPENDED',
  /** The request failed validation or is malformed */
  BAD_REQUEST = 'BAD_REQUEST',
  /** A resource with this information already exists */
  DUPLICATE_CONSTRAINT = 'DUPLICATE_CONSTRAINT',
  /** Organization is pending approval or suspended */
  ORGANIZATION_NOT_ACTIVE = 'ORGANIZATION_NOT_ACTIVE',
  /** Service creation limit reached for organization tier */
  SERVICE_LIMIT_EXCEEDED = 'SERVICE_LIMIT_EXCEEDED',
  /** Team member limit reached for organization tier */
  TEAM_LIMIT_EXCEEDED = 'TEAM_LIMIT_EXCEEDED',
  /** Invitation link has expired */
  INVITATION_EXPIRED = 'INVITATION_EXPIRED',
  /** The magic link or verification token has expired */
  LINK_EXPIRED = 'LINK_EXPIRED',
  /** Device code for headless authentication has expired */
  DEVICE_CODE_EXPIRED = 'DEVICE_CODE_EXPIRED',
  /** Authorization is still pending (device flow) */
  AUTHORIZATION_PENDING = 'AUTHORIZATION_PENDING',
  DEVICE_CODE_PENDING = 'DEVICE_CODE_PENDING',
  /** Feature not available in organization's current tier */
  FEATURE_NOT_AVAILABLE_IN_TIER = 'FEATURE_NOT_AVAILABLE_IN_TIER',
  /** Rate limit exceeded */
  RATE_LIMITED = 'RATE_LIMITED',
  TOO_MANY_REQUESTS = 'TOO_MANY_REQUESTS',
  /** The password does not meet requirements */
  WEAK_PASSWORD = 'WEAK_PASSWORD',
  /** The MFA code is invalid */
  INVALID_MFA_CODE = 'INVALID_MFA_CODE',
  /** Malformed or invalid JWT token */
  JWT_ERROR = 'JWT_ERROR',
  /** Unexpected server error */
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  /** OAuth provider communication failed */
  OAUTH_ERROR = 'OAUTH_ERROR',
  /** The passkey authentication failed */
  PASSKEY_ERROR = 'PASSKEY_ERROR',
  /** Billing system error */
  STRIPE_ERROR = 'STRIPE_ERROR',
  /** General database operation failed */
  DATABASE_ERROR = 'DATABASE_ERROR',
  /** General system error */
  GENERIC_ERROR = 'GENERIC_ERROR',
}

/**
 * Custom error class for SSO API errors.
 * Provides structured error information from the API.
 */
export class SsoApiError extends Error {
  /**
   * The HTTP status code of the error response.
   */
  public readonly statusCode: number;

  /**
   * The specific error code returned by the API.
   */
  public readonly errorCode: string;

  /**
   * ISO 8601 timestamp when the error occurred.
   */
  public readonly timestamp: string;

  constructor(message: string, statusCode: number, errorCode: string, timestamp: string) {
    super(message);
    this.name = 'SsoApiError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.timestamp = timestamp;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SsoApiError);
    }
  }

  /**
   * Check if the error is a specific error code.
   */
  public is(errorCode: string): boolean {
    return this.errorCode === errorCode;
  }

  /**
   * Check if the error is an authentication error.
   */
  public isAuthError(): boolean {
    return this.statusCode === 401 || this.errorCode === 'UNAUTHORIZED' || this.errorCode === 'TOKEN_EXPIRED';
  }

  /**
   * Check if the error is a permission error.
   */
  public isForbidden(): boolean {
    return this.statusCode === 403 || this.errorCode === 'FORBIDDEN';
  }

  /**
   * Check if the error is a not found error.
   */
  public isNotFound(): boolean {
    return this.statusCode === 404 || this.errorCode === 'NOT_FOUND';
  }
}
