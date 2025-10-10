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
