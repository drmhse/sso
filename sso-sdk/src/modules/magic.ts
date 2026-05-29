import { HttpClient } from '../http';

/**
 * Magic link request payload
 */
export interface MagicLinkRequest {
  /** Email address to send the magic link to */
  email: string;
  /** Optional organization context */
  org_slug?: string;
  orgSlug?: string;
  /** Optional service context */
  service_slug?: string;
  /** Optional service callback URI */
  redirect_uri?: string;
  /** Optional caller state to return to hosted service callbacks */
  state?: string;
}

/**
 * Magic link response
 */
export interface MagicLinkResponse {
  /** Success message */
  message: string;
}

/**
 * Magic link verification query parameters
 */
export interface MagicLinkVerifyQuery {
  /** The magic link token */
  token: string;
  /** Optional where to redirect after successful verification */
  redirectUri?: string;
  /** Optional caller state to return to hosted service callbacks */
  state?: string;
}

/**
 * Magic links module for passwordless authentication
 */
export class MagicLinks {
  constructor(private http: HttpClient) {}

  /**
   * Request a magic link to be sent to the user's email
   *
   * @param data Magic link request data
   * @returns Promise resolving to magic link response
   */
  async request(data: MagicLinkRequest): Promise<MagicLinkResponse> {
    const response = await this.http.post('/api/auth/magic-link/request', {
      ...data,
      org_slug: data.org_slug || data.orgSlug,
    });
    return response.data;
  }

  /**
   * Verify a magic link token and complete authentication
   * Note: This is typically handled by redirecting to the magic link URL
   * The backend will handle verification and either redirect or return tokens
   *
   * @param token The magic link token to verify
   * @param redirectUri Optional where to redirect after success
   * @returns URL to redirect to for verification
   */
  getVerificationUrl(token: string, redirectUri?: string, state?: string): string {
    const params = new URLSearchParams({ token });
    if (redirectUri) {
      params.append('redirect_uri', redirectUri);
    }
    if (state) {
      params.append('state', state);
    }
    return `/api/auth/magic-link/verify?${params.toString()}`;
  }

  /**
   * Verify a magic link token via API call
   * This is an alternative to redirect-based verification
   *
   * @param token The magic link token
   * @param redirectUri Optional redirect URI
   * @returns Promise resolving to authentication response
   */
  async verify(token: string, redirectUri?: string, state?: string): Promise<any> {
    const params = new URLSearchParams({ token });
    if (redirectUri) {
      params.append('redirect_uri', redirectUri);
    }
    if (state) {
      params.append('state', state);
    }

    const response = await this.http.get(`/api/auth/magic-link/verify?${params.toString()}`);
    return response.data;
  }

  /**
   * Construct the complete magic link URL that would be sent via email
   *
   * @param token The magic link token
   * @param redirectUri Optional redirect URI
   * @returns Complete magic link URL
   */
  constructMagicLink(token: string, redirectUri?: string, state?: string): string {
    return this.getVerificationUrl(token, redirectUri, state);
  }
}

/**
 * Convenience function to create a MagicLinks module instance
 *
 * @param http HTTP client instance
 * @returns MagicLinks module instance
 */
export function createMagicLinks(http: HttpClient): MagicLinks {
  return new MagicLinks(http);
}
