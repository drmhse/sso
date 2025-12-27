import { SsoClient, CookieStorage } from '@drmhse/sso-sdk';

/**
 * Configuration for creating an AuthOS client optimized for Next.js
 */
export interface CreateAuthOSClientOptions {
  /**
   * Base URL of the SSO API service
   */
  baseURL: string;
  /**
   * Cookie name for storing the access token
   * @default 'authos_token'
   */
  tokenCookie?: string;
  /**
   * Cookie domain (optional)
   * Use this for subdomain-wide auth
   */
  domain?: string;
  /**
   * Cookie path
   * @default '/'
   */
  path?: string;
  /**
   * SameSite cookie attribute
   * @default 'lax'
   */
  sameSite?: 'strict' | 'lax' | 'none';
}

/**
 * Create an SSO client optimized for Next.js with cookie storage.
 *
 * This client uses cookies instead of localStorage, which enables:
 * - Server-side middleware auth checks
 * - SSR hydration without loading flash
 * - Shared auth state across tabs
 *
 * @example
 * ```tsx
 * // lib/authos.ts
 * import { createAuthOSClient } from '@drmhse/authos-react/nextjs';
 *
 * export const authos = createAuthOSClient({
 *   baseURL: process.env.NEXT_PUBLIC_AUTHOS_URL!,
 * });
 * ```
 *
 * @example With custom cookie settings
 * ```tsx
 * import { createAuthOSClient } from '@drmhse/authos-react/nextjs';
 *
 * export const authos = createAuthOSClient({
 *   baseURL: 'https://auth.example.com',
 *   tokenCookie: 'my_app_token',
 *   domain: '.example.com', // Share across subdomains
 * });
 * ```
 */
export function createAuthOSClient(options: CreateAuthOSClientOptions): SsoClient {
  const {
    baseURL,
    tokenCookie = 'authos_token',
    domain,
    path = '/',
    sameSite = 'lax',
  } = options;

  return new SsoClient({
    baseURL,
    storage: new CookieStorage({
      domain,
      path,
      secure: true, // Always use secure cookies for auth
      sameSite,
      // 30 days default max age
      maxAge: 30 * 24 * 60 * 60,
    }),
    storagePrefix: tokenCookie,
  });
}

/**
 * Create an SSO client for use with SSR token fetching.
 * Use this in server components where you need to make API calls
 * with a token from cookies.
 *
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { createServerClient } from '@drmhse/authos-react/nextjs';
 * import { getToken } from '@drmhse/authos-react/nextjs';
 *
 * export default async function DashboardPage() {
 *   const token = await getToken();
 *   const client = createServerClient(token);
 *
 *   const user = token ? await client.user.getProfile() : null;
 *
 *   return <div>Welcome, {user?.email}!</div>;
 * }
 * ```
 */
export function createServerClient(token: string, baseURL: string): SsoClient {
  return new SsoClient({
    baseURL,
    token, // Initial token for server-side use
  });
}
