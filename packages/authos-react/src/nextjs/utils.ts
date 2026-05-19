/**
 * Utility functions for Next.js integration
 */

/**
 * Construct the JWKS URL from a base URL.
 *
 * This helper simplifies middleware configuration by deriving the JWKS URL
 * from the same base URL used in your client-side configuration.
 *
 * @param baseURL - The base URL of your AuthOS instance
 * @returns The full JWKS URL
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { getJwksUrl, authMiddleware } from '@drmhse/authos-react/nextjs';
 *
 * export default authMiddleware({
 *   jwksUrl: getJwksUrl(process.env.NEXT_PUBLIC_AUTHOS_URL!),
 *   protectedRoutes: ['/dashboard/*'],
 * });
 * ```
 */
export function getJwksUrl(baseURL: string): string {
  const base = baseURL.endsWith('/') ? baseURL.slice(0, -1) : baseURL;
  return `${base}/.well-known/jwks.json`;
}

/**
 * Get the base URL without trailing slash
 */
export function normalizeBaseUrl(baseURL: string): string {
  return baseURL.endsWith('/') ? baseURL.slice(0, -1) : baseURL;
}
