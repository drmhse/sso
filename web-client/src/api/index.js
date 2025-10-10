import { SsoClient } from '@drmhse/sso-sdk';

/**
 * Singleton instance of the SSO SDK client.
 * This is shared across the entire application.
 */
export const sso = new SsoClient({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000',
  token: localStorage.getItem('sso_token') || null,
});
