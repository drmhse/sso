import { SsoClient } from '@drmhse/sso-sdk';

/**
 * Base SSO SDK client instance (without interceptors).
 * This is used internally and by the interceptor wrapper.
 */
export const ssoBase = new SsoClient({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000',
  token: localStorage.getItem('sso_token') || null,
});

/**
 * Default export - base client for direct use
 * For intercepted version with automatic auth error handling, import from './interceptor'
 */
export const sso = ssoBase;
