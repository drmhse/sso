import { SsoClient } from '@drmhse/sso-sdk';

function readInitialToken() {
  if (typeof localStorage === 'undefined' || typeof localStorage.getItem !== 'function') {
    return null;
  }

  return localStorage.getItem('sso_access_token') || null;
}

export const ssoBase = new SsoClient({
  baseURL: typeof window !== 'undefined' ? window.location.origin : 'http://localhost',
  token: readInitialToken(),
});

export const sso = ssoBase;
