import { SsoClient } from '@drmhse/sso-sdk';

export const ssoBase = new SsoClient({
  baseURL: window.location.origin,
  token: localStorage.getItem('sso_access_token') || null,
});

export const sso = ssoBase;
