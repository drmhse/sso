import { defineNuxtPlugin, useRuntimeConfig } from 'nuxt/app';
import { createAuthOS } from '../../plugin';
import { CookieStorage } from '@drmhse/sso-sdk';

export default defineNuxtPlugin((nuxtApp) => {
  const config = useRuntimeConfig();
  const authOSConfig = config.public.authOS as {
    baseURL: string;
    tokenCookie?: string;
    domain?: string;
    path?: string;
    sameSite?: 'strict' | 'lax' | 'none';
  };

  // Use CookieStorage for Nuxt SSR compatibility
  const storage = new CookieStorage({
    domain: authOSConfig.domain,
    path: authOSConfig.path ?? '/',
    secure: true, // Always use secure cookies for auth
    sameSite: authOSConfig.sameSite ?? 'lax',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  });

  const authOS = createAuthOS({
    baseURL: authOSConfig.baseURL,
    storage,
  });

  nuxtApp.vueApp.use(authOS);

  // Expose the token cookie name for useTokenCookie() composable
  return {
    provide: {
      authOSTokenCookie: authOSConfig.tokenCookie ?? 'authos_token',
    },
  };
});
