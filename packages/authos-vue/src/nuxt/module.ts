import { defineNuxtModule, addPlugin, createResolver, addImports } from '@nuxt/kit';

export interface AuthOSModuleOptions {
  baseUrl: string;
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

export default defineNuxtModule<AuthOSModuleOptions>({
  meta: {
    name: '@drmhse/authos-vue/nuxt',
    configKey: 'authOS',
    compatibility: {
      nuxt: '^3.0.0',
    },
  },
  defaults: {
    baseUrl: '',
    tokenCookie: 'authos_token',
    path: '/',
    sameSite: 'lax',
  },
  setup(
    options: AuthOSModuleOptions,
    nuxt: { options: { runtimeConfig: { public: Record<string, unknown> } } },
  ) {
    const resolver = createResolver(import.meta.url);

    nuxt.options.runtimeConfig.public.authOS = {
      baseUrl: options.baseUrl,
      tokenCookie: options.tokenCookie,
      domain: options.domain,
      path: options.path,
      sameSite: options.sameSite,
    };

    addPlugin(resolver.resolve('./runtime/plugin'));

    addImports([
      { name: 'useAuthOS', from: '@drmhse/authos-vue' },
      { name: 'useUser', from: '@drmhse/authos-vue' },
      { name: 'useOrganization', from: '@drmhse/authos-vue' },
    ]);
  },
});
