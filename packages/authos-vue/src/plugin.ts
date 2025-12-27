import type { App } from 'vue';
import { reactive, nextTick } from 'vue';
import { SsoClient, BrowserStorage, MemoryStorage } from '@drmhse/sso-sdk';
import type { AuthOSPluginOptions, AuthOSState, AuthOSContext } from './types';
import { AUTH_OS_INJECTION_KEY } from './types';

export function createAuthOS(options: AuthOSPluginOptions) {
  // Use provided storage, or fallback to BrowserStorage (with MemoryStorage fallback for SSR/tests)
  const getStorage = () => {
    if (options.storage) return options.storage;
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        return new BrowserStorage();
      }
    } catch {
      // localStorage not available (e.g., in tests)
    }
    return new MemoryStorage();
  };

  const client = new SsoClient({
    baseURL: options.baseUrl,
    storage: getStorage(),
    token: options.initialToken, // Pass initial token if provided
  });

  // If we have an initial token from SSR, set it on the client to prevent loading flash
  let hasSetInitialToken = false;
  const setInitialToken = async () => {
    if (options.initialToken && !hasSetInitialToken) {
      await client.setSession({ access_token: options.initialToken });
      hasSetInitialToken = true;
    }
  };

  const state = reactive<AuthOSState>({
    user: null,
    isAuthenticated: false,
    isLoading: !options.initialToken, // Skip loading if we have initial token
    currentOrganization: null,
    organizations: [],
  });

  const context: AuthOSContext = {
    client,
    state,
  };

  return {
    install(app: App) {
      // Set initial token after plugin is installed
      nextTick(() => {
        setInitialToken();
      });

      client.onAuthStateChange(async (isAuthenticated: boolean) => {
        state.isAuthenticated = isAuthenticated;
        state.isLoading = false;

        if (isAuthenticated) {
          try {
            const profile = await client.user.getProfile();
            state.user = profile;
          } catch {
            state.user = null;
          }

          try {
            const orgs = await client.organizations.list();
            state.organizations = orgs;
            if (orgs.length > 0 && !state.currentOrganization) {
              state.currentOrganization = orgs[0];
            }
          } catch {
            state.organizations = [];
          }
        } else {
          state.user = null;
          state.currentOrganization = null;
          state.organizations = [];
        }
      });

      app.provide(AUTH_OS_INJECTION_KEY, context);
      app.config.globalProperties.$authOS = context;
    },
  };
}
