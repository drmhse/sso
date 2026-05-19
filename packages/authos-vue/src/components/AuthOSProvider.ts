import { defineComponent, provide, reactive, onMounted, onUnmounted, h, type PropType } from 'vue';
import { SsoClient, BrowserStorage, MemoryStorage } from '@drmhse/sso-sdk';
import type { TokenStorage } from '@drmhse/sso-sdk';
import type { AuthOSState, AuthOSContext, AuthOSPluginOptions } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';

export const AuthOSProvider = defineComponent({
  name: 'AuthOSProvider',
  props: {
    baseURL: {
      type: String,
      required: true,
    },
    org: {
      type: String,
      default: undefined,
    },
    service: {
      type: String,
      default: undefined,
    },
    redirectUri: {
      type: String,
      default: undefined,
    },
    storage: {
      type: Object as PropType<TokenStorage>,
      default: undefined,
    },
    client: {
      type: Object as PropType<SsoClient>,
      default: undefined,
    },
  },
  setup(props, { slots }) {
    const getStorage = (): TokenStorage => {
      if (props.storage) return props.storage;
      if (typeof window !== 'undefined') return new BrowserStorage();
      return new MemoryStorage();
    };

    const client =
      props.client ??
      new SsoClient({
        baseURL: props.baseURL,
        storage: getStorage(),
      });

    const state = reactive<AuthOSState>({
      user: null,
      isAuthenticated: false,
      isLoading: true,
      currentOrganization: null,
      organizations: [],
    });

    // Build options object for OAuth access
    const options: AuthOSPluginOptions = {
      baseURL: props.baseURL,
      org: props.org,
      service: props.service,
      redirectUri: props.redirectUri,
    };

    const context: AuthOSContext = { client, state, options };
    provide(AUTH_OS_INJECTION_KEY, context);

    let unsubscribe: (() => void) | undefined;

    onMounted(() => {
      unsubscribe = client.onAuthStateChange(async (isAuthenticated: boolean) => {
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
    });

    onUnmounted(() => {
      unsubscribe?.();
    });

    return () => (slots.default ? slots.default() : h('div'));
  },
});
