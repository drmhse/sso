import { defineComponent, h, computed, type PropType, type VNode } from 'vue';
import { useAuthOS } from '../composables/useAuthOS';
import type { SupportedOAuthProvider } from '../types';

/**
 * Human-readable provider names for button labels
 */
const PROVIDER_NAMES: Record<SupportedOAuthProvider, string> = {
  github: 'GitHub',
  google: 'Google',
  microsoft: 'Microsoft',
};

/**
 * SVG icons for each OAuth provider
 */
function getProviderIcon(provider: SupportedOAuthProvider): VNode {
  switch (provider) {
    case 'github':
      return h('svg', {
        xmlns: 'http://www.w3.org/2000/svg',
        viewBox: '0 0 24 24',
        fill: 'currentColor',
        'aria-hidden': 'true',
      }, [
        h('path', {
          d: 'M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z',
        }),
      ]);
    case 'google':
      return h('svg', {
        xmlns: 'http://www.w3.org/2000/svg',
        viewBox: '0 0 24 24',
        'aria-hidden': 'true',
      }, [
        h('path', {
          fill: '#4285F4',
          d: 'M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z',
        }),
        h('path', {
          fill: '#34A853',
          d: 'M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z',
        }),
        h('path', {
          fill: '#FBBC05',
          d: 'M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z',
        }),
        h('path', {
          fill: '#EA4335',
          d: 'M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z',
        }),
      ]);
    case 'microsoft':
      return h('svg', {
        xmlns: 'http://www.w3.org/2000/svg',
        viewBox: '0 0 23 23',
        'aria-hidden': 'true',
      }, [
        h('path', { fill: '#f35325', d: 'M1 1h10v10H1z' }),
        h('path', { fill: '#81bc06', d: 'M12 1h10v10H12z' }),
        h('path', { fill: '#05a6f0', d: 'M1 12h10v10H1z' }),
        h('path', { fill: '#ffba08', d: 'M12 12h10v10H12z' }),
      ]);
  }
}

export interface OAuthButtonSlotProps {
  provider: SupportedOAuthProvider;
  providerName: string;
  isConfigured: boolean;
  disabled: boolean;
  handleClick: () => void;
}

/**
 * OAuth login button for a specific provider.
 * Redirects the user to the OAuth provider's login page.
 *
 * Requires `org` and `service` to be configured in createAuthOS options.
 *
 * @example
 * ```vue
 * <script setup>
 * import { OAuthButton } from '@drmhse/authos-vue';
 * </script>
 *
 * <template>
 *   <OAuthButton provider="github" />
 *   <OAuthButton provider="google">Sign in with Google</OAuthButton>
 * </template>
 * ```
 */
export const OAuthButton = defineComponent({
  name: 'OAuthButton',
  props: {
    provider: {
      type: String as PropType<SupportedOAuthProvider>,
      required: true,
    },
    disabled: {
      type: Boolean,
      default: false,
    },
  },
  emits: ['redirect'],
  setup(props, { slots, emit }) {
    const { client, options } = useAuthOS();

    const isConfigured = computed(() => !!(options.org && options.service));
    const providerName = computed(() => PROVIDER_NAMES[props.provider]);

    function handleClick() {
      if (!options.org || !options.service) {
        console.error(
          `[AuthOS] OAuth login requires "org" and "service" in createAuthOS options.\n` +
            `Current options: { org: ${options.org ? `"${options.org}"` : 'undefined'}, service: ${options.service ? `"${options.service}"` : 'undefined'} }\n` +
            `\n` +
            `Example:\n` +
            `  app.use(createAuthOS({\n` +
            `    baseURL: "${options.baseURL}",\n` +
            `    org: "your-org-slug",\n` +
            `    service: "your-service-slug",\n` +
            `  }));\n` +
            `\n` +
            `See: https://docs.authos.dev/vue/oauth-setup`
        );
        return;
      }

      const redirectUri =
        options.redirectUri ??
        (typeof window !== 'undefined' ? window.location.origin + '/callback' : undefined);

      const url = client.auth.getLoginUrl(props.provider, {
        org: options.org,
        service: options.service,
        redirect_uri: redirectUri,
      });

      emit('redirect');
      window.location.href = url;
    }

    return () => {
      const slotProps: OAuthButtonSlotProps = {
        provider: props.provider,
        providerName: providerName.value,
        isConfigured: isConfigured.value,
        disabled: props.disabled,
        handleClick,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      return h(
        'button',
        {
          type: 'button',
          onClick: handleClick,
          disabled: props.disabled || !isConfigured.value,
          'data-authos-oauth': '',
          'data-provider': props.provider,
        },
        [
          getProviderIcon(props.provider),
          h('span', `Continue with ${providerName.value}`),
        ]
      );
    };
  },
});
