import { defineComponent, ref, computed, onMounted, h } from 'vue';
import { useAuthOS } from '../composables/useAuthOS';

/**
 * Passkey (WebAuthn) sign-in component.
 * 
 * Uses the Web Authentication API for passwordless authentication
 * via biometrics, security keys, or platform authenticators.
 * 
 * @example
 * ```vue
 * <script setup>
 * import { PasskeySignIn } from '@drmhse/authos-vue';
 * </script>
 * 
 * <template>
 *   <PasskeySignIn @success="() => router.push('/dashboard')" />
 * </template>
 * ```
 */
export const PasskeySignIn = defineComponent({
  name: 'PasskeySignIn',
  props: {
    showPasswordSignIn: {
      type: Boolean,
      default: true,
    },
    orgSlug: {
      type: String,
      default: undefined,
    },
    serviceSlug: {
      type: String,
      default: undefined,
    },
    redirectUri: {
      type: String,
      default: undefined,
    },
    state: {
      type: String,
      default: undefined,
    },
  },
  emits: ['success', 'error'],
  setup(props, { emit, slots }) {
    const { client, options } = useAuthOS();
    
    const email = ref('');
    const isLoading = ref(false);
    const error = ref<string | null>(null);
    const isSupported = ref(true);

    // Check WebAuthn support
    onMounted(() => {
      isSupported.value = client.passkeys.isSupported();
    });

    async function handleSubmit() {
      error.value = null;
      isLoading.value = true;

      try {
        const org = props.orgSlug ?? options.org;
        const service = props.serviceSlug ?? options.service;
        const passkeyContext = org && service
          ? {
              org_slug: org,
              service_slug: service,
              redirect_uri: props.redirectUri ?? options.redirectUri,
              state: props.state,
            }
          : undefined;

        // Use the SDK's convenient login method which handles the full WebAuthn flow
        await client.passkeys.login(email.value, passkeyContext);
        emit('success');
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Passkey authentication failed';
        error.value = message;
        emit('error', err);
      } finally {
        isLoading.value = false;
      }
    }

    const slotProps = computed(() => ({
      email: email.value,
      isLoading: isLoading.value,
      error: error.value,
      isSupported: isSupported.value,
      updateEmail: (val: string) => { email.value = val; },
      submit: handleSubmit,
    }));

    return () => {
      // Use scoped slot if provided
      if (slots.default) {
        return slots.default(slotProps.value);
      }

      // Unsupported state
      if (!isSupported.value) {
        return h('div', {
          'data-authos-passkey': '',
          'data-state': 'unsupported',
        }, [
          h('div', { 'data-authos-error': '' }, 'Passkeys are not supported in this browser.'),
          props.showPasswordSignIn
            ? h('a', { href: '/signin', 'data-authos-link': 'signin' }, 'Sign in with password')
            : null,
        ]);
      }

      // Form
      return h('form', {
        onSubmit: (e: Event) => {
          e.preventDefault();
          handleSubmit();
        },
        'data-authos-passkey': '',
      }, [
        h('div', { 'data-authos-field': 'email' }, [
          h('label', { for: 'authos-passkey-email' }, 'Email'),
          h('input', {
            id: 'authos-passkey-email',
            type: 'email',
            autocomplete: 'email webauthn',
            value: email.value,
            onInput: (e: Event) => { email.value = (e.target as HTMLInputElement).value; },
            placeholder: 'Enter your email',
            required: true,
            disabled: isLoading.value,
          }),
        ]),
        error.value ? h('div', { 'data-authos-error': '' }, error.value) : null,
        h('button', {
          type: 'submit',
          disabled: isLoading.value,
          'data-authos-submit': '',
        }, isLoading.value ? 'Authenticating...' : 'Sign in with Passkey'),
        props.showPasswordSignIn
          ? h('div', { 'data-authos-signin-prompt': '' }, [
              h('a', { href: '/signin', 'data-authos-link': 'signin' }, 'Sign in with password'),
            ])
          : null,
      ]);
    };
  },
});
