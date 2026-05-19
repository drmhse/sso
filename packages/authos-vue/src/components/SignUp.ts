import { defineComponent, ref, h, type PropType } from 'vue';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOS } from '../composables/useAuthOS';
import { OAuthButton } from './OAuthButton';

type SupportedOAuthProvider = 'github' | 'google' | 'microsoft';

export interface SignUpSlotProps {
  email: string;
  password: string;
  error: string | null;
  isSubmitting: boolean;
  updateEmail: (value: string) => void;
  updatePassword: (value: string) => void;
  submit: () => Promise<void>;
}

export const SignUp = defineComponent({
  name: 'SignUp',
  props: {
    onSuccess: {
      type: Function as PropType<() => void>,
      default: undefined,
    },
    onError: {
      type: Function as PropType<(error: Error) => void>,
      default: undefined,
    },
    /** Organization slug for tenant context */
    orgSlug: {
      type: String,
      default: undefined,
    },
    /** Service slug for tenant attribution (used with orgSlug) */
    serviceSlug: {
      type: String,
      default: undefined,
    },
    /** List of OAuth providers to display buttons for */
    providers: {
      type: [Array, Boolean] as PropType<SupportedOAuthProvider[] | false>,
      default: false,
    },
    /** Show divider between OAuth and email form */
    showDivider: {
      type: Boolean,
      default: true,
    },
    /** Show sign in link */
    showSignIn: {
      type: Boolean,
      default: true,
    },
  },
  emits: ['success', 'error'],
  setup(props, { slots, emit }) {
    const { client, options } = useAuthOS();

    const email = ref('');
    const password = ref('');
    const confirmPassword = ref('');
    const error = ref<string | null>(null);
    const isSubmitting = ref(false);
    const isSuccess = ref(false);

    // OAuth config check
    const hasOAuthConfig = !!(options.org && options.service);
    // @ts-ignore - PropType casting issues with mixed types
    const oauthProviders = Array.isArray(props.providers) ? props.providers : [];

    async function submit() {
      error.value = null;

      // Validation
      if (password.value !== confirmPassword.value) {
        error.value = 'Passwords do not match';
        return;
      }

      if (password.value.length < 8) {
        error.value = 'Password must be at least 8 characters';
        return;
      }

      isSubmitting.value = true;

      try {
        await client.auth.register({
          email: email.value,
          password: password.value,
          org_slug: props.orgSlug ?? options.org,
          service_slug: props.serviceSlug ?? options.service,
        } as any);

        isSuccess.value = true;
        emit('success');
        props.onSuccess?.();
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Registration failed';
        error.value = message;
        const e = err instanceof Error ? err : new Error(message);
        emit('error', e);
        props.onError?.(e);
      } finally {
        isSubmitting.value = false;
      }
    }

    return () => {
      const slotProps: SignUpSlotProps = {
        email: email.value,
        password: password.value,
        error: error.value,
        isSubmitting: isSubmitting.value,
        updateEmail: (v: string) => (email.value = v),
        updatePassword: (v: string) => (password.value = v),
        submit,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      if (isSuccess.value) {
        return h('div', { 'data-authos-signup': '', 'data-state': 'success' }, [
          h('div', { 'data-authos-success': '' }, [
            h('h2', 'Check your email'),
            h('p', `We've sent a verification link to ${email.value}. Please click the link to verify your account.`),
          ])
        ]);
      }

      return h('div', { 'data-authos-signup': '', 'data-state': 'credentials' }, [
        // OAuth Section
        oauthProviders.length > 0 && h('div', { 'data-authos-oauth-section': '' }, [
          oauthProviders.map((provider) =>
            h(OAuthButton, {
              key: provider,
              provider: provider as any,
              disabled: isSubmitting.value || !hasOAuthConfig,
            })
          ),
          !hasOAuthConfig && h('p', {
            'data-authos-oauth-warning': '',
            style: { color: 'orange', fontSize: '0.875rem' }
          }, 'OAuth requires org and service in plugin options')
        ]),

        // Divider
        oauthProviders.length > 0 && props.showDivider && h('div', { 'data-authos-divider': '' }, [
          h('span', 'or')
        ]),

        h('form', { onSubmit: (e: Event) => { e.preventDefault(); submit(); } }, [
          h('div', { 'data-authos-field': 'email' }, [
            h('label', { for: 'authos-signup-email' }, 'Email'),
            h('input', {
              id: 'authos-signup-email',
              type: 'email',
              autocomplete: 'email',
              value: email.value,
              placeholder: 'Enter your email',
              required: true,
              disabled: isSubmitting.value,
              onInput: (e: Event) => (email.value = (e.target as HTMLInputElement).value),
            }),
          ]),
          h('div', { 'data-authos-field': 'password' }, [
            h('label', { for: 'authos-signup-password' }, 'Password'),
            h('input', {
              id: 'authos-signup-password',
              type: 'password',
              autocomplete: 'new-password',
              value: password.value,
              placeholder: 'Create a password',
              required: true,
              disabled: isSubmitting.value,
              onInput: (e: Event) => (password.value = (e.target as HTMLInputElement).value),
            }),
          ]),
          // Confirm Password
          h('div', { 'data-authos-field': 'confirm-password' }, [
            h('label', { for: 'authos-signup-confirm' }, 'Confirm Password'),
            h('input', {
              id: 'authos-signup-confirm',
              type: 'password',
              autocomplete: 'new-password',
              value: confirmPassword.value,
              placeholder: 'Confirm your password',
              required: true,
              disabled: isSubmitting.value,
              onInput: (e: Event) => (confirmPassword.value = (e.target as HTMLInputElement).value),
            }),
          ]),

          error.value && h('div', { 'data-authos-error': '' }, error.value),

          h('button', {
            type: 'submit',
            disabled: isSubmitting.value,
            'data-authos-submit': '',
          }, isSubmitting.value ? 'Creating account...' : 'Sign Up'),

          // Sign In Link
          props.showSignIn && h('div', { 'data-authos-signin-prompt': '' }, [
            'Already have an account? ',
            h('a', { href: '/signin', 'data-authos-link': 'signin' }, 'Sign in')
          ]),
        ]),
      ]);
    };
  },
});
