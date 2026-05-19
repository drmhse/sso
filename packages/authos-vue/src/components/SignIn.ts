import { defineComponent, ref, h, type PropType } from 'vue';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOS } from '../composables/useAuthOS';

type SignInStep = 'credentials' | 'mfa';

const MFA_PREAUTH_EXPIRY = 300;

export interface SignInSlotProps {
  email: string;
  password: string;
  mfaCode: string;
  step: SignInStep;
  error: string | null;
  isSubmitting: boolean;
  updateEmail: (value: string) => void;
  updatePassword: (value: string) => void;
  updateMfaCode: (value: string) => void;
  submit: () => Promise<void>;
}

export const SignIn = defineComponent({
  name: 'SignIn',
  props: {
    onSuccess: {
      type: Function as PropType<() => void>,
      default: undefined,
    },
    onError: {
      type: Function as PropType<(error: Error) => void>,
      default: undefined,
    },
  },
  emits: ['success', 'error'],
  setup(props, { slots, emit }) {
    const { client, options } = useAuthOS();

    const email = ref('');
    const password = ref('');
    const mfaCode = ref('');
    const preauthToken = ref('');
    const step = ref<SignInStep>('credentials');
    const error = ref<string | null>(null);
    const isSubmitting = ref(false);

    async function submit() {
      error.value = null;
      isSubmitting.value = true;

      try {
        if (step.value === 'credentials') {
          const result = await client.auth.login({
            email: email.value,
            password: password.value,
            org_slug: options.org,
            service_slug: options.service,
          } as any);

          if (result.expires_in === MFA_PREAUTH_EXPIRY) {
            preauthToken.value = result.access_token;
            step.value = 'mfa';
          } else {
            emit('success');
            props.onSuccess?.();
          }
        } else {
          await client.auth.verifyMfa(preauthToken.value, mfaCode.value);
          emit('success');
          props.onSuccess?.();
        }
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Login failed';
        error.value = message;
        const e = err instanceof Error ? err : new Error(message);
        emit('error', e);
        props.onError?.(e);
      } finally {
        isSubmitting.value = false;
      }
    }

    return () => {
      const slotProps: SignInSlotProps = {
        email: email.value,
        password: password.value,
        mfaCode: mfaCode.value,
        step: step.value,
        error: error.value,
        isSubmitting: isSubmitting.value,
        updateEmail: (v: string) => (email.value = v),
        updatePassword: (v: string) => (password.value = v),
        updateMfaCode: (v: string) => (mfaCode.value = v),
        submit,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      // MFA step
      if (step.value === 'mfa') {
        return h('div', { 'data-authos-signin': '', 'data-state': 'mfa' }, [
          h('form', { onSubmit: (e: Event) => { e.preventDefault(); submit(); } }, [
            h('div', { 'data-authos-field': 'mfa-code' }, [
              h('label', { for: 'authos-mfa-code' }, 'Verification Code'),
              h('input', {
                id: 'authos-mfa-code',
                type: 'text',
                inputMode: 'numeric',
                autocomplete: 'one-time-code',
                value: mfaCode.value,
                placeholder: 'Enter 6-digit code',
                required: true,
                disabled: isSubmitting.value,
                onInput: (e: Event) => (mfaCode.value = (e.target as HTMLInputElement).value),
              }),
            ]),
            error.value && h('div', { 'data-authos-error': '' }, error.value),
            h('button', {
              type: 'submit',
              disabled: isSubmitting.value,
              'data-authos-submit': '',
            }, isSubmitting.value ? 'Verifying...' : 'Verify'),
            h('button', {
              type: 'button',
              'data-authos-back': '',
              onClick: () => {
                step.value = 'credentials';
                mfaCode.value = '';
                preauthToken.value = '';
                error.value = null;
              },
            }, 'Back to login'),
          ]),
        ]);
      }

      // Credentials step
      return h('div', { 'data-authos-signin': '', 'data-state': 'credentials' }, [
        h('form', { onSubmit: (e: Event) => { e.preventDefault(); submit(); } }, [
          h('div', { 'data-authos-field': 'email' }, [
            h('label', { for: 'authos-email' }, 'Email'),
            h('input', {
              id: 'authos-email',
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
            h('label', { for: 'authos-password' }, 'Password'),
            h('input', {
              id: 'authos-password',
              type: 'password',
              autocomplete: 'current-password',
              value: password.value,
              placeholder: 'Enter your password',
              required: true,
              disabled: isSubmitting.value,
              onInput: (e: Event) => (password.value = (e.target as HTMLInputElement).value),
            }),
          ]),
          error.value && h('div', { 'data-authos-error': '' }, error.value),
          h('button', {
            type: 'submit',
            disabled: isSubmitting.value,
            'data-authos-submit': '',
          }, isSubmitting.value ? 'Signing in...' : 'Sign In'),
        ]),
      ]);
    };
  },
});
