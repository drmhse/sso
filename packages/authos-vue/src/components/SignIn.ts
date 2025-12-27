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
    const { client } = useAuthOS();

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
          });

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

      return h('form', { onSubmit: (e: Event) => { e.preventDefault(); submit(); } }, [
        step.value === 'credentials'
          ? [
              h('input', {
                type: 'email',
                value: email.value,
                placeholder: 'Email',
                onInput: (e: Event) => (email.value = (e.target as HTMLInputElement).value),
              }),
              h('input', {
                type: 'password',
                value: password.value,
                placeholder: 'Password',
                onInput: (e: Event) => (password.value = (e.target as HTMLInputElement).value),
              }),
            ]
          : h('input', {
              type: 'text',
              value: mfaCode.value,
              placeholder: 'MFA Code',
              onInput: (e: Event) => (mfaCode.value = (e.target as HTMLInputElement).value),
            }),
        error.value && h('p', { style: 'color: red' }, error.value),
        h('button', { type: 'submit', disabled: isSubmitting.value }, isSubmitting.value ? 'Signing in...' : 'Sign In'),
      ]);
    };
  },
});
