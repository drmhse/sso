import { defineComponent, ref, h, type PropType } from 'vue';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOS } from '../composables/useAuthOS';

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
  },
  emits: ['success', 'error'],
  setup(props, { slots, emit }) {
    const { client } = useAuthOS();

    const email = ref('');
    const password = ref('');
    const error = ref<string | null>(null);
    const isSubmitting = ref(false);

    async function submit() {
      error.value = null;
      isSubmitting.value = true;

      try {
        await client.auth.register({
          email: email.value,
          password: password.value,
        });

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

      return h('form', { onSubmit: (e: Event) => { e.preventDefault(); submit(); } }, [
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
        error.value && h('p', { style: 'color: red' }, error.value),
        h('button', { type: 'submit', disabled: isSubmitting.value }, isSubmitting.value ? 'Creating account...' : 'Sign Up'),
      ]);
    };
  },
});
