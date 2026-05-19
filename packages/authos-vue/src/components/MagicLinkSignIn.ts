import { defineComponent, ref, computed, h, type PropType } from 'vue';
import { useAuthOS } from '../composables/useAuthOS';

/**
 * Passwordless sign-in via magic link (email).
 * 
 * Sends a one-time login link to the user's email address.
 * 
 * @example
 * ```vue
 * <script setup>
 * import { MagicLinkSignIn } from '@drmhse/authos-vue';
 * </script>
 * 
 * <template>
 *   <MagicLinkSignIn @success="() => alert('Check your email!')" />
 * </template>
 * ```
 */
export const MagicLinkSignIn = defineComponent({
  name: 'MagicLinkSignIn',
  props: {
    showPasswordSignIn: {
      type: Boolean,
      default: true,
    },
  },
  emits: ['success', 'error'],
  setup(props, { emit, slots }) {
    const { client } = useAuthOS();
    
    const email = ref('');
    const isLoading = ref(false);
    const error = ref<string | null>(null);
    const isSent = ref(false);

    async function handleSubmit() {
      error.value = null;
      isLoading.value = true;

      try {
        await client.magicLinks.request({ email: email.value });
        isSent.value = true;
        emit('success');
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to send magic link';
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
      isSent: isSent.value,
      updateEmail: (val: string) => { email.value = val; },
      submit: handleSubmit,
      reset: () => { isSent.value = false; },
    }));

    return () => {
      // Use scoped slot if provided
      if (slots.default) {
        return slots.default(slotProps.value);
      }

      // Default UI
      if (isSent.value) {
        return h('div', { 'data-authos-magic-link': '', 'data-state': 'sent' }, [
          h('div', { 'data-authos-success': '' }, [
            h('p', 'Check your email!'),
            h('p', ['We sent a login link to ', h('strong', email.value)]),
          ]),
          h('button', {
            type: 'button',
            onClick: () => { isSent.value = false; },
            'data-authos-back': '',
          }, 'Use a different email'),
        ]);
      }

      return h('form', {
        onSubmit: (e: Event) => {
          e.preventDefault();
          handleSubmit();
        },
        'data-authos-magic-link': '',
        'data-state': 'form',
      }, [
        h('div', { 'data-authos-field': 'email' }, [
          h('label', { for: 'authos-magic-email' }, 'Email'),
          h('input', {
            id: 'authos-magic-email',
            type: 'email',
            autocomplete: 'email',
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
        }, isLoading.value ? 'Sending...' : 'Send Magic Link'),
        props.showPasswordSignIn
          ? h('div', { 'data-authos-signin-prompt': '' }, [
              h('a', { href: '/signin', 'data-authos-link': 'signin' }, 'Sign in with password'),
            ])
          : null,
      ]);
    };
  },
});
