import { defineComponent, onMounted, ref, h, type PropType } from 'vue';
import { useAuthOS } from '../composables/useAuthOS';

export interface CallbackSlotProps {
  error: string | null;
}

export const Callback = defineComponent({
  name: 'Callback',
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
    const error = ref<string | null>(null);

    onMounted(async () => {
      if (!client) {
        error.value = 'AuthOS client not initialized';
        return;
      }

      // Parse callback parameters from URL hash first, then fall back to query params.
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      const queryParams = new URLSearchParams(window.location.search);

      const accessToken =
        hashParams.get('access_token') || queryParams.get('access_token');
      const refreshToken =
        hashParams.get('refresh_token') || queryParams.get('refresh_token');
      const errorParam = hashParams.get('error') || queryParams.get('error');
      const errorDescription =
        hashParams.get('error_description') || queryParams.get('error_description');

      if (errorParam) {
        const msg = errorDescription || errorParam;
        error.value = msg;
        const e = new Error(msg);
        emit('error', e);
        props.onError?.(e);
        return;
      }

      if (accessToken) {
        try {
          // Set session using SDK
          await client.setSession({
            access_token: accessToken,
            refresh_token: refreshToken || undefined,
          });

          emit('success');
          props.onSuccess?.();
        } catch (err: any) {
          const message = err.message || 'Failed to set session';
          error.value = message;
          const e = err instanceof Error ? err : new Error(message);
          emit('error', e);
          props.onError?.(e);
        }
      } else {
        // No tokens found
        const message = 'No authentication tokens found in callback URL.';
        error.value = message;
        const e = new Error(message);
        emit('error', e);
        props.onError?.(e);
      }
    });

    return () => {
      const slotProps: CallbackSlotProps = {
        error: error.value,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      // Default UI
      return h('div', { 'data-authos-callback': '' }, [
        error.value
          ? h('div', { 'data-authos-error': '' }, error.value)
          : h('div', { 'data-authos-loading': '' }, 'Completing sign in...'),
      ]);
    };
  },
});
