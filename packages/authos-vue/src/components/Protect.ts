import { defineComponent, computed, h, type PropType, type VNode } from 'vue';
import { useUser } from '../composables/useUser';

export const Protect = defineComponent({
  name: 'Protect',
  props: {
    permission: {
      type: String,
      default: undefined,
    },
    permissions: {
      type: Array as PropType<string[]>,
      default: undefined,
    },
    requireAll: {
      type: Boolean,
      default: false,
    },
    fallback: {
      type: [Object, Function] as PropType<VNode | (() => VNode)>,
      default: undefined,
    },
  },
  setup(props, { slots }) {
    const { user, isLoading } = useUser();

    const hasAccess = computed(() => {
      if (isLoading.value || !user.value) {
        return false;
      }

      const userPermissions = user.value.permissions ?? [];

      if (props.permission) {
        return userPermissions.includes(props.permission);
      }

      if (props.permissions && props.permissions.length > 0) {
        if (props.requireAll) {
          return props.permissions.every((p) => userPermissions.includes(p));
        }
        return props.permissions.some((p) => userPermissions.includes(p));
      }

      return true;
    });

    return () => {
      if (isLoading.value) {
        return h('div', { 'data-authos-protect': '', 'data-state': 'loading' });
      }

      if (hasAccess.value) {
        return h('div', { 'data-authos-protect': '', 'data-state': 'allowed' }, slots.default?.());
      }

      if (props.fallback) {
        const fallbackContent = typeof props.fallback === 'function' ? props.fallback() : props.fallback;
        return h('div', { 'data-authos-protect': '', 'data-state': 'denied' }, [fallbackContent]);
      }

      if (slots.fallback) {
        return h('div', { 'data-authos-protect': '', 'data-state': 'denied' }, slots.fallback());
      }

      return h('div', { 'data-authos-protect': '', 'data-state': 'denied' });
    };
  },
});
