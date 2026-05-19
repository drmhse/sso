import { defineComponent, ref, h, type PropType } from 'vue';
import { useUser } from '../composables/useUser';
import { useAuthOS } from '../composables/useAuthOS';

export interface UserButtonSlotProps {
  user: ReturnType<typeof useUser>['user']['value'];
  isLoading: boolean;
  isLoggingOut: boolean;
  logout: () => Promise<void>;
}

export const UserButton = defineComponent({
  name: 'UserButton',
  props: {
    onLogout: {
      type: Function as PropType<() => void>,
      default: undefined,
    },
  },
  emits: ['logout'],
  setup(props, { slots, emit }) {
    const { user, isLoading } = useUser();
    const { client } = useAuthOS();
    const isLoggingOut = ref(false);

    async function logout() {
      isLoggingOut.value = true;
      try {
        await client.auth.logout();
        emit('logout');
        props.onLogout?.();
      } finally {
        isLoggingOut.value = false;
      }
    }

    return () => {
      const slotProps: UserButtonSlotProps = {
        user: user.value,
        isLoading: isLoading.value,
        isLoggingOut: isLoggingOut.value,
        logout,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      if (isLoading.value) {
        return h('div', { 'data-authos-userbutton': '', 'data-state': 'loading' }, 'Loading...');
      }

      if (!user.value) {
        return h('div', { 'data-authos-userbutton': '', 'data-state': 'signed-out' }, 'Not signed in');
      }

      // Get user initials for avatar
      const getInitials = (email: string): string => {
        const name = email.split('@')[0];
        return name.substring(0, 2).toUpperCase();
      };

      return h('div', { 'data-authos-userbutton': '', 'data-state': 'signed-in' }, [
        h('div', { 'data-authos-avatar': '' }, getInitials(user.value.email)),
        h('span', { 'data-authos-email': '' }, user.value.email),
        h(
          'button',
          {
            'data-authos-logout': '',
            onClick: logout,
            disabled: isLoggingOut.value,
          },
          isLoggingOut.value ? 'Logging out...' : 'Logout'
        ),
      ]);
    };
  },
});
