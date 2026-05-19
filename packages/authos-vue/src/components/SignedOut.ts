import { defineComponent, type PropType } from 'vue';
import { useAuthOS } from '../composables/useAuthOS';

/**
 * Renders children only when the user is NOT authenticated.
 * Use with SignedIn to create conditional UI based on auth state.
 *
 * @example
 * ```vue
 * <script setup>
 * import { SignedIn, SignedOut, UserButton, SignIn } from '@drmhse/authos-vue';
 * </script>
 *
 * <template>
 *   <header>
 *     <SignedIn>
 *       <UserButton />
 *     </SignedIn>
 *     <SignedOut>
 *       <SignIn />
 *     </SignedOut>
 *   </header>
 * </template>
 * ```
 */
export const SignedOut = defineComponent({
  name: 'SignedOut',
  setup(_, { slots }) {
    const { isAuthenticated, isLoading } = useAuthOS();

    return () => {
      // Don't render while loading to prevent flash of content
      if (isLoading.value) {
        return null;
      }

      // Only render when NOT authenticated
      if (isAuthenticated.value) {
        return null;
      }

      return slots.default?.();
    };
  },
});
