import { defineComponent, h, type PropType } from 'vue';
import { useOrganization } from '../composables/useOrganization';
import type { OrganizationResponse } from '@drmhse/sso-sdk';

export interface OrganizationSwitcherSlotProps {
  currentOrganization: OrganizationResponse | null;
  organizations: OrganizationResponse[];
  isSwitching: boolean;
  switchTo: (slug: string) => Promise<void>;
}

export const OrganizationSwitcher = defineComponent({
  name: 'OrganizationSwitcher',
  props: {
    onSwitch: {
      type: Function as PropType<(org: OrganizationResponse) => void>,
      default: undefined,
    },
  },
  emits: ['switch'],
  setup(props, { slots, emit }) {
    const { currentOrganization, organizations, switchOrganization, isSwitching } = useOrganization();

    async function switchTo(slug: string) {
      await switchOrganization(slug);
      const org = organizations.value.find((o) => o.organization.slug === slug);
      if (org) {
        emit('switch', org);
        props.onSwitch?.(org);
      }
    }

    return () => {
      const slotProps: OrganizationSwitcherSlotProps = {
        currentOrganization: currentOrganization.value,
        organizations: organizations.value,
        isSwitching: isSwitching.value,
        switchTo,
      };

      if (slots.default) {
        return slots.default(slotProps);
      }

      // Always render a wrapper div
      return h(
        'div',
        { 'data-authos-orgswitcher': '', 'data-state': organizations.value.length > 0 ? 'ready' : 'empty' },
        organizations.value.length > 0
          ? h(
              'select',
              {
                value: currentOrganization.value?.organization.slug ?? '',
                disabled: isSwitching.value,
                onChange: (e: Event) => switchTo((e.target as HTMLSelectElement).value),
              },
              organizations.value.map((org) =>
                h('option', { key: org.organization.id, value: org.organization.slug }, org.organization.name)
              )
            )
          : 'No organizations'
      );
    };
  },
});
