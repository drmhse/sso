import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import ManagedConfigPanel from '@/components/ManagedConfigPanel.vue';

vi.mock('@/features/setup/useManagedConfig', () => ({
  useManagedConfig: () => ({
    loading: false,
    refreshing: false,
    saving: false,
    applying: false,
    form: {
      deployment: {},
      standalone: {},
      caddy: {},
      platformOwner: {},
      billing: {},
      smtp: {},
      oauth: {},
      services: [],
      outputs: {},
    },
    configPath: '/var/lib/authos/config.json',
    statusMessage: 'Ready to apply.',
    statusUpdatedAt: 'Now',
    statusLabel: 'success',
    statusClass: 'active',
    message: '',
    messageType: 'success',
    validationErrors: [],
    advancedJson: '{}\n',
    loadConfig: vi.fn(),
    saveConfig: vi.fn(),
    saveAndApply: vi.fn(),
  }),
}));

vi.mock('@/features/setup/components/ManagedConfigDeploymentSection.vue', () => ({ default: { template: '<div>deployment</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigCaddySection.vue', () => ({ default: { template: '<div>caddy</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigPlatformOwnerSection.vue', () => ({ default: { template: '<div>platform owner</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigBillingSection.vue', () => ({ default: { template: '<div>billing</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigSmtpSection.vue', () => ({ default: { template: '<div>smtp</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigOauthSection.vue', () => ({ default: { template: '<div>oauth</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigServicesSection.vue', () => ({ default: { template: '<div>services</div>' } }));
vi.mock('@/features/setup/components/ManagedConfigOutputsSection.vue', () => ({ default: { template: '<div>outputs</div>' } }));

afterEach(() => {
  vi.clearAllMocks();
});

describe('ManagedConfigPanel', () => {
  it('renders the sticky apply surface for the setup workspace', () => {
    const wrapper = mount(ManagedConfigPanel);

    expect(wrapper.find('.sticky-action-bar').exists()).toBe(true);
    expect(wrapper.text()).toContain('Apply & Restart');
    expect(wrapper.text()).toContain('Validation passed. Ready to apply configuration.');
  });
});
