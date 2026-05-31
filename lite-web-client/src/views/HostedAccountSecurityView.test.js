import { nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { createMemoryHistory, createRouter } from 'vue-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import HostedAccountSecurityView from '@/views/HostedAccountSecurityView.vue';
import { useAuthStore } from '@/stores/auth';
import { clearBrowserStorage } from '@/test/storage';

vi.mock('@/lib/api', () => ({
  sso: {
    auth: {
      logout: vi.fn().mockResolvedValue({}),
    },
    user: {
      getProfile: vi.fn().mockResolvedValue({ email: 'alice@example.com' }),
      updateProfile: vi.fn().mockResolvedValue({}),
      changePassword: vi.fn().mockResolvedValue({}),
      mfa: {
        getStatus: vi.fn().mockResolvedValue({ enabled: false, has_backup_codes: false }),
        setup: vi.fn().mockResolvedValue({}),
        verify: vi.fn().mockResolvedValue({ backup_codes: [] }),
        disable: vi.fn().mockResolvedValue({}),
        regenerateBackupCodes: vi.fn().mockResolvedValue({ backup_codes: [] }),
      },
      devices: {
        list: vi.fn().mockResolvedValue({ devices: [] }),
        updateName: vi.fn().mockResolvedValue({}),
        revoke: vi.fn().mockResolvedValue({}),
      },
    },
    passkeys: {
      list: vi.fn().mockResolvedValue([]),
      register: vi.fn().mockResolvedValue({}),
      updateName: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({}),
    },
    setAuthToken: vi.fn(),
  },
}));

function createTestRouter(path) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/account/security', component: HostedAccountSecurityView },
    ],
  });

  router.push(path);
  return router;
}

async function mountView(path) {
  const pinia = createPinia();
  setActivePinia(pinia);
  const authStore = useAuthStore();
  authStore.$patch({
    status: 'authenticated',
    token: 'test-token',
    refreshToken: 'test-refresh',
    user: { email: 'alice@example.com' },
  });

  const router = createTestRouter(path);
  await router.isReady();

  const wrapper = mount(HostedAccountSecurityView, {
    global: {
      plugins: [pinia, router],
    },
  });

  await flush();
  return wrapper;
}

async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

afterEach(() => {
  vi.clearAllMocks();
  clearBrowserStorage();
  document.body.innerHTML = '';
});

describe('HostedAccountSecurityView', () => {
  it('renders the focused account security controls without workspace navigation', async () => {
    const wrapper = await mountView('/account/security?org=queuezero&service=flux&return_to=https%3A%2F%2Fflux.example.com%2Fsettings');
    const text = wrapper.text();

    expect(text).toContain('Account security');
    expect(text).toContain('Signed in as');
    expect(text).toContain('alice@example.com');
    expect(text).toContain('For flux in queuezero.');
    expect(text).toContain('Account Profile');
    expect(text).toContain('Multi-Factor Authentication (MFA)');
    expect(text).toContain('Passkeys');
    expect(text).toContain('Trusted Devices');
    expect(text).toContain('Return to application');
    expect(text).not.toContain('Applications');
    expect(text).not.toContain('Users');
    expect(text).not.toContain('Organization');
    expect(text).not.toContain('Platform Setup');
    expect(text).not.toContain('Open full client');
  });

  it('does not render a return action for unsafe return URLs', async () => {
    const wrapper = await mountView('/account/security?return_to=javascript%3Aalert%281%29');

    expect(wrapper.text()).not.toContain('Return to application');
  });
});
