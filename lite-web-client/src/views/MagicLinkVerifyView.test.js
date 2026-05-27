import { mount } from '@vue/test-utils';
import { nextTick } from 'vue';
import { createPinia, setActivePinia } from 'pinia';
import { createMemoryHistory, createRouter } from 'vue-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import MagicLinkVerifyView from '@/views/MagicLinkVerifyView.vue';
import MfaChallengeView from '@/views/MfaChallengeView.vue';
import { useAuthFlowStore } from '@/stores/authFlow';
import { clearBrowserStorage } from '@/test/storage';

const verifyMock = vi.fn();

vi.mock('@/lib/api', () => ({
  sso: {
    magicLinks: {
      verify: (...args) => verifyMock(...args),
    },
  },
}));

function createTestRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/auth/magic-link/verify', component: MagicLinkVerifyView },
      { path: '/mfa-challenge', component: MfaChallengeView },
      { path: '/support', component: { template: '<div />' } },
    ],
  });
}

async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

afterEach(() => {
  verifyMock.mockReset();
  clearBrowserStorage();
});

describe('MagicLinkVerifyView', () => {
  it('stores the MFA challenge and redirects to the full-page MFA route', async () => {
    verifyMock.mockResolvedValue({
      requires_mfa: true,
      preauth_token: 'preauth-token',
    });

    const pinia = createPinia();
    setActivePinia(pinia);
    const router = createTestRouter();
    router.push('/auth/magic-link/verify?token=hello');
    await router.isReady();

    mount(MagicLinkVerifyView, {
      global: {
        plugins: [pinia, router],
      },
    });

    await flush();

    const authFlowStore = useAuthFlowStore();
    expect(authFlowStore.mfaChallenge.preauthToken).toBe('preauth-token');
    expect(router.currentRoute.value.path).toBe('/mfa-challenge');
  });
});
