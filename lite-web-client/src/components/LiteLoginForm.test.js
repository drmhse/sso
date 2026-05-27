import { nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import { createMemoryHistory, createRouter } from 'vue-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import LiteLoginForm from '@/components/LiteLoginForm.vue';
import { clearBrowserStorage } from '@/test/storage';

vi.mock('@/lib/api', () => ({
  sso: {
    auth: {
      lookupEmail: vi.fn().mockResolvedValue({ auth_method: 'password' }),
      getAdminLoginUrl: vi.fn().mockReturnValue('/oauth'),
      getLoginUrl: vi.fn().mockReturnValue('/oauth'),
    },
    magicLinks: {},
    passkeys: {
      isSupported: vi.fn().mockReturnValue(true),
    },
  },
}));

function createTestRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/forgot-password', component: { template: '<div />' } },
      { path: '/register', component: { template: '<div />' } },
    ],
  });
}

async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

afterEach(() => {
  clearBrowserStorage();
});

describe('LiteLoginForm', () => {
  it('moves from email capture to password entry after lookup', async () => {
    const router = createTestRouter();
    router.push('/');
    await router.isReady();

    const wrapper = mount(LiteLoginForm, {
      global: {
        plugins: [createPinia(), router],
      },
    });

    await wrapper.get('#login-email').setValue('alice@example.com');
    const continueButton = wrapper.findAll('button').find((button) => button.text().trim() === 'Continue');
    expect(continueButton).toBeTruthy();
    await continueButton.trigger('click');
    await flush();

    expect(wrapper.text()).toContain('Password');
    expect(wrapper.text()).toContain('alice@example.com');
    expect(wrapper.find('#login-password').exists()).toBe(true);
  });
});
