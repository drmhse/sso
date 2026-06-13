import { nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import { createMemoryHistory, createRouter } from 'vue-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import LiteLoginForm from '@/components/LiteLoginForm.vue';
import { sso } from '@/lib/api';
import { clearBrowserStorage } from '@/test/storage';

vi.mock('@/lib/api', () => ({
  sso: {
    auth: {
      lookupEmail: vi.fn().mockResolvedValue({ auth_method: 'password' }),
      getContext: vi.fn().mockResolvedValue({
        organization: { slug: 'acme', name: 'Acme' },
        service: { slug: 'portal', name: 'Portal', redirect_uri_valid: true },
        available_providers: ['github', 'google'],
        auth_methods: ['password', 'magic_link', 'passkey'],
      }),
      login: vi.fn(),
      getAdminLoginUrl: vi.fn().mockReturnValue('#oauth'),
      getLoginUrl: vi.fn().mockReturnValue('#oauth'),
    },
    magicLinks: {
      request: vi.fn().mockResolvedValue({ message: 'Link sent' }),
    },
    passkeys: {
      isSupported: vi.fn().mockReturnValue(true),
      login: vi.fn(),
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
  vi.clearAllMocks();
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

  it('passes the protected Lite return path through admin OAuth', async () => {
    const router = createTestRouter();
    const returnTo = '/account/security?org=queuezero&service=flux&return_to=https%3A%2F%2Fflux.example.com%2Fsettings';
    router.push({ path: '/', query: { redirect: returnTo } });
    await router.isReady();

    const wrapper = mount(LiteLoginForm, {
      global: {
        plugins: [createPinia(), router],
      },
    });

    const githubButton = wrapper.findAll('button').find((button) => button.text().includes('Github'));
    expect(githubButton).toBeTruthy();
    await githubButton.trigger('click');

    expect(sso.auth.getAdminLoginUrl).toHaveBeenCalledWith('github', { return_to: returnTo });
  });

  it('propagates org-scoped hosted login context through OAuth and local fallbacks', async () => {
    const router = createTestRouter();
    router.push({
      path: '/',
      query: {
        org: 'acme',
        service: 'portal',
        redirect_uri: 'https://portal.example.com/callback',
        state: 'caller-state',
      },
    });
    await router.isReady();

    const wrapper = mount(LiteLoginForm, {
      global: {
        plugins: [createPinia(), router],
      },
    });
    await flush();

    expect(sso.auth.getContext).toHaveBeenCalledWith({
      org: 'acme',
      service: 'portal',
      redirect_uri: 'https://portal.example.com/callback',
    });
    expect(wrapper.text()).toContain('Signing in to Portal for Acme.');

    const githubButton = wrapper.findAll('button').find((button) => button.text().includes('Github'));
    await githubButton.trigger('click');
    expect(sso.auth.getLoginUrl).toHaveBeenCalledWith('github', {
      org: 'acme',
      service: 'portal',
      redirect_uri: 'https://portal.example.com/callback',
      state: 'caller-state',
      connection_id: null,
    });

    await wrapper.get('#login-email').setValue('alice@example.com');
    const continueButton = wrapper.findAll('button').find((button) => button.text().trim() === 'Continue');
    await continueButton.trigger('click');
    await flush();

    await wrapper.get('#login-password').setValue('secret-pass');
    sso.auth.login.mockRejectedValueOnce(new Error('stop after payload capture'));
    const signInButton = wrapper.findAll('button').find((button) => button.text().includes('Sign In'));
    await signInButton.trigger('click');
    await flush();
    expect(sso.auth.login).toHaveBeenCalledWith({
      email: 'alice@example.com',
      password: 'secret-pass',
      org_slug: 'acme',
      service_slug: 'portal',
      redirect_uri: 'https://portal.example.com/callback',
      state: 'caller-state',
    });

    const magicLinkButton = wrapper.findAll('button').find((button) => button.text().includes('Send a magic link instead'));
    await magicLinkButton.trigger('click');
    await flush();
    expect(sso.magicLinks.request).toHaveBeenCalledWith({
      email: 'alice@example.com',
      org_slug: 'acme',
      service_slug: 'portal',
      redirect_uri: 'https://portal.example.com/callback',
      state: 'caller-state',
    });

    sso.passkeys.login.mockRejectedValueOnce(new Error('stop after context capture'));
    const passkeyButton = wrapper.findAll('button').find((button) => button.text().includes('Passkey'));
    await passkeyButton.trigger('click');
    await flush();
    expect(sso.passkeys.login).toHaveBeenCalledWith('alice@example.com', {
      org_slug: 'acme',
      service_slug: 'portal',
      redirect_uri: 'https://portal.example.com/callback',
      state: 'caller-state',
    });
  });

  it('keeps password and recovery fallbacks available after passkey failure', async () => {
    sso.passkeys.login.mockRejectedValueOnce(new Error('Passkey sign-in was cancelled.'));
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
    await continueButton.trigger('click');
    await flush();

    const passkeyButton = wrapper.findAll('button').find((button) => button.text().includes('Passkey'));
    expect(passkeyButton).toBeTruthy();
    await passkeyButton.trigger('click');
    await flush();

    expect(wrapper.text()).toContain('Passkey sign-in was cancelled.');
    expect(wrapper.find('#login-password').exists()).toBe(true);
    expect(wrapper.findAll('button').some((button) => button.text().includes('Sign In'))).toBe(true);
    expect(wrapper.findAll('button').some((button) => button.text().includes('Send a magic link instead'))).toBe(true);
    expect(wrapper.find('a[href="/forgot-password"]').exists()).toBe(true);
    expect(wrapper.findAll('button').some((button) => button.text().includes('Passkey'))).toBe(true);

    const text = wrapper.text();
    expect(text.indexOf('Password')).toBeLessThan(text.indexOf('Send a magic link instead'));
    expect(text.indexOf('Send a magic link instead')).toBeLessThan(text.indexOf('Forgot password?'));
    expect(text.indexOf('Forgot password?')).toBeLessThan(text.lastIndexOf('Passkey'));
  });
});
