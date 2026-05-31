import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  FOCUSED_ACCOUNT_SECURITY_PATH,
  WORKSPACE_ACCOUNT_SECURITY_PATH,
  focusedAccountSecurityRedirect,
  default as router,
  routes,
} from '@/router';

function createStorageStub() {
  const entries = new Map();

  return {
    get length() {
      return entries.size;
    },
    clear() {
      entries.clear();
    },
    getItem(key) {
      return entries.has(key) ? entries.get(key) : null;
    },
    key(index) {
      return Array.from(entries.keys())[index] || null;
    },
    removeItem(key) {
      entries.delete(key);
    },
    setItem(key, value) {
      entries.set(key, String(value));
    },
  };
}

function installBrowserStorageStubs() {
  vi.stubGlobal('localStorage', createStorageStub());
  vi.stubGlobal('sessionStorage', createStorageStub());
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('lite router map', () => {
  it('defines the MFA route and routed workspace children', () => {
    const paths = routes.map((route) => route.path);
    expect(paths).toContain('/authorize');
    expect(paths).toContain('/mfa-challenge');
    expect(paths).toContain(FOCUSED_ACCOUNT_SECURITY_PATH);
    expect(paths).toContain('/app');
    expect(paths).toContain('/home');
  });

  it('registers the focused account security route as authenticated', () => {
    const route = routes.find((entry) => entry.path === FOCUSED_ACCOUNT_SECURITY_PATH);

    expect(route.name).toBe('account-security');
    expect(route.meta.requiresAuth).toBe(true);
  });

  it('redirects root workspace and home to the overview page', () => {
    const homeRoute = routes.find((route) => route.path === '/home');
    const appRoute = routes.find((route) => route.path === '/app');
    const defaultChild = appRoute.children.find((child) => child.path === '');

    expect(homeRoute.redirect).toBe('/app/overview');
    expect(defaultChild.redirect).toBe('/app/overview');
  });

  it('registers all workspace child pages', () => {
    const appRoute = routes.find((route) => route.path === '/app');
    const childNames = appRoute.children.map((child) => child.name).filter(Boolean);

    expect(childNames).toEqual([
      'app-overview',
      'app-applications',
      'app-users',
      'app-organization',
      'app-account-security',
      'app-platform-setup',
    ]);
  });

  it('moves app-referred account security links to the focused route', () => {
    const query = {
      org: 'queuezero',
      service: 'flux',
      return_to: 'https://flux.example.com/settings',
    };

    expect(focusedAccountSecurityRedirect({
      path: WORKSPACE_ACCOUNT_SECURITY_PATH,
      query,
    })).toEqual({
      path: FOCUSED_ACCOUNT_SECURITY_PATH,
      query,
      replace: true,
    });
  });

  it('keeps direct workspace account security links inside the workspace', () => {
    expect(focusedAccountSecurityRedirect({
      path: WORKSPACE_ACCOUNT_SECURITY_PATH,
      query: {},
    })).toBeNull();
  });

  it('preserves legacy account security deep links through the auth guard', async () => {
    installBrowserStorageStubs();
    setActivePinia(createPinia());

    await router.push({
      path: WORKSPACE_ACCOUNT_SECURITY_PATH,
      query: {
        org: 'queuezero',
        service: 'flux',
        return_to: 'https://flux.example.com/settings',
      },
    });

    expect(router.currentRoute.value.path).toBe('/');
    expect(router.currentRoute.value.query.redirect).toBe(
      '/account/security?org=queuezero&service=flux&return_to=https://flux.example.com/settings',
    );
  });

  it('preserves focused account security links through the auth guard', async () => {
    installBrowserStorageStubs();
    setActivePinia(createPinia());

    await router.push({
      path: FOCUSED_ACCOUNT_SECURITY_PATH,
      query: {
        org: 'queuezero',
        service: 'flux',
        return_to: 'https://flux.example.com/settings',
      },
    });

    expect(router.currentRoute.value.path).toBe('/');
    expect(router.currentRoute.value.query.redirect).toBe(
      '/account/security?org=queuezero&service=flux&return_to=https://flux.example.com/settings',
    );
  });
});
