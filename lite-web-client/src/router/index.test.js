import { describe, expect, it } from 'vitest';
import { routes } from '@/router';

describe('lite router map', () => {
  it('defines the MFA route and routed workspace children', () => {
    const paths = routes.map((route) => route.path);
    expect(paths).toContain('/authorize');
    expect(paths).toContain('/mfa-challenge');
    expect(paths).toContain('/app');
    expect(paths).toContain('/home');
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
});
