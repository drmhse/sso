import { afterEach, describe, expect, it } from 'vitest';
import {
  clearPostLoginRedirect,
  postLoginRedirect,
  storePostLoginRedirect,
  takePostLoginRedirect,
} from '@/utils/redirects';

afterEach(() => {
  clearPostLoginRedirect();
});

describe('redirect helpers', () => {
  it('consumes the stored post-login redirect when no query redirect is present', () => {
    storePostLoginRedirect('/invitations/accept?token=invite-token');

    expect(postLoginRedirect({ query: {} })).toBe('/invitations/accept?token=invite-token');
    expect(takePostLoginRedirect()).toBeNull();
  });

  it('rejects unsafe redirect targets', () => {
    expect(storePostLoginRedirect('https://evil.example.com')).toBeNull();
    expect(postLoginRedirect({ query: { redirect: '//evil.example.com' } })).toBe('/app/overview');
  });
});
