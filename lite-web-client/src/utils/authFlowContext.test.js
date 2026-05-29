import { describe, expect, it } from 'vitest';
import { getAuthFlowContext, hasServiceAuthContext } from '@/utils/authFlowContext';

describe('auth flow context helpers', () => {
  it('detects service-auth query context on hosted entry routes', () => {
    const route = {
      query: {
        org: 'indie-blog',
        service: 'blog-app',
        redirect_uri: 'http://app.example.com/callback',
        return_to: 'http://app.example.com/settings',
        state: 'caller-state',
      },
    };

    expect(hasServiceAuthContext(route)).toBe(true);
    expect(getAuthFlowContext(route)).toMatchObject({
      org: 'indie-blog',
      service: 'blog-app',
      redirectUri: 'http://app.example.com/callback',
      returnTo: 'http://app.example.com/settings',
      state: 'caller-state',
      isServiceFlow: true,
    });
  });

  it('does not treat platform routes as service-auth context', () => {
    expect(hasServiceAuthContext({ query: {} })).toBe(false);
    expect(hasServiceAuthContext({ query: { org: 'authos', service: 'platform' } })).toBe(false);
  });
});
