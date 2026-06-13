import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryStorage, SsoClient } from '../dist/index.mjs';

function base64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtWithExp(exp, extraClaims = {}) {
  return `${base64Url({ alg: 'none', typ: 'JWT' })}.${base64Url({ exp, ...extraClaims })}.signature`;
}

test('organization select uses current token and returned session can scope later requests', async () => {
  const originalFetch = globalThis.fetch;
  const oldToken = jwtWithExp(Math.floor(Date.now() / 1000) + 300, { org: 'alpha' });
  const newToken = jwtWithExp(Math.floor(Date.now() / 1000) + 300, { org: 'beta' });
  const requests = [];

  globalThis.fetch = async (url, init) => {
    requests.push({ url: String(url), init });

    if (String(url).endsWith('/api/organizations/beta/select')) {
      return new Response(
        JSON.stringify({
          organization: { id: 'org-beta', slug: 'beta', name: 'Beta' },
          membership: { id: 'membership-beta', org_id: 'org-beta', user_id: 'user-1', role: 'member' },
          access_token: newToken,
          refresh_token: 'refresh-beta',
          expires_in: 86400,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    if (String(url).endsWith('/api/organizations/beta')) {
      return new Response(
        JSON.stringify({
          organization: { id: 'org-beta', slug: 'beta', name: 'Beta' },
          membership_count: 2,
          service_count: 1,
          tier: null,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    return new Response(JSON.stringify({ message: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const client = new SsoClient({
      baseURL: 'https://auth.example.com/',
      storage: new MemoryStorage(),
      storagePrefix: 'org_switch_',
    });
    await client.setSession({ access_token: oldToken, refresh_token: 'refresh-alpha' });

    const selected = await client.organizations.select('beta');
    assert.equal(selected.access_token, newToken);
    assert.equal(requests[0].url, 'https://auth.example.com/api/organizations/beta/select');
    assert.equal(requests[0].init.method, 'POST');
    assert.equal(requests[0].init.headers.Authorization, `Bearer ${oldToken}`);

    await client.setSession({
      access_token: selected.access_token,
      refresh_token: selected.refresh_token,
    });
    const org = await client.organizations.get('beta');

    assert.equal(org.organization.slug, 'beta');
    assert.equal(requests[1].url, 'https://auth.example.com/api/organizations/beta');
    assert.equal(requests[1].init.method, 'GET');
    assert.equal(requests[1].init.headers.Authorization, `Bearer ${newToken}`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
