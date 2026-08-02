import assert from 'node:assert/strict';
import test from 'node:test';
import { OrganizationsModule } from '../dist/index.mjs';

function recordingHttp() {
  const requests = [];
  const http = {};
  for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
    http[method] = async (path, body) => {
      requests.push({ method: method.toUpperCase(), path, body });
      return { data: {} };
    };
  }
  return { http, requests };
}

test('organization SDK uses the API ownership-transfer route', async () => {
  const { http, requests } = recordingHttp();
  const organizations = new OrganizationsModule(http);

  await organizations.members.transferOwnership('acme', { new_owner_email: 'next@example.com' });

  assert.deepEqual(requests, [{
    method: 'POST',
    path: '/api/organizations/acme/transfer-ownership',
    body: { new_owner_email: 'next@example.com' },
  }]);
});

test('organization SDK uses PUT for SIEM replacement updates', async () => {
  const { http, requests } = recordingHttp();
  const organizations = new OrganizationsModule(http);

  await organizations.siem.update('acme', 'siem-1', { enabled: false });

  assert.deepEqual(requests, [{
    method: 'PUT',
    path: '/api/organizations/acme/siem-configs/siem-1',
    body: { enabled: false },
  }]);
});

test('upstream-provider SDK matches the routed CRUD methods', async () => {
  const { http, requests } = recordingHttp();
  const organizations = new OrganizationsModule(http);

  await organizations.upstreamProviders.get('acme', 'provider-1');
  await organizations.upstreamProviders.update('acme', 'provider-1', { enabled: false });

  assert.deepEqual(requests, [
    {
      method: 'GET',
      path: '/api/organizations/acme/upstream-providers/provider-1',
      body: undefined,
    },
    {
      method: 'PATCH',
      path: '/api/organizations/acme/upstream-providers/provider-1',
      body: { enabled: false },
    },
  ]);
});

test('member add accepts the created invitation by nested response ID', async () => {
  const requests = [];
  const http = {
    post: async (path, body) => {
      requests.push({ method: 'POST', path, body });
      if (path.endsWith('/invitations')) {
        return {
          data: {
            invitation: { id: 'inv-1', email: 'person@example.com', role: 'member' },
            inviter: { id: 'owner-1', email: 'owner@example.com' },
            token: 'one-time-token',
          },
        };
      }
      return { data: null };
    },
  };
  const organizations = new OrganizationsModule(http);

  const invitation = await organizations.members.add('acme', {
    email: 'person@example.com',
    role: 'member',
  });

  assert.equal(invitation.id, 'inv-1');
  assert.deepEqual(requests, [
    {
      method: 'POST',
      path: '/api/organizations/acme/invitations',
      body: { email: 'person@example.com', role: 'member' },
    },
    {
      method: 'POST',
      path: '/api/organizations/acme/invitations/inv-1/accept',
      body: undefined,
    },
  ]);
});
