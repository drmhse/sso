import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryStorage, SessionManager } from '../dist/index.mjs';

function base64Url(value) {
  return Buffer.from(JSON.stringify(value))
    .toString('base64url');
}

function jwtWithExp(exp) {
  return `${base64Url({ alg: 'none', typ: 'JWT' })}.${base64Url({ exp })}.signature`;
}

function createSession(refreshHandler, minValiditySeconds = 30) {
  return new SessionManager(
    new MemoryStorage(),
    refreshHandler,
    {
      storageKeyPrefix: 'test_',
      minValiditySeconds,
    },
  );
}

test('returns a fresh access token without refreshing', async () => {
  let refreshCalls = 0;
  const session = createSession(async () => {
    refreshCalls += 1;
    return {
      access_token: jwtWithExp(Math.floor(Date.now() / 1000) + 300),
      refresh_token: 'refresh-2',
      expires_in: 300,
    };
  });

  const token = jwtWithExp(Math.floor(Date.now() / 1000) + 120);
  await session.setSession({ access_token: token, refresh_token: 'refresh-1' });

  assert.equal(await session.getToken(), token);
  assert.equal(refreshCalls, 0);
});

test('refreshes an access token before it expires', async () => {
  let refreshTokenSeen = null;
  const refreshedToken = jwtWithExp(Math.floor(Date.now() / 1000) + 300);
  const session = createSession(async (refreshToken) => {
    refreshTokenSeen = refreshToken;
    return {
      access_token: refreshedToken,
      refresh_token: 'refresh-2',
      expires_in: 300,
    };
  });

  await session.setSession({
    access_token: jwtWithExp(Math.floor(Date.now() / 1000) + 10),
    refresh_token: 'refresh-1',
  });

  assert.equal(await session.getToken(), refreshedToken);
  assert.equal(refreshTokenSeen, 'refresh-1');
  assert.equal(await session.getToken(), refreshedToken);
});

test('deduplicates concurrent proactive refreshes', async () => {
  let refreshCalls = 0;
  let releaseRefresh;
  const refreshedToken = jwtWithExp(Math.floor(Date.now() / 1000) + 300);
  const refreshStarted = new Promise((resolve) => {
    releaseRefresh = resolve;
  });
  const session = createSession(async () => {
    refreshCalls += 1;
    await refreshStarted;
    return {
      access_token: refreshedToken,
      refresh_token: 'refresh-2',
      expires_in: 300,
    };
  });

  await session.setSession({
    access_token: jwtWithExp(Math.floor(Date.now() / 1000) + 5),
    refresh_token: 'refresh-1',
  });

  const first = session.getToken();
  const second = session.getToken();
  releaseRefresh();

  assert.deepEqual(await Promise.all([first, second]), [refreshedToken, refreshedToken]);
  assert.equal(refreshCalls, 1);
});

test('clears an expired access token when no refresh token is available', async () => {
  const session = createSession(async () => {
    throw new Error('refresh should not be called');
  });

  await session.setSession({ access_token: jwtWithExp(Math.floor(Date.now() / 1000) - 1) });

  assert.equal(await session.getToken(), null);
  assert.equal(session.isAuthenticated(), false);
});

test('leaves malformed or opaque tokens untouched', async () => {
  let refreshCalls = 0;
  const session = createSession(async () => {
    refreshCalls += 1;
    return {
      access_token: 'new-token',
      refresh_token: 'refresh-2',
      expires_in: 300,
    };
  });

  await session.setSession({ access_token: 'opaque-token', refresh_token: 'refresh-1' });

  assert.equal(await session.getToken(), 'opaque-token');
  assert.equal(refreshCalls, 0);
});

test('returns null after a failed proactive refresh clears the session', async () => {
  const session = createSession(async () => {
    throw new Error('refresh failed');
  });

  await session.setSession({
    access_token: jwtWithExp(Math.floor(Date.now() / 1000) + 5),
    refresh_token: 'refresh-1',
  });

  assert.equal(await session.getToken(), null);
  assert.equal(session.isAuthenticated(), false);
});

test('in-flight storage load does not overwrite a newer session', async () => {
  let releaseAccessRead;
  let releaseRefreshRead;
  const storage = {
    values: new Map(),
    getItem(key) {
      if (key === 'test_access_token') {
        return new Promise((resolve) => {
          releaseAccessRead = () => resolve(jwtWithExp(Math.floor(Date.now() / 1000) + 300));
        });
      }
      if (key === 'test_refresh_token') {
        return new Promise((resolve) => {
          releaseRefreshRead = () => resolve('stale-refresh');
        });
      }
      return null;
    },
    setItem(key, value) {
      this.values.set(key, value);
    },
    removeItem(key) {
      this.values.delete(key);
    },
  };
  const session = new SessionManager(storage, async () => {
    throw new Error('refresh should not be called');
  }, {
    storageKeyPrefix: 'test_',
  });

  const load = session.loadSession();
  await Promise.resolve();

  const currentToken = jwtWithExp(Math.floor(Date.now() / 1000) + 300);
  await session.setSession({
    access_token: currentToken,
    refresh_token: 'current-refresh',
  });

  releaseAccessRead();
  await Promise.resolve();
  releaseRefreshRead();
  await load;

  assert.equal(await session.getToken(), currentToken);
});
