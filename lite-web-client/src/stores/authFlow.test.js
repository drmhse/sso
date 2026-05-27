import { createPinia, setActivePinia } from 'pinia';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { useAuthFlowStore } from '@/stores/authFlow';
import { clearBrowserStorage } from '@/test/storage';

const STORAGE_KEY = 'authos_lite_auth_flow';

describe('authFlow store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    clearBrowserStorage();
  });

  afterEach(() => {
    clearBrowserStorage();
  });

  it('drops expired MFA challenges from session storage', () => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
      mfaChallenge: {
        preauthToken: 'expired-token',
        createdAt: Date.now() - (6 * 60 * 1000),
      },
    }));

    const store = useAuthFlowStore();

    expect(store.mfaChallenge).toBeNull();
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('persists a fresh MFA challenge with metadata', () => {
    const store = useAuthFlowStore();
    store.setMfaChallenge({
      preauthToken: 'fresh-token',
      redirectPath: '/app/overview',
    });

    expect(store.hasMfaChallenge).toBe(true);
    expect(store.mfaChallenge?.preauthToken).toBe('fresh-token');
    expect(typeof store.mfaChallenge?.createdAt).toBe('number');
  });
});
