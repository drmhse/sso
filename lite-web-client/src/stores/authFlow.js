import { defineStore } from 'pinia';

const STORAGE_KEY = 'authos_lite_auth_flow';
const MFA_CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000;

function normalizeChallenge(rawChallenge) {
  if (!rawChallenge || typeof rawChallenge.preauthToken !== 'string' || !rawChallenge.preauthToken.trim()) {
    return null;
  }

  const createdAt = Number(rawChallenge.createdAt || 0);
  if (!createdAt || (Date.now() - createdAt) > MFA_CHALLENGE_MAX_AGE_MS) {
    return null;
  }

  return {
    preauthToken: rawChallenge.preauthToken,
    redirectUri: rawChallenge.redirectUri || '',
    redirectPath: rawChallenge.redirectPath || '',
    deviceCodeId: rawChallenge.deviceCodeId || '',
    supportPath: rawChallenge.supportPath || '/support',
    state: rawChallenge.state || '',
    createdAt,
  };
}

function readState() {
  if (typeof window === 'undefined') {
    return { mfaChallenge: null };
  }

  try {
    const parsed = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null');
    const mfaChallenge = normalizeChallenge(parsed?.mfaChallenge || null);
    if (!mfaChallenge) {
      sessionStorage.removeItem(STORAGE_KEY);
    }
    return { mfaChallenge };
  } catch (error) {
    sessionStorage.removeItem(STORAGE_KEY);
    return { mfaChallenge: null };
  }
}

function persistState(mfaChallenge) {
  if (typeof window === 'undefined') return;

  if (!mfaChallenge) {
    sessionStorage.removeItem(STORAGE_KEY);
    return;
  }

  sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ mfaChallenge }));
}

export const useAuthFlowStore = defineStore('authFlow', {
  state: () => readState(),

  getters: {
    hasMfaChallenge: (state) => Boolean(state.mfaChallenge?.preauthToken),
  },

  actions: {
    setMfaChallenge(payload) {
      this.mfaChallenge = {
        preauthToken: payload.preauthToken,
        redirectUri: payload.redirectUri || '',
        redirectPath: payload.redirectPath || '',
        deviceCodeId: payload.deviceCodeId || '',
        supportPath: payload.supportPath || '/support',
        state: payload.state || '',
        createdAt: Date.now(),
      };
      persistState(this.mfaChallenge);
    },

    clearMfaChallenge() {
      this.mfaChallenge = null;
      persistState(null);
    },
  },
});
