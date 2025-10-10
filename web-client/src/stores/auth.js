import { defineStore } from 'pinia';
import { sso } from '@/api';
import { decodeJwt, isTokenExpired } from '@/utils/jwtParser';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('sso_token') || null,
    user: null,
    claims: null,
    status: 'idle', // 'idle' | 'loading' | 'authenticated' | 'error'
  }),

  getters: {
    isAuthenticated: (state) => {
      return state.status === 'authenticated' && state.token && !isTokenExpired(state.token);
    },

    isPlatformOwner: (state) => {
      return state.claims?.platform_owner === true;
    },

    currentRole: (state) => {
      return state.claims?.org_role || null;
    },

    currentOrgSlug: (state) => {
      return state.claims?.org || null;
    },

    currentOrgId: (state) => {
      return state.claims?.org_id || null;
    },

    userEmail: (state) => {
      return state.user?.email || state.claims?.email || null;
    },

    userId: (state) => {
      return state.user?.id || state.claims?.sub || null;
    },
  },

  actions: {
    /**
     * Initialize authentication state on app startup.
     * Validates the token by fetching user profile.
     */
    async initializeAuth() {
      this.status = 'loading';

      const token = localStorage.getItem('sso_token');
      if (!token) {
        this.status = 'idle';
        return;
      }

      // Check if token is expired
      if (isTokenExpired(token)) {
        this.clearAuth();
        this.status = 'idle';
        return;
      }

      // Decode token to get claims
      this.claims = decodeJwt(token);

      try {
        // Validate token by fetching user profile
        this.token = token;
        sso.setAuthToken(token);

        const userData = await sso.user.getProfile();
        this.user = userData;
        this.status = 'authenticated';
      } catch (error) {
        console.error('Failed to initialize auth:', error);
        this.clearAuth();
        this.status = 'error';
      }
    },

    /**
     * Handle login callback after OAuth redirect.
     * Stores token and fetches user data.
     * @param {string} token - JWT token from OAuth callback
     */
    async handleLoginCallback(token) {
      if (!token) {
        throw new Error('Token is required');
      }

      this.status = 'loading';

      try {
        // Store token
        localStorage.setItem('sso_token', token);
        this.token = token;

        // Decode token to get claims
        this.claims = decodeJwt(token);

        // Set token in SDK client
        sso.setAuthToken(token);

        // Fetch user profile
        const userData = await sso.user.getProfile();
        this.user = userData;
        this.status = 'authenticated';
      } catch (error) {
        console.error('Failed to handle login callback:', error);
        this.clearAuth();
        this.status = 'error';
        throw error;
      }
    },

    /**
     * Log out the user and clear all auth state.
     */
    logout() {
      this.clearAuth();
      this.status = 'idle';
    },

    /**
     * Clear authentication state and local storage.
     */
    clearAuth() {
      localStorage.removeItem('sso_token');
      this.token = null;
      this.user = null;
      this.claims = null;
      sso.setAuthToken(null);
    },

    /**
     * Refresh user profile data.
     */
    async refreshUser() {
      if (!this.isAuthenticated) {
        throw new Error('Not authenticated');
      }

      try {
        const userData = await sso.user.getProfile();
        this.user = userData;
      } catch (error) {
        console.error('Failed to refresh user:', error);
        throw error;
      }
    },
  },
});
