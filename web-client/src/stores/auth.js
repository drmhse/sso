import { defineStore } from 'pinia';
import { sso } from '@/api';
import { decodeJwt, isTokenExpired } from '@/utils/jwtParser';
import router from '@/router';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('sso_token') || null,
    refreshToken: localStorage.getItem('sso_refresh_token') || null,
    user: JSON.parse(localStorage.getItem('sso_user') || 'null'),
    claims: JSON.parse(localStorage.getItem('sso_claims') || 'null'),
    status: localStorage.getItem('sso_status') || 'idle', // 'idle' | 'loading' | 'authenticated' | 'error'
  }),

  getters: {
    isAuthenticated: (state) => {
      return state.status === 'authenticated' && state.token && !isTokenExpired(state.token);
    },

    isPlatformOwner: (state) => {
      return state.claims?.is_platform_owner === true;
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
     * Uses cached data for instant startup, validates in background.
     */
    async initializeAuth() {
      const token = localStorage.getItem('sso_token');
      if (!token) {
        this.status = 'idle';
        localStorage.setItem('sso_status', 'idle');
        return;
      }

      // Check if token is expired
      if (isTokenExpired(token)) {
        this.clearAuth();
        this.status = 'idle';
        localStorage.setItem('sso_status', 'idle');
        return;
      }

      // If we have cached user data and status is authenticated, use it immediately
      const cachedStatus = localStorage.getItem('sso_status');
      const cachedUser = localStorage.getItem('sso_user');

      if (cachedStatus === 'authenticated' && cachedUser) {
        this.status = 'authenticated';
        this.token = token;
        this.user = JSON.parse(cachedUser);
        this.claims = decodeJwt(token);
        sso.setAuthToken(token);

        // Validate in background
        this.validateSession().catch(error => {
          try {
            this.handleAuthError(error);
          } catch (e) {
            // Error already handled
          }
        });

        return;
      }

      // Otherwise, validate immediately
      this.status = 'loading';
      this.claims = decodeJwt(token);

      try {
        this.token = token;
        sso.setAuthToken(token);

        const userData = await sso.user.getProfile();
        this.user = userData;
        localStorage.setItem('sso_user', JSON.stringify(userData));

        this.status = 'authenticated';
        localStorage.setItem('sso_status', 'authenticated');
      } catch (error) {
        console.error('Failed to initialize auth:', error);
        try {
          this.handleAuthError(error);
        } catch (e) {
          this.status = 'error';
          localStorage.setItem('sso_status', 'error');
        }
      }
    },

    /**
     * Validate session in background without blocking UI
     */
    async validateSession() {
      try {
        await sso.user.getProfile();
      } catch (error) {
        throw error;
      }
    },

    /**
     * Handle login callback after OAuth redirect.
     * Stores both access and refresh tokens, then fetches user data.
     * @param {string} accessToken - JWT access token from OAuth callback
     * @param {string} refreshToken - Refresh token from OAuth callback
     */
    async handleLoginCallback(accessToken, refreshToken) {
      if (!accessToken || !refreshToken) {
        throw new Error('Both access token and refresh token are required');
      }

      this.status = 'loading';
      localStorage.setItem('sso_status', 'loading');

      try {
        // Store both tokens
        localStorage.setItem('sso_token', accessToken);
        localStorage.setItem('sso_refresh_token', refreshToken);
        this.token = accessToken;
        this.refreshToken = refreshToken;

        // Decode token to get claims
        this.claims = decodeJwt(accessToken);
        localStorage.setItem('sso_claims', JSON.stringify(this.claims));

        // Set token in SDK client
        sso.setAuthToken(accessToken);

        // Fetch user profile
        const userData = await sso.user.getProfile();
        this.user = userData;
        localStorage.setItem('sso_user', JSON.stringify(userData));

        this.status = 'authenticated';
        localStorage.setItem('sso_status', 'authenticated');
      } catch (error) {
        console.error('Failed to handle login callback:', error);
        this.clearAuth();
        this.status = 'error';
        localStorage.setItem('sso_status', 'error');
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
      localStorage.removeItem('sso_refresh_token');
      localStorage.removeItem('sso_user');
      localStorage.removeItem('sso_claims');
      localStorage.removeItem('sso_status');
      this.token = null;
      this.refreshToken = null;
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

    /**
     * Refresh the JWT access token using the refresh token.
     * This implements automatic token rotation.
     * @returns {Promise<{accessToken: string, refreshToken: string}>}
     */
    async refreshAccessToken() {
      if (!this.refreshToken) {
        throw new Error('No refresh token available');
      }

      try {
        const response = await sso.auth.refreshToken(this.refreshToken);

        // Update state and storage with new tokens
        this.token = response.access_token;
        this.refreshToken = response.refresh_token;
        localStorage.setItem('sso_token', response.access_token);
        localStorage.setItem('sso_refresh_token', response.refresh_token);
        sso.setAuthToken(response.access_token);

        // Update claims
        this.claims = decodeJwt(response.access_token);
        localStorage.setItem('sso_claims', JSON.stringify(this.claims));

        return {
          accessToken: response.access_token,
          refreshToken: response.refresh_token,
        };
      } catch (error) {
        console.error('Failed to refresh access token:', error);
        // If refresh fails, the session is invalid - clear auth and redirect
        this.logout();
        throw error;
      }
    },

    /**
     * Handle authentication errors globally.
     * Clears state and redirects to login if session is invalid.
     */
    handleAuthError(error) {
      console.error('Auth error:', error);

      // Check if it's an authentication error
      const isAuthError =
        error?.response?.status === 401 ||
        error?.response?.status === 403 ||
        error?.message?.toLowerCase().includes('unauthorized') ||
        error?.message?.toLowerCase().includes('session');

      if (isAuthError) {
        this.clearAuth();
        this.status = 'idle';

        // Only redirect if not already on login page
        if (router.currentRoute.value.path !== '/login') {
          router.push({
            name: 'Login',
            query: {
              error: 'session_expired',
              redirect: router.currentRoute.value.fullPath
            }
          });
        }
      }

      throw error; // Re-throw for component-level handling if needed
    },
  },
});
