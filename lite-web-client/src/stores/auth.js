import { defineStore } from 'pinia';
import router from '@/router';
import { sso } from '@/lib/api';
import { decodeJwt, isTokenExpired } from '@/utils/jwt';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('sso_access_token') || null,
    refreshToken: localStorage.getItem('sso_refresh_token') || null,
    user: JSON.parse(localStorage.getItem('sso_user') || 'null'),
    claims: JSON.parse(localStorage.getItem('sso_claims') || 'null'),
    status: localStorage.getItem('sso_status') || 'idle',
    permissions: JSON.parse(localStorage.getItem('sso_permissions') || '[]'),
    plan: localStorage.getItem('sso_plan') || null,
    features: JSON.parse(localStorage.getItem('sso_features') || '[]'),
    activeOrgRole: localStorage.getItem('sso_active_org_role') || null,
  }),

  getters: {
    isAuthenticated: (state) => (
      state.status === 'authenticated' && Boolean(state.token) && !isTokenExpired(state.token)
    ),
    isPlatformOwner: (state) => state.claims?.is_platform_owner === true,
    currentOrgSlug: (state) => state.claims?.org || null,
    currentOrgId: (state) => state.claims?.org_id || null,
    userEmail: (state) => state.user?.email || state.claims?.email || null,
    userId: (state) => state.user?.id || state.claims?.sub || null,
  },

  actions: {
    async initializeAuth() {
      const token = localStorage.getItem('sso_access_token');
      if (!token || isTokenExpired(token)) {
        this.clearAuth();
        this.status = 'idle';
        localStorage.setItem('sso_status', 'idle');
        return;
      }

      this.token = token;
      this.claims = decodeJwt(token);
      sso.setAuthToken(token);

      const cachedStatus = localStorage.getItem('sso_status');
      const cachedUser = localStorage.getItem('sso_user');
      if (cachedStatus === 'authenticated' && cachedUser) {
        this.user = JSON.parse(cachedUser);
        this.status = 'authenticated';
        return;
      }

      this.status = 'loading';
      localStorage.setItem('sso_status', 'loading');

      try {
        const userData = await sso.user.getProfile();
        this.user = userData;
        this.permissions = userData.permissions || [];
        this.plan = userData.plan || null;
        this.features = userData.features || [];
        localStorage.setItem('sso_user', JSON.stringify(userData));
        localStorage.setItem('sso_permissions', JSON.stringify(this.permissions));
        localStorage.setItem('sso_plan', this.plan || '');
        localStorage.setItem('sso_features', JSON.stringify(this.features));
        this.status = 'authenticated';
        localStorage.setItem('sso_status', 'authenticated');
      } catch (error) {
        this.handleAuthError(error);
      }
    },

    async handleLoginCallback(accessToken, refreshToken) {
      if (!accessToken || !refreshToken) {
        throw new Error('Both access token and refresh token are required');
      }

      this.status = 'loading';
      localStorage.setItem('sso_status', 'loading');
      this.token = accessToken;
      this.refreshToken = refreshToken;
      this.claims = decodeJwt(accessToken);
      this.activeOrgRole = null;

      localStorage.setItem('sso_access_token', accessToken);
      localStorage.setItem('sso_refresh_token', refreshToken);
      localStorage.setItem('sso_claims', JSON.stringify(this.claims));
      localStorage.removeItem('sso_active_org_role');

      await sso.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

      const userData = await sso.user.getProfile();
      this.user = userData;
      this.permissions = userData.permissions || [];
      this.plan = userData.plan || null;
      this.features = userData.features || [];
      localStorage.setItem('sso_user', JSON.stringify(userData));
      localStorage.setItem('sso_permissions', JSON.stringify(this.permissions));
      localStorage.setItem('sso_plan', this.plan || '');
      localStorage.setItem('sso_features', JSON.stringify(this.features));
      this.status = 'authenticated';
      localStorage.setItem('sso_status', 'authenticated');
    },

    async completeMfaChallenge(preauthToken, code, deviceCodeId = null) {
      const response = await sso.auth.verifyMfa(preauthToken, code, deviceCodeId);
      await this.handleLoginCallback(response.access_token, response.refresh_token);
      return response;
    },

    async refreshUser() {
      const userData = await sso.user.getProfile();
      this.user = userData;
      this.permissions = userData.permissions || [];
      this.plan = userData.plan || null;
      this.features = userData.features || [];
      localStorage.setItem('sso_user', JSON.stringify(userData));
      localStorage.setItem('sso_permissions', JSON.stringify(this.permissions));
      localStorage.setItem('sso_plan', this.plan || '');
      localStorage.setItem('sso_features', JSON.stringify(this.features));
    },

    async updateTokens(accessToken, refreshToken, role = null) {
      this.token = accessToken;
      this.refreshToken = refreshToken;
      this.claims = decodeJwt(accessToken);
      this.activeOrgRole = role;
      localStorage.setItem('sso_access_token', accessToken);
      localStorage.setItem('sso_refresh_token', refreshToken);
      localStorage.setItem('sso_claims', JSON.stringify(this.claims));
      if (role) localStorage.setItem('sso_active_org_role', role);
      sso.setAuthToken(accessToken);
      await sso.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
      await this.refreshUser();
    },

    async refreshAccessToken() {
      if (!this.refreshToken) throw new Error('No refresh token available');
      const response = await sso.auth.refreshToken(this.refreshToken);
      this.token = response.access_token;
      this.refreshToken = response.refresh_token;
      this.claims = decodeJwt(response.access_token);
      localStorage.setItem('sso_access_token', response.access_token);
      localStorage.setItem('sso_refresh_token', response.refresh_token);
      localStorage.setItem('sso_claims', JSON.stringify(this.claims));
      sso.setAuthToken(response.access_token);
      return response;
    },

    clearAuth() {
      localStorage.removeItem('sso_access_token');
      localStorage.removeItem('sso_refresh_token');
      localStorage.removeItem('sso_user');
      localStorage.removeItem('sso_claims');
      localStorage.removeItem('sso_status');
      localStorage.removeItem('sso_permissions');
      localStorage.removeItem('sso_plan');
      localStorage.removeItem('sso_features');
      localStorage.removeItem('sso_active_org_role');
      this.token = null;
      this.refreshToken = null;
      this.user = null;
      this.claims = null;
      this.permissions = [];
      this.plan = null;
      this.features = [];
      this.activeOrgRole = null;
      sso.setAuthToken(null);
    },

    async logout() {
      try {
        await sso.auth.logout();
      } catch (error) {
        console.warn('Logout request failed:', error);
      } finally {
        this.clearAuth();
        this.status = 'idle';
        localStorage.setItem('sso_status', 'idle');
      }
    },

    handleAuthError(error) {
      console.error('Auth error:', error);
      this.clearAuth();
      this.status = 'idle';
      localStorage.setItem('sso_status', 'idle');

      if (router.currentRoute.value.path !== '/') {
        router.push({
          path: '/',
          query: {
            error: 'session_expired',
            redirect: router.currentRoute.value.fullPath,
          },
        });
      }

      throw error;
    },
  },
});
