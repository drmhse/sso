import { defineStore } from 'pinia';
import { ssoWithInterceptor as sso } from '@/api/interceptor';

export const useEndUsersStore = defineStore('endUsers', {
  state: () => ({
    users: [],
    total: 0,
    currentPage: 1,
    limit: 50,
    selectedUser: null,
    loading: false,
    error: null,
  }),

  getters: {
    /**
     * Get users with active subscriptions
     */
    activeUsers: (state) => state.users.filter(user =>
      user.subscriptions.some(sub => sub.status === 'active')
    ),

    /**
     * Get users by service
     */
    usersByService: (state) => (serviceId) => state.users.filter(user =>
      user.subscriptions.some(sub => sub.service_id === serviceId)
    ),

    /**
     * Get total users count
     */
    totalUsers: (state) => state.total,

    /**
     * Check if there are more pages
     */
    hasMore: (state) => state.users.length < state.total,
  },

  actions: {
    /**
     * Fetch end-users for an organization
     */
    async fetchEndUsers(orgSlug, page = 1, limit = 50) {
      this.loading = true;
      this.error = null;

      try {
        const response = await sso.organizations.endUsers.list(orgSlug, { page, limit });
        this.users = response.users;
        this.total = response.total;
        this.currentPage = response.page;
        this.limit = response.limit;
      } catch (error) {
        console.error('Failed to fetch end-users:', error);
        this.error = error.message || 'Failed to fetch end-users';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Fetch a specific end-user with detailed information
     */
    async fetchEndUser(orgSlug, userId) {
      this.loading = true;
      this.error = null;

      try {
        this.selectedUser = await sso.organizations.endUsers.get(orgSlug, userId);
        return this.selectedUser;
      } catch (error) {
        console.error('Failed to fetch end-user details:', error);
        this.error = error.message || 'Failed to fetch end-user details';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Revoke all sessions for an end-user (force logout)
     */
    async revokeUserSessions(orgSlug, userId) {
      try {
        const result = await sso.organizations.endUsers.revokeSessions(orgSlug, userId);

        // Update local state if this is the selected user
        if (this.selectedUser && this.selectedUser.user.id === userId) {
          this.selectedUser.session_count = 0;
        }

        return result;
      } catch (error) {
        console.error('Failed to revoke user sessions:', error);
        throw error;
      }
    },

    /**
     * Load next page of users
     */
    async loadMore(orgSlug) {
      if (!this.hasMore) return;

      const nextPage = this.currentPage + 1;
      this.loading = true;

      try {
        const response = await sso.organizations.endUsers.list(orgSlug, {
          page: nextPage,
          limit: this.limit,
        });

        // Append new users to existing list
        this.users = [...this.users, ...response.users];
        this.currentPage = response.page;
      } catch (error) {
        console.error('Failed to load more users:', error);
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Clear state (e.g., when switching organizations)
     */
    clear() {
      this.users = [];
      this.total = 0;
      this.currentPage = 1;
      this.selectedUser = null;
      this.error = null;
    },
  },
});
