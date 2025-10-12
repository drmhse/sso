import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    // Auth routes
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/auth/Login.vue'),
      meta: { layout: 'auth' },
    },
    {
      path: '/callback',
      name: 'Callback',
      component: () => import('@/views/auth/Callback.vue'),
      meta: { layout: 'auth' },
    },
    {
      path: '/activate',
      name: 'ActivateDevice',
      component: () => import('@/views/device/ActivateDevice.vue'),
      meta: { layout: 'auth' },
    },
    {
      path: '/signup',
      name: 'Signup',
      component: () => import('@/views/auth/Signup.vue'),
      meta: { requiresAuth: true },
    },

    // Home / Landing / Redirect
    {
      path: '/',
      name: 'Landing',
      component: () => import('@/views/Landing.vue'),
      meta: { layout: 'auth' },
    },
    {
      path: '/home',
      name: 'Home',
      component: () => import('@/views/Home.vue'),
      meta: { requiresAuth: true },
    },

    // Platform Owner routes
    {
      path: '/platform',
      meta: { requiresAuth: true, requiresPlatformOwner: true },
      children: [
        {
          path: 'dashboard',
          name: 'PlatformDashboard',
          component: () => import('@/views/platform/PlatformDashboard.vue'),
        },
        {
          path: 'organizations',
          name: 'OrganizationList',
          component: () => import('@/views/platform/organizations/OrganizationList.vue'),
        },
        {
          path: 'audit-log',
          name: 'PlatformAuditLog',
          component: () => import('@/views/platform/PlatformAuditLog.vue'),
        },
      ],
    },

    // Organization routes
    {
      path: '/orgs/:orgSlug',
      meta: { requiresAuth: true },
      children: [
        {
          path: 'dashboard',
          name: 'OrgDashboard',
          component: () => import('@/views/organization/OrgDashboard.vue'),
        },
        {
          path: 'settings',
          name: 'OrgSettings',
          component: () => import('@/views/organization/OrgSettings.vue'),
        },
        {
          path: 'members',
          name: 'TeamMembers',
          component: () => import('@/views/organization/members/TeamMembers.vue'),
        },
        {
          path: 'services',
          name: 'ServiceList',
          component: () => import('@/views/organization/services/ServiceList.vue'),
        },
        {
          path: 'services/:serviceId',
          name: 'ServiceDetail',
          component: () => import('@/views/organization/services/ServiceDetail.vue'),
        },
        {
          path: 'users',
          name: 'EndUserList',
          component: () => import('@/views/organization/users/UserList.vue'),
        },
        {
          path: 'billing',
          name: 'BillingDashboard',
          component: () => import('@/views/organization/billing/BillingDashboard.vue'),
        },
      ],
    },

    // User routes
    {
      path: '/invitations',
      name: 'MyInvitations',
      component: () => import('@/views/user/MyInvitations.vue'),
      meta: { requiresAuth: true },
    },
    {
      path: '/settings/connections',
      name: 'ConnectedAccounts',
      component: () => import('@/views/user/ConnectedAccounts.vue'),
      meta: { requiresAuth: true },
    },

    // 404
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: () => import('@/views/NotFound.vue'),
    },
  ],
});

// Navigation guards
let authInitialized = false;

router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore();

  // Initialize auth on first navigation
  if (!authInitialized) {
    await authStore.initializeAuth();
    authInitialized = true;
  }

  // Check if route requires authentication
  if (to.meta.requiresAuth) {
    if (!authStore.isAuthenticated) {
      return next({
        name: 'Login',
        query: { redirect: to.fullPath },
      });
    }

    // Check if route requires platform owner role
    if (to.meta.requiresPlatformOwner && !authStore.isPlatformOwner) {
      return next({ name: 'Home' });
    }
  }

  // Redirect authenticated users away from login and landing
  if ((to.name === 'Login' || to.name === 'Landing') && authStore.isAuthenticated) {
    return next({ name: 'Home' });
  }

  next();
});

export default router;
