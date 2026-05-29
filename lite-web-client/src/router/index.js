import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import { hasServiceAuthContext } from '@/utils/authFlowContext';
import { defaultAuthenticatedRoute, storePostLoginRedirect } from '@/utils/redirects';

export const routes = [
  { path: '/', component: () => import('@/views/LoginView.vue') },
  { path: '/authorize', component: () => import('@/views/LoginView.vue') },
  { path: '/bootstrap-login', component: () => import('@/views/BootstrapLoginView.vue') },
  { path: '/callback', component: () => import('@/views/CallbackView.vue') },
  { path: '/register', component: () => import('@/views/RegisterView.vue') },
  { path: '/forgot-password', component: () => import('@/views/ForgotPasswordView.vue') },
  { path: '/reset-password', component: () => import('@/views/ResetPasswordView.vue') },
  { path: '/verify-email', component: () => import('@/views/VerifyEmailView.vue') },
  { path: '/mfa-challenge', component: () => import('@/views/MfaChallengeView.vue'), meta: { requiresChallenge: true } },
  { path: '/auth/magic-link/verify', component: () => import('@/views/MagicLinkVerifyView.vue') },
  { path: '/activate', component: () => import('@/views/ActivateDeviceView.vue') },
  { path: '/activate/success', component: () => import('@/views/ActivateDeviceView.vue') },
  { path: '/activate/mfa-challenge', component: () => import('@/views/MfaChallengeView.vue'), meta: { deviceFlow: true } },
  { path: '/support', component: () => import('@/views/SupportView.vue') },
  {
    path: '/app',
    component: () => import('@/views/WorkspaceView.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/app/overview' },
      { path: 'overview', name: 'app-overview', component: () => import('@/features/workspace/pages/OverviewPage.vue'), meta: { workspaceTitle: 'Overview' } },
      { path: 'applications', name: 'app-applications', component: () => import('@/features/workspace/pages/ApplicationsPage.vue'), meta: { workspaceTitle: 'Applications' } },
      { path: 'users', name: 'app-users', component: () => import('@/features/workspace/pages/UsersPage.vue'), meta: { workspaceTitle: 'Users' } },
      { path: 'organization', name: 'app-organization', component: () => import('@/features/workspace/pages/OrganizationPage.vue'), meta: { workspaceTitle: 'Organization' } },
      { path: 'account-security', name: 'app-account-security', component: () => import('@/features/workspace/pages/AccountSecurityPage.vue'), meta: { workspaceTitle: 'Security' } },
      { path: 'platform-setup', name: 'app-platform-setup', component: () => import('@/features/workspace/pages/PlatformSetupPage.vue'), meta: { workspaceTitle: 'Platform' } },
    ],
  },
  { path: '/invitations/accept', component: () => import('@/views/InvitationAcceptView.vue'), meta: { requiresAuth: true } },
  { path: '/home', redirect: '/app/overview' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore();
  const authFlowStore = useAuthFlowStore();

  if (authStore.status === 'idle' && localStorage.getItem('sso_access_token')) {
    try {
      await authStore.initializeAuth();
    } catch (error) {
      console.warn('Auth initialization failed during navigation:', error);
    }
  }

  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    storePostLoginRedirect(to.fullPath);
    next({
      path: '/',
    });
    return;
  }

  if (from.meta.requiresChallenge && !to.meta.requiresChallenge) {
    authFlowStore.clearMfaChallenge();
  }

  if (to.meta.requiresChallenge && !authFlowStore.hasMfaChallenge) {
    next('/');
    return;
  }

  if (authStore.isAuthenticated && ['/', '/register', '/forgot-password'].includes(to.path)) {
    if (hasServiceAuthContext(to)) {
      if (to.path !== '/') {
        next({
          path: '/',
          query: to.query,
        });
        return;
      }

      next();
      return;
    }

    next(defaultAuthenticatedRoute());
    return;
  }

  next();
});

export default router;
