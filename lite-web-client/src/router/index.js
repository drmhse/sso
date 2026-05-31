import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import { firstQueryValue, hasServiceAuthContext } from '@/utils/authFlowContext';
import { defaultAuthenticatedRoute, loginRouteForProtectedTarget } from '@/utils/redirects';

export const FOCUSED_ACCOUNT_SECURITY_PATH = '/account/security';
export const WORKSPACE_ACCOUNT_SECURITY_PATH = '/app/account-security';

export function focusedAccountSecurityRedirect(to) {
  if (to.path !== WORKSPACE_ACCOUNT_SECURITY_PATH || !firstQueryValue(to.query?.return_to)) {
    return null;
  }

  return {
    path: FOCUSED_ACCOUNT_SECURITY_PATH,
    query: to.query,
    replace: true,
  };
}

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
  { path: FOCUSED_ACCOUNT_SECURITY_PATH, name: 'account-security', component: () => import('@/views/HostedAccountSecurityView.vue'), meta: { requiresAuth: true } },
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
  const accountSecurityRedirect = focusedAccountSecurityRedirect(to);

  if (accountSecurityRedirect) {
    next(accountSecurityRedirect);
    return;
  }

  if (authStore.status === 'idle' && localStorage.getItem('sso_access_token')) {
    try {
      await authStore.initializeAuth();
    } catch (error) {
      console.warn('Auth initialization failed during navigation:', error);
    }
  }

  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next(loginRouteForProtectedTarget(to.fullPath));
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
