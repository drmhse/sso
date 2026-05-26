import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const routes = [
  { path: '/', component: () => import('@/views/LoginView.vue') },
  { path: '/bootstrap-login', component: () => import('@/views/BootstrapLoginView.vue') },
  { path: '/callback', component: () => import('@/views/CallbackView.vue') },
  { path: '/register', component: () => import('@/views/RegisterView.vue') },
  { path: '/forgot-password', component: () => import('@/views/ForgotPasswordView.vue') },
  { path: '/reset-password', component: () => import('@/views/ResetPasswordView.vue') },
  { path: '/verify-email', component: () => import('@/views/VerifyEmailView.vue') },
  { path: '/auth/magic-link/verify', component: () => import('@/views/MagicLinkVerifyView.vue') },
  { path: '/activate', component: () => import('@/views/ActivateDeviceView.vue') },
  { path: '/activate/:pathMatch(.*)*', component: () => import('@/views/ActivateDeviceView.vue') },
  { path: '/support', component: () => import('@/views/SupportView.vue') },
  { path: '/app', component: () => import('@/views/WorkspaceView.vue'), meta: { requiresAuth: true } },
  { path: '/invitations/accept', component: () => import('@/views/InvitationAcceptView.vue'), meta: { requiresAuth: true } },
  { path: '/home', redirect: '/app' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore();

  if (authStore.status === 'idle' && localStorage.getItem('sso_access_token')) {
    try {
      await authStore.initializeAuth();
    } catch (error) {
      console.warn('Auth initialization failed during navigation:', error);
    }
  }

  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next({
      path: '/',
      query: {
        redirect: to.fullPath,
      },
    });
    return;
  }

  if (authStore.isAuthenticated && ['/', '/register', '/forgot-password'].includes(to.path)) {
    next('/app');
    return;
  }

  next();
});

export default router;
