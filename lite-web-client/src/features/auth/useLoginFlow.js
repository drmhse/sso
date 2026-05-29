import { computed, onMounted, ref } from 'vue';
import { GitBranch, Landmark, Mail, ShieldCheck } from '@lucide/vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import { appendTokensToRedirectUri, authRouteWithContext, getAuthFlowContext } from '@/utils/authFlowContext';
import {
  postLoginRedirect,
  storePostLoginRedirect,
} from '@/utils/redirects';

export function useLoginFlow(route, router) {
  const authStore = useAuthStore();
  const authFlowStore = useAuthFlowStore();

  const email = ref('');
  const password = ref('');
  const step = ref(1);
  const loading = ref(false);
  const lookupLoading = ref(false);
  const magicLinkLoading = ref(false);
  const passkeyLoading = ref(false);
  const statusMessage = ref('');
  const statusType = ref('error');
  const hrdData = ref(null);
  const publicAuthContext = ref(null);

  const authContext = computed(() => getAuthFlowContext(route));
  const availableProviders = computed(() => publicAuthContext.value?.available_providers || ['github', 'google', 'microsoft']);
  const providerOptions = computed(() => availableProviders.value.map((provider) => ({
    key: provider,
    label: providerLabel(provider),
    icon: iconForProvider(provider),
  })));
  const serviceDisplayName = computed(() => publicAuthContext.value?.service?.name || authContext.value.serviceLabel);
  const orgDisplayName = computed(() => publicAuthContext.value?.organization?.name || authContext.value.orgLabel);
  const redirectInvalid = computed(() => publicAuthContext.value?.service?.redirect_uri_valid === false);
  const canUseMagicLink = computed(() => (publicAuthContext.value?.auth_methods || ['password', 'magic_link']).includes('magic_link'));
  const canUsePasskey = computed(() => (publicAuthContext.value?.auth_methods || ['password', 'passkey']).includes('passkey') && sso.passkeys.isSupported());
  const statusClass = computed(() => statusType.value === 'success' ? 'alert-success' : statusType.value === 'warning' ? 'alert-warning' : 'alert-error');
  const upstreamProvider = computed(() => hrdData.value?.provider_name || '');
  const connectionId = computed(() => hrdData.value?.connection_id || '');
  const forgotPasswordTo = computed(() => authRouteWithContext(route, '/forgot-password'));

  async function loadPublicAuthContext() {
    const ctx = authContext.value;
    if (!ctx.org && !ctx.service) {
      publicAuthContext.value = null;
      return null;
    }

    try {
      publicAuthContext.value = await sso.auth.getContext({
        org: ctx.org || undefined,
        service: ctx.service || undefined,
        redirect_uri: ctx.redirectUri || undefined,
      });
    } catch (error) {
      console.warn('Failed to load public auth context:', error);
      publicAuthContext.value = null;
    }

    return publicAuthContext.value;
  }

  async function resumeAuthenticatedServiceFlow() {
    const ctx = authContext.value;
    if (!authStore.isAuthenticated || !ctx.isServiceFlow) {
      return false;
    }

    if (!ctx.redirectUri) {
      statusType.value = 'error';
      statusMessage.value = 'This sign-in request is missing a valid return URL. Please reopen the app and try again.';
      return false;
    }

    if (!publicAuthContext.value) {
      await loadPublicAuthContext();
    }

    if (!publicAuthContext.value) {
      statusType.value = 'error';
      statusMessage.value = 'AuthOS could not validate this sign-in request right now. Please try again in a moment.';
      return false;
    }

    if (redirectInvalid.value) {
      statusType.value = 'error';
      statusMessage.value = 'This sign-in request has an unregistered return URL. Contact the app developer and try again.';
      return false;
    }

    if (!authStore.token || !authStore.refreshToken) {
      statusType.value = 'error';
      statusMessage.value = 'Your AuthOS session could not be resumed. Sign in again to continue.';
      return false;
    }

    statusType.value = 'success';
    statusMessage.value = `Already signed in. Returning to ${serviceDisplayName.value}.`;
    window.location.href = appendTokensToRedirectUri(
      ctx.redirectUri,
      authStore.token,
      authStore.refreshToken,
      { state: ctx.state },
    );
    return true;
  }

  onMounted(async () => {
    if (route.query.error === 'session_expired') {
      statusType.value = 'warning';
      statusMessage.value = 'Your session expired. Sign in again to continue.';
    }

    const ctx = authContext.value;
    if (!ctx.org && !ctx.service) {
      return;
    }

    await loadPublicAuthContext();
    await resumeAuthenticatedServiceFlow();
  });

  async function handleEmailLookup() {
    if (!email.value.trim()) return;
    lookupLoading.value = true;
    statusMessage.value = '';

    try {
      hrdData.value = await sso.auth.lookupEmail(email.value.trim());
    } catch (error) {
      console.warn('Email lookup fell back to password:', error);
      hrdData.value = { auth_method: 'password' };
    } finally {
      lookupLoading.value = false;
      step.value = 2;
    }
  }

  function handleOAuthLogin(provider, providedConnectionId = null) {
    const ctx = authContext.value;
    storePostLoginRedirect(route.query.redirect);

    if (ctx.isServiceFlow && !ctx.redirectUri) {
      statusType.value = 'error';
      statusMessage.value = 'This sign-in request is missing a valid return URL.';
      return;
    }

    const org = ctx.org || 'authos';
    const service = ctx.service || 'platform';
    const loginUrl = org === 'authos' && service === 'platform' && !providedConnectionId
      ? sso.auth.getAdminLoginUrl(provider)
      : sso.auth.getLoginUrl(provider, {
          org,
          service,
          redirect_uri: ctx.redirectUri,
          state: ctx.state,
          connection_id: providedConnectionId,
        });

    window.location.href = loginUrl;
  }

  async function handlePasswordLogin() {
    if (!email.value || !password.value) return;

    const ctx = authContext.value;
    if (ctx.isServiceFlow && !ctx.redirectUri) {
      statusType.value = 'error';
      statusMessage.value = 'This sign-in request is missing a valid return URL.';
      return;
    }

    loading.value = true;
    statusMessage.value = '';

    try {
      const payload = {
        email: email.value.trim(),
        password: password.value,
      };

      if (ctx.isServiceFlow) {
        payload.org_slug = ctx.org;
        payload.service_slug = ctx.service;
        payload.redirect_uri = ctx.redirectUri;
        payload.state = ctx.state;
      }

      const response = await sso.auth.login(payload);
      await finishLoginResponse(response);
    } catch (error) {
      statusType.value = 'error';
      statusMessage.value = error.message || 'Failed to sign in.';
    } finally {
      loading.value = false;
    }
  }

  async function handleMagicLinkRequest() {
    magicLinkLoading.value = true;
    statusType.value = 'success';

    try {
      const ctx = authContext.value;
      const payload = { email: email.value.trim() };

      if (ctx.isServiceFlow) {
        payload.org_slug = ctx.org;
        payload.service_slug = ctx.service;
        payload.redirect_uri = ctx.redirectUri;
        payload.state = ctx.state;
      }

      const response = await sso.magicLinks.request(payload);
      statusMessage.value = response?.message || `Sign-in link sent to ${email.value}.`;
    } catch (error) {
      statusType.value = 'error';
      statusMessage.value = error.message || 'Failed to send a sign-in link.';
    } finally {
      magicLinkLoading.value = false;
    }
  }

  async function handlePasskeyLogin() {
    passkeyLoading.value = true;
    statusMessage.value = '';

    try {
      const ctx = authContext.value;
      const response = await sso.passkeys.login(
        email.value.trim(),
        ctx.isServiceFlow
          ? {
              org_slug: ctx.org,
              service_slug: ctx.service,
              redirect_uri: ctx.redirectUri,
              state: ctx.state,
            }
          : undefined,
      );

      await authStore.handleLoginCallback(response.access_token, response.refresh_token);

      if (ctx.isServiceFlow && ctx.redirectUri) {
        window.location.href = appendTokensToRedirectUri(
          ctx.redirectUri,
          response.access_token,
          response.refresh_token,
          { state: ctx.state },
        );
        return;
      }

      router.push(postLoginRedirect(route));
    } catch (error) {
      statusType.value = 'error';
      statusMessage.value = error.message || 'Passkey sign-in failed.';
    } finally {
      passkeyLoading.value = false;
    }
  }

  function resetToEmailStep() {
    step.value = 1;
    password.value = '';
    hrdData.value = null;
    statusMessage.value = '';
  }

  async function finishLoginResponse(response) {
    const ctx = authContext.value;
    if (response.expires_in === 300 && !response.refresh_token) {
      authFlowStore.setMfaChallenge({
        preauthToken: response.access_token,
        redirectUri: ctx.redirectUri,
        redirectPath: postLoginRedirect(route),
        supportPath: authRouteWithContext(route, '/support'),
        state: ctx.state,
      });
      await router.push('/mfa-challenge');
      return;
    }

    await authStore.handleLoginCallback(response.access_token, response.refresh_token);

    if (ctx.isServiceFlow && ctx.redirectUri) {
      window.location.href = appendTokensToRedirectUri(
        ctx.redirectUri,
        response.access_token,
        response.refresh_token,
        { state: ctx.state },
      );
      return;
    }

    await router.push(postLoginRedirect(route));
  }

  return {
    email,
    password,
    step,
    loading,
    lookupLoading,
    magicLinkLoading,
    passkeyLoading,
    statusMessage,
    statusClass,
    upstreamProvider,
    connectionId,
    publicAuthContext,
    authContext,
    providerOptions,
    serviceDisplayName,
    orgDisplayName,
    redirectInvalid,
    canUseMagicLink,
    canUsePasskey,
    forgotPasswordTo,
    handleEmailLookup,
    handleOAuthLogin,
    handlePasswordLogin,
    handleMagicLinkRequest,
    handlePasskeyLogin,
    resetToEmailStep,
  };
}

function providerLabel(provider) {
  if (provider === 'oidc') return 'Single sign-on';
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}

function iconForProvider(provider) {
  if (provider === 'github') return GitBranch;
  if (provider === 'google') return Mail;
  if (provider === 'microsoft') return Landmark;
  return ShieldCheck;
}
