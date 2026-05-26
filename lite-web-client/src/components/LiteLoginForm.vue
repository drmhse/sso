<template>
  <div class="stack">
    <div v-if="statusMessage" class="alert" :class="statusClass">{{ statusMessage }}</div>

    <div
      v-if="authContext.isServiceFlow"
      class="alert alert-warning"
    >
      Signing in to {{ serviceDisplayName }} for {{ orgDisplayName }}.
      <span v-if="redirectInvalid"> This request has an unregistered return URL.</span>
    </div>

    <div v-if="step === 1" class="stack">
      <div class="button-row">
        <BaseButton
          v-for="provider in availableProviders"
          :key="provider"
          variant="secondary"
          @click="handleOAuthLogin(provider)"
        >
          Continue with {{ providerLabel(provider) }}
        </BaseButton>
      </div>

      <div class="field">
        <label for="email">Email address</label>
        <input
          id="email"
          v-model="email"
          class="input"
          type="email"
          placeholder="name@company.com"
          @keyup.enter="handleEmailLookup"
        />
      </div>

      <BaseButton :loading="lookupLoading" @click="handleEmailLookup">
        Continue with email
      </BaseButton>
    </div>

    <div v-else class="stack">
      <div class="meta-item">
        <div class="meta-label">Email</div>
        <div class="meta-value" style="font-size: 1rem;">{{ email }}</div>
      </div>

      <div v-if="hrdData?.auth_method === 'upstream'" class="stack">
        <div class="alert alert-warning">
          This account is managed by {{ hrdData.provider_name || 'an external identity provider' }}.
        </div>
        <BaseButton @click="handleOAuthLogin('oidc', hrdData.connection_id)">
          Continue with {{ hrdData.provider_name || 'single sign-on' }}
        </BaseButton>
      </div>

      <template v-else>
        <div class="button-row" v-if="canUseMagicLink || canUsePasskey">
          <BaseButton v-if="canUseMagicLink" variant="secondary" :loading="magicLinkLoading" @click="handleMagicLinkRequest">
            Email me a sign-in link
          </BaseButton>
          <BaseButton v-if="canUsePasskey" variant="secondary" :loading="passkeyLoading" @click="handlePasskeyLogin">
            Sign in with passkey
          </BaseButton>
        </div>

        <div class="field">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="password"
            class="input"
            type="password"
            placeholder="Password"
            @keyup.enter="handlePasswordLogin"
          />
        </div>

        <div class="button-row" style="justify-content: space-between;">
          <router-link :to="authRouteWithContext(route, '/forgot-password')" class="muted">
            Forgot password?
          </router-link>
          <button class="btn btn-secondary" @click="step = 1">Change email</button>
        </div>

        <BaseButton :loading="loading" @click="handlePasswordLogin">
          Sign in
        </BaseButton>
      </template>
    </div>

    <MfaChallengeModal
      :is-open="showMfaChallenge"
      :preauth-token="preauthToken"
      @success="handleMfaSuccess"
      @close="showMfaChallenge = false"
      @lost-device="router.push(authRouteWithContext(route, '/support'))"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { authRouteWithContext, appendTokensToRedirectUri, getAuthFlowContext } from '@/utils/authFlowContext';
import { defaultAuthenticatedRoute, normalizeInternalRedirect, storePostLoginRedirect } from '@/utils/redirects';
import BaseButton from './BaseButton.vue';
import MfaChallengeModal from './MfaChallengeModal.vue';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

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
const showMfaChallenge = ref(false);
const preauthToken = ref('');

const authContext = computed(() => getAuthFlowContext(route));
const availableProviders = computed(() => publicAuthContext.value?.available_providers || ['github', 'google', 'microsoft']);
const serviceDisplayName = computed(() => publicAuthContext.value?.service?.name || authContext.value.serviceLabel);
const orgDisplayName = computed(() => publicAuthContext.value?.organization?.name || authContext.value.orgLabel);
const redirectInvalid = computed(() => publicAuthContext.value?.service?.redirect_uri_valid === false);
const canUseMagicLink = computed(() => (publicAuthContext.value?.auth_methods || ['password', 'magic_link']).includes('magic_link'));
const canUsePasskey = computed(() => (publicAuthContext.value?.auth_methods || ['password', 'passkey']).includes('passkey') && sso.passkeys.isSupported());
const statusClass = computed(() => statusType.value === 'success' ? 'alert-success' : statusType.value === 'warning' ? 'alert-warning' : 'alert-error');

onMounted(async () => {
  if (route.query.error === 'session_expired') {
    statusType.value = 'warning';
    statusMessage.value = 'Your session expired. Sign in again to continue.';
  }

  const ctx = authContext.value;
  if (!ctx.org && !ctx.service) return;

  try {
    publicAuthContext.value = await sso.auth.getContext({
      org: ctx.org || undefined,
      service: ctx.service || undefined,
      redirect_uri: ctx.redirectUri || undefined,
    });
  } catch (error) {
    console.warn('Failed to load public auth context:', error);
  }
});

function providerLabel(provider) {
  return provider === 'oidc' ? 'single sign-on' : provider.charAt(0).toUpperCase() + provider.slice(1);
}

async function handleEmailLookup() {
  if (!email.value) return;
  lookupLoading.value = true;
  statusMessage.value = '';

  try {
    hrdData.value = await sso.auth.lookupEmail(email.value);
  } catch (error) {
    console.warn('Email lookup fell back to password:', error);
    hrdData.value = { auth_method: 'password' };
  } finally {
    lookupLoading.value = false;
    step.value = 2;
  }
}

function handleOAuthLogin(provider, connectionId = null) {
  const ctx = authContext.value;
  storePostLoginRedirect(route.query.redirect);

  if (ctx.isServiceFlow && !ctx.redirectUri) {
    statusType.value = 'error';
    statusMessage.value = 'This sign-in request is missing a valid return URL.';
    return;
  }

  const org = ctx.org || 'authos';
  const service = ctx.service || 'platform';
  const loginUrl = org === 'authos' && service === 'platform' && !connectionId
    ? sso.auth.getAdminLoginUrl(provider)
    : sso.auth.getLoginUrl(provider, {
        org,
        service,
        redirect_uri: ctx.redirectUri,
        connection_id: connectionId,
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
      email: email.value,
      password: password.value,
    };

    if (ctx.isServiceFlow) {
      payload.org_slug = ctx.org;
      payload.service_slug = ctx.service;
      payload.redirect_uri = ctx.redirectUri;
    }

    const response = await sso.auth.login(payload);
    if (response.expires_in === 300 && !response.refresh_token) {
      preauthToken.value = response.access_token;
      showMfaChallenge.value = true;
      return;
    }

    await authStore.handleLoginCallback(response.access_token, response.refresh_token);

    if (ctx.isServiceFlow && ctx.redirectUri) {
      window.location.href = appendTokensToRedirectUri(
        ctx.redirectUri,
        response.access_token,
        response.refresh_token,
      );
      return;
    }

    router.push(normalizeInternalRedirect(route.query.redirect) || defaultAuthenticatedRoute());
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
    const payload = { email: email.value };

    if (ctx.isServiceFlow) {
      payload.org_slug = ctx.org;
      payload.service_slug = ctx.service;
      payload.redirect_uri = ctx.redirectUri;
    }

    await sso.magicLinks.request(payload);
    statusMessage.value = `Sign-in link sent to ${email.value}.`;
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
      email.value,
      ctx.isServiceFlow ? {
        org_slug: ctx.org,
        service_slug: ctx.service,
        redirect_uri: ctx.redirectUri,
      } : undefined,
    );

    await authStore.handleLoginCallback(response.access_token, response.refresh_token);

    if (ctx.isServiceFlow && ctx.redirectUri) {
      window.location.href = appendTokensToRedirectUri(
        ctx.redirectUri,
        response.access_token,
        response.refresh_token,
      );
      return;
    }

    router.push(defaultAuthenticatedRoute());
  } catch (error) {
    statusType.value = 'error';
    statusMessage.value = error.message || 'Passkey sign-in failed.';
  } finally {
    passkeyLoading.value = false;
  }
}

async function handleMfaSuccess({ code }) {
  try {
    await authStore.completeMfaChallenge(preauthToken.value, code);
    showMfaChallenge.value = false;

    if (authContext.value.isServiceFlow && authContext.value.redirectUri && authStore.token && authStore.refreshToken) {
      window.location.href = appendTokensToRedirectUri(
        authContext.value.redirectUri,
        authStore.token,
        authStore.refreshToken,
      );
      return;
    }

    router.push(defaultAuthenticatedRoute());
  } catch (error) {
    statusType.value = 'error';
    statusMessage.value = error.message || 'MFA verification failed.';
    showMfaChallenge.value = false;
  }
}
</script>
