<template>
  <div class="page-shell">
    <div class="auth-card stack" style="text-align: center;">
      <div>
        <div class="eyebrow">OAuth callback</div>
        <h1 class="title">Completing sign-in</h1>
      </div>

      <LoadingSpinner v-if="status === 'loading'" text="Finalizing your AuthOS session..." />
      <div v-else-if="status === 'error'" class="alert alert-error">{{ errorMessage }}</div>
      <div v-else class="alert alert-success">Signed in. Redirecting...</div>
    </div>

    <MfaChallengeModal
      :is-open="showMfaChallenge"
      :preauth-token="preauthToken"
      :device-code-id="deviceCodeId"
      @success="handleMfaSuccess"
      @close="router.push('/')"
      @lost-device="router.push(authRouteWithContext(route, '/support'))"
    />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import MfaChallengeModal from '@/components/MfaChallengeModal.vue';
import { appendTokensToRedirectUri, authRouteWithContext } from '@/utils/authFlowContext';
import { postLoginRedirect } from '@/utils/redirects';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const status = ref('loading');
const errorMessage = ref('');
const showMfaChallenge = ref(false);
const preauthToken = ref('');
const deviceCodeId = ref(null);

function readTokenPayload() {
  let accessToken;
  let refreshToken;
  let mfaRequired;
  let preauth;
  let deviceId;
  let error;

  if (window.location.hash) {
    const params = new URLSearchParams(window.location.hash.slice(1));
    accessToken = params.get('access_token');
    refreshToken = params.get('refresh_token');
    mfaRequired = params.get('mfa_required');
    preauth = params.get('preauth_token');
    deviceId = params.get('device_code_id');
    error = params.get('error');

    if (accessToken || refreshToken || preauth) {
      window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }
  }

  if (!accessToken && !refreshToken && !preauth && !error) {
    accessToken = Array.isArray(route.query.access_token) ? route.query.access_token[0] : route.query.access_token;
    refreshToken = Array.isArray(route.query.refresh_token) ? route.query.refresh_token[0] : route.query.refresh_token;
    mfaRequired = Array.isArray(route.query.mfa_required) ? route.query.mfa_required[0] : route.query.mfa_required;
    preauth = Array.isArray(route.query.preauth_token) ? route.query.preauth_token[0] : route.query.preauth_token;
    deviceId = Array.isArray(route.query.device_code_id) ? route.query.device_code_id[0] : route.query.device_code_id;
    error = Array.isArray(route.query.error) ? route.query.error[0] : route.query.error;
  }

  return { accessToken, refreshToken, mfaRequired, preauth, deviceId, error };
}

function completeRedirect() {
  router.push(postLoginRedirect(route));
}

onMounted(async () => {
  try {
    if (route.query.device_flow_status === 'success') {
      status.value = 'success';
      return;
    }

    const { accessToken, refreshToken, mfaRequired, preauth, deviceId, error } = readTokenPayload();
    if (error) throw new Error(String(error));

    if (mfaRequired === 'true' && preauth) {
      preauthToken.value = String(preauth);
      deviceCodeId.value = deviceId ? String(deviceId) : null;
      showMfaChallenge.value = true;
      return;
    }

    if (!accessToken || !refreshToken) {
      throw new Error('No authentication tokens were returned.');
    }

    await authStore.handleLoginCallback(String(accessToken), String(refreshToken));
    status.value = 'success';
    completeRedirect();
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'Authentication failed.';
  }
});

async function handleMfaSuccess({ code, deviceCodeId: deviceId }) {
  try {
    await authStore.completeMfaChallenge(preauthToken.value, code, deviceId || deviceCodeId.value);
    showMfaChallenge.value = false;
    status.value = 'success';

    const redirectUri = Array.isArray(route.query.redirect_uri) ? route.query.redirect_uri[0] : route.query.redirect_uri;
    if (redirectUri && authStore.token && authStore.refreshToken) {
      window.location.href = appendTokensToRedirectUri(redirectUri, authStore.token, authStore.refreshToken);
      return;
    }

    completeRedirect();
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'MFA verification failed.';
    showMfaChallenge.value = false;
  }
}
</script>
