<template>
  <AuthShell title="Completing sign-in" description="We’re finalizing your AuthOS session.">
    <AuthStatusPanel
      :status="status"
      loading-text="Finalizing your AuthOS session..."
      success-text="Signed in. Redirecting..."
      :error-text="errorMessage"
    />
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import AuthStatusPanel from '@/features/auth/components/AuthStatusPanel.vue';
import { formatCallbackError } from '@/features/auth/errors';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import { authRouteWithContext, getAuthFlowContext } from '@/utils/authFlowContext';
import { postLoginRedirect } from '@/utils/redirects';
import { scrubCurrentUrl } from '@/utils/urlSecurity';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const authFlowStore = useAuthFlowStore();
const authContext = getAuthFlowContext(route);

const status = ref('loading');
const errorMessage = ref('');

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
  }

  if (!accessToken && !refreshToken && !preauth && !error) {
    accessToken = Array.isArray(route.query.access_token) ? route.query.access_token[0] : route.query.access_token;
    refreshToken = Array.isArray(route.query.refresh_token) ? route.query.refresh_token[0] : route.query.refresh_token;
    mfaRequired = Array.isArray(route.query.mfa_required) ? route.query.mfa_required[0] : route.query.mfa_required;
    preauth = Array.isArray(route.query.preauth_token) ? route.query.preauth_token[0] : route.query.preauth_token;
    deviceId = Array.isArray(route.query.device_code_id) ? route.query.device_code_id[0] : route.query.device_code_id;
    error = Array.isArray(route.query.error) ? route.query.error[0] : route.query.error;
  }

  if (accessToken || refreshToken || preauth || error) {
    scrubCurrentUrl({
      queryKeys: ['access_token', 'refresh_token', 'mfa_required', 'mfa_challenge', 'preauth_token', 'device_code_id', 'user_code', 'error'],
      hashKeys: ['access_token', 'refresh_token', 'mfa_required', 'mfa_challenge', 'preauth_token', 'device_code_id', 'user_code', 'error'],
    });
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
    if (error) throw new Error(formatCallbackError(error));

    if (mfaRequired === 'true' && preauth) {
      authFlowStore.setMfaChallenge({
        preauthToken: String(preauth),
        redirectUri: authContext.isServiceFlow ? authContext.redirectUri : '',
        redirectPath: postLoginRedirect(route),
        deviceCodeId: deviceId ? String(deviceId) : '',
        supportPath: authRouteWithContext(route, '/support'),
        state: authContext.state,
      });
      await router.replace('/mfa-challenge');
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
</script>
