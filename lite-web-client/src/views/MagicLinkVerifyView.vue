<template>
  <div class="page-shell">
    <div class="auth-card stack" style="text-align: center;">
      <div>
        <div class="eyebrow">Magic link</div>
        <h1 class="title">Verifying your sign-in link</h1>
      </div>

      <LoadingSpinner v-if="status === 'loading'" text="Checking your magic link..." />
      <div v-else-if="status === 'error'" class="alert alert-error">{{ errorMessage }}</div>
      <div v-else class="alert alert-success">Signed in. Redirecting...</div>
    </div>

    <MfaChallengeModal
      :is-open="showMfaChallenge"
      :preauth-token="preauthToken"
      @success="handleMfaSuccess"
      @close="router.push('/')"
      @lost-device="router.push(authRouteWithContext(route, '/support'))"
    />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import MfaChallengeModal from '@/components/MfaChallengeModal.vue';
import { appendTokensToRedirectUri, authRouteWithContext, firstQueryValue } from '@/utils/authFlowContext';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const status = ref('loading');
const errorMessage = ref('');
const showMfaChallenge = ref(false);
const preauthToken = ref('');
const redirectUri = firstQueryValue(route.query.redirect_uri);

onMounted(async () => {
  const token = firstQueryValue(route.query.token);
  if (!token) {
    status.value = 'error';
    errorMessage.value = 'This sign-in link is missing its verification token.';
    return;
  }

  try {
    const response = await sso.magicLinks.verify(token, redirectUri || undefined);

    if (response?.requires_mfa && response?.preauth_token) {
      preauthToken.value = response.preauth_token;
      showMfaChallenge.value = true;
      return;
    }

    if (!response?.access_token || !response?.refresh_token) {
      throw new Error('The sign-in link response was incomplete.');
    }

    await authStore.handleLoginCallback(response.access_token, response.refresh_token);
    status.value = 'success';

    if (redirectUri) {
      window.location.href = appendTokensToRedirectUri(redirectUri, response.access_token, response.refresh_token);
      return;
    }

    router.push('/app');
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'This sign-in link is invalid or expired.';
  }
});

async function handleMfaSuccess({ code }) {
  try {
    await authStore.completeMfaChallenge(preauthToken.value, code);
    showMfaChallenge.value = false;
    status.value = 'success';

    if (redirectUri && authStore.token && authStore.refreshToken) {
      window.location.href = appendTokensToRedirectUri(redirectUri, authStore.token, authStore.refreshToken);
      return;
    }

    router.push('/app');
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'MFA verification failed.';
  }
}
</script>
