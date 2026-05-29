<template>
  <AuthShell
    title="Two-Factor Authentication"
    description="Enter the 6-digit code from your authenticator app."
    panel-width="md"
  >
    <div class="stack">
      <div v-if="statusMessage" class="alert alert-error">{{ statusMessage }}</div>

      <div class="field">
        <label for="mfa-code-input">{{ useRecoveryCode ? 'Recovery code' : 'Authenticator code' }}</label>
        <input
          id="mfa-code-input"
          v-model="code"
          class="input input-code input-code--centered"
          :maxlength="useRecoveryCode ? 32 : 6"
          :placeholder="useRecoveryCode ? 'Enter recovery code' : '000000'"
          autocomplete="one-time-code"
        />
      </div>

      <BaseButton :loading="loading" block @click="handleVerify">
        Verify
      </BaseButton>

      <div class="auth-inline-links auth-inline-links--center">
        <button type="button" class="text-link" @click="useRecoveryCode = !useRecoveryCode">
          {{ useRecoveryCode ? 'Use authenticator code' : 'Use a recovery code' }}
        </button>
        <button type="button" class="text-link" @click="handleLostDevice">
          Lost authenticator device?
        </button>
      </div>
    </div>
  </AuthShell>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';
import { appendTokensToRedirectUri, firstQueryValue } from '@/utils/authFlowContext';
import { defaultAuthenticatedRoute } from '@/utils/redirects';
import { scrubCurrentUrl } from '@/utils/urlSecurity';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const authFlowStore = useAuthFlowStore();

const code = ref('');
const loading = ref(false);
const statusMessage = ref('');
const useRecoveryCode = ref(false);
const deviceChallenge = ref(null);

const deviceFlow = computed(() => route.meta.deviceFlow === true);
const challenge = computed(() => {
  if (deviceFlow.value) {
    return deviceChallenge.value;
  }

  return authFlowStore.mfaChallenge;
});

onMounted(() => {
  if (!deviceFlow.value) return;

  deviceChallenge.value = {
    preauthToken: firstQueryValue(route.query.preauth_token),
    deviceCodeId: firstQueryValue(route.query.device_code_id),
    redirectUri: '',
    redirectPath: '/activate/success',
    supportPath: '/support',
  };

  scrubCurrentUrl({
    queryKeys: ['preauth_token', 'device_code_id', 'user_code'],
  });
});

async function handleVerify() {
  if (!challenge.value?.preauthToken || !code.value.trim()) {
    statusMessage.value = 'This verification challenge is incomplete.';
    return;
  }

  loading.value = true;
  statusMessage.value = '';

  try {
    if (deviceFlow.value) {
      await sso.http.post('/api/auth/mfa/verify', {
        preauth_token: challenge.value.preauthToken,
        code: code.value.trim(),
        ...(challenge.value.deviceCodeId ? { device_code_id: challenge.value.deviceCodeId } : {}),
      });
      await router.replace('/activate/success');
      return;
    }

    await authStore.completeMfaChallenge(
      challenge.value.preauthToken,
      code.value.trim(),
      challenge.value.deviceCodeId || null,
    );

    const redirectUri = challenge.value.redirectUri;
    const redirectPath = challenge.value.redirectPath || defaultAuthenticatedRoute();
    authFlowStore.clearMfaChallenge();

    if (redirectUri && authStore.token && authStore.refreshToken) {
      window.location.href = appendTokensToRedirectUri(redirectUri, authStore.token, authStore.refreshToken, {
        state: challenge.value.state,
      });
      return;
    }

    await router.replace(redirectPath);
  } catch (error) {
    statusMessage.value = error.message || 'MFA verification failed.';
  } finally {
    loading.value = false;
  }
}

function handleLostDevice() {
  if (!deviceFlow.value) {
    authFlowStore.clearMfaChallenge();
  }
  router.push(challenge.value?.supportPath || '/support');
}
</script>
