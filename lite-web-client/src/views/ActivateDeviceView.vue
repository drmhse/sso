<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Device flow</div>
        <h1 class="title">{{ heading }}</h1>
        <p class="muted">{{ description }}</p>
      </div>

      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>
      <div v-if="successMessage" class="alert alert-success">{{ successMessage }}</div>

      <template v-if="isSuccessState">
        <div class="alert alert-success">
          The device is authorized. Return to your CLI or desktop app to continue.
        </div>
      </template>

      <template v-else-if="!loginContext && !isMfaState">
        <div class="field">
          <label for="device-code">Activation code</label>
          <input
            id="device-code"
            v-model="userCode"
            class="input code"
            maxlength="9"
            placeholder="ABCD-1234"
            @input="normalizeCode"
          />
        </div>
        <BaseButton :loading="loading" @click="verifyCode">Continue</BaseButton>
      </template>

      <template v-else-if="loginContext">
        <div class="alert alert-warning">
          Continue sign-in for <strong>{{ loginContext.service_slug }}</strong> in <strong>{{ loginContext.org_slug }}</strong>.
        </div>
        <div class="button-row">
          <BaseButton v-for="provider in loginContext.available_providers" :key="provider" variant="secondary" @click="handleLogin(provider)">
            {{ providerLabel(provider) }}
          </BaseButton>
        </div>
      </template>
    </div>

    <MfaChallengeModal
      :is-open="showMfaChallenge"
      :preauth-token="preauthToken"
      :device-code-id="deviceCodeId"
      @success="handleMfaSuccess"
      @close="handleMfaClose"
      @lost-device="router.push('/support')"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import MfaChallengeModal from '@/components/MfaChallengeModal.vue';

const route = useRoute();
const router = useRouter();
const userCode = ref('');
const loading = ref(false);
const errorMessage = ref('');
const loginContext = ref(null);
const successMessage = ref('');
const showMfaChallenge = ref(false);
const preauthToken = ref('');
const deviceCodeId = ref(null);

const isMfaState = computed(() => route.path.startsWith('/activate/mfa-challenge'));
const isSuccessState = computed(
  () => route.path.startsWith('/activate/success') || route.query.device_flow_status === 'success',
);
const heading = computed(() => {
  if (isMfaState.value) return 'Complete verification';
  if (isSuccessState.value) return 'Device authorized';
  return 'Authorize a device';
});
const description = computed(() => {
  if (isMfaState.value) {
    return 'Finish the sign-in with your authenticator app or a backup code.';
  }
  if (isSuccessState.value) {
    return 'The device flow finished successfully.';
  }
  return 'Enter the code from your CLI or desktop app.';
});

onMounted(() => {
  if (isMfaState.value) {
    preauthToken.value = String(route.query.preauth_token || '');
    deviceCodeId.value = route.query.device_code_id ? String(route.query.device_code_id) : null;
    if (!preauthToken.value) {
      errorMessage.value = 'This device authorization challenge is missing its verification token.';
      return;
    }
    showMfaChallenge.value = true;
    return;
  }

  if (isSuccessState.value) {
    successMessage.value = 'You can return to the waiting device now.';
  }
});

function normalizeCode() {
  let next = userCode.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (next.length > 4) next = `${next.slice(0, 4)}-${next.slice(4, 8)}`;
  userCode.value = next;
}

function providerLabel(provider) {
  return `Sign in with ${provider.charAt(0).toUpperCase()}${provider.slice(1)}`;
}

async function verifyCode() {
  if (!userCode.value) return;
  loading.value = true;
  errorMessage.value = '';

  try {
    loginContext.value = await sso.auth.deviceCode.verify(userCode.value);
  } catch (error) {
    errorMessage.value = error.message || 'Invalid or expired device code.';
  } finally {
    loading.value = false;
  }
}

function handleLogin(provider) {
  const isPlatformFlow = loginContext.value.org_slug === 'platform' && loginContext.value.service_slug === 'admin-cli';
  const loginUrl = isPlatformFlow
    ? sso.auth.getAdminLoginUrl(provider, {
        org_slug: loginContext.value.org_slug,
        user_code: userCode.value,
      })
    : sso.auth.getLoginUrl(provider, {
        org: loginContext.value.org_slug,
        service: loginContext.value.service_slug,
        user_code: userCode.value,
      });

  window.location.href = loginUrl;
}

async function handleMfaSuccess({ code, deviceCodeId: currentDeviceCodeId }) {
  loading.value = true;
  errorMessage.value = '';

  try {
    await sso.http.post('/api/auth/mfa/verify', {
      preauth_token: preauthToken.value,
      code,
      ...(currentDeviceCodeId || deviceCodeId.value
        ? { device_code_id: currentDeviceCodeId || deviceCodeId.value }
        : {}),
    });
    showMfaChallenge.value = false;
    successMessage.value = 'The device is authorized. Return to your CLI or desktop app to continue.';
    await router.replace('/activate/success');
  } catch (error) {
    errorMessage.value = error.message || 'MFA verification failed.';
    showMfaChallenge.value = true;
  } finally {
    loading.value = false;
  }
}

function handleMfaClose() {
  showMfaChallenge.value = false;
  router.push('/activate');
}
</script>
