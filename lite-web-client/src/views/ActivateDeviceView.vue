<template>
  <AuthShell :title="heading" :description="description">
    <div class="stack">
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>
      <div v-if="successMessage" class="alert alert-success">{{ successMessage }}</div>

      <template v-if="isSuccessState">
        <div class="alert alert-success">
          The device is authorized. Return to your CLI or desktop app to continue.
        </div>
      </template>

      <template v-else-if="!loginContext">
        <div class="field">
          <label for="device-code">Activation code</label>
          <input
            id="device-code"
            v-model="userCode"
            class="input input-code"
            maxlength="9"
            placeholder="ABCD-1234"
            @input="normalizeCode"
          />
        </div>
        <BaseButton :loading="loading" block @click="verifyCode">Continue</BaseButton>
      </template>

      <template v-else>
        <div class="alert alert-warning">
          Continue sign-in for <strong>{{ loginContext.service_slug }}</strong> in <strong>{{ loginContext.org_slug }}</strong>.
        </div>
        <div class="auth-provider-grid">
          <BaseButton
            v-for="provider in loginContext.available_providers"
            :key="provider"
            variant="secondary"
            block
            @click="handleLogin(provider)"
          >
            {{ providerLabel(provider) }}
          </BaseButton>
        </div>
      </template>
    </div>
  </AuthShell>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import { sso } from '@/lib/api';

const route = useRoute();
const userCode = ref('');
const loading = ref(false);
const errorMessage = ref('');
const loginContext = ref(null);
const successMessage = ref('');

const isSuccessState = computed(
  () => route.path.startsWith('/activate/success') || route.query.device_flow_status === 'success',
);
const heading = computed(() => (isSuccessState.value ? 'Device authorized' : 'Authorize a device'));
const description = computed(() => (
  isSuccessState.value
    ? 'The device flow finished successfully.'
    : 'Enter the code from your CLI or desktop app.'
));

onMounted(() => {
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
</script>
