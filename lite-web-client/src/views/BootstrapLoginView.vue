<template>
  <AuthShell
    title="Preparing your setup session"
    description="This one-time link signs in the platform owner and opens the managed setup workspace."
  >
    <AuthStatusPanel
      :status="status"
      loading-text="Signing in..."
      success-text="Signed in. Redirecting to platform setup..."
      :error-text="errorMessage"
    />
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import AuthStatusPanel from '@/features/auth/components/AuthStatusPanel.vue';
import { useAuthStore } from '@/stores/auth';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const status = ref('loading');
const errorMessage = ref('');

onMounted(async () => {
  const token = readBootstrapToken();
  if (!token) {
    status.value = 'error';
    errorMessage.value = 'This bootstrap link is missing its token.';
    return;
  }

  window.history.replaceState({}, document.title, route.path);

  try {
    const response = await fetch('/api/public/bootstrap-login', {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ token }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Bootstrap login failed.');
    }

    await authStore.handleLoginCallback(payload.access_token, payload.refresh_token);
    status.value = 'success';
    await router.replace('/app/platform-setup');
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'Bootstrap login failed.';
  }
});

function readBootstrapToken() {
  const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
  return String(new URLSearchParams(hash).get('token') || '').trim();
}
</script>
