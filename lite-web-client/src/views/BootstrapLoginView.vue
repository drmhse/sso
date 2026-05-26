<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Bootstrap access</div>
        <h1 class="title">Preparing your AuthOS setup session</h1>
        <p class="muted" style="margin: 0;">This one-time link signs in the platform owner and opens the managed setup workspace.</p>
      </div>

      <LoadingSpinner v-if="status === 'loading'" text="Signing in..." />
      <div v-else-if="status === 'error'" class="alert alert-error">{{ errorMessage }}</div>
      <div v-else class="alert alert-success">Signed in. Redirecting to the setup workspace…</div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
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
    await router.replace('/app#setup');
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
