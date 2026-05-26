<template>
  <div class="page-shell">
    <div class="auth-card stack" style="text-align: center;">
      <div>
        <div class="eyebrow">Email verification</div>
        <h1 class="title">Confirming your email</h1>
      </div>

      <LoadingSpinner v-if="loading" text="Verifying your email address..." />
      <div v-else-if="message" class="alert alert-success">{{ message }}</div>
      <div v-else class="alert alert-error">{{ errorMessage }}</div>

      <p class="muted">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
const router = useRouter();
const loading = ref(true);
const message = ref('');
const errorMessage = ref('');

onMounted(async () => {
  const token = Array.isArray(route.query.token) ? route.query.token[0] : route.query.token;
  if (!token) {
    loading.value = false;
    errorMessage.value = 'Missing verification token.';
    return;
  }

  try {
    const response = await fetch(`/auth/verify-email?token=${encodeURIComponent(String(token))}`);
    if (!response.ok) throw new Error(await response.text() || 'Verification failed.');
    message.value = 'Email verified. Redirecting to sign in...';
    setTimeout(() => router.push(authRouteWithContext(route, '/')), 1400);
  } catch (error) {
    errorMessage.value = error.message || 'Email verification failed.';
  } finally {
    loading.value = false;
  }
});
</script>
