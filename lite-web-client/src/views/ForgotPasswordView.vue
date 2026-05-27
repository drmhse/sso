<template>
  <AuthShell
    title="Reset your password"
    description="We’ll send a password reset link to the email address on this account."
  >
    <div class="stack">
      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>

      <div class="field">
        <label for="email">Email address</label>
        <input id="email" v-model="email" type="email" class="input input-lg" placeholder="you@example.com" />
      </div>

      <BaseButton :loading="loading" block @click="handleSubmit">Send reset link</BaseButton>

      <p class="muted auth-centered-copy">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </AuthShell>
</template>

<script setup>
import { ref } from 'vue';
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import { sso } from '@/lib/api';
import { authRouteWithContext, getAuthFlowContext } from '@/utils/authFlowContext';

const route = useRoute();
const email = ref('');
const loading = ref(false);
const message = ref('');
const errorMessage = ref('');

async function handleSubmit() {
  if (!email.value) return;

  loading.value = true;
  message.value = '';
  errorMessage.value = '';

  try {
    const ctx = getAuthFlowContext(route);
    const payload = { email: email.value };

    if (ctx.isServiceFlow) {
      payload.org_slug = ctx.org;
      payload.service_slug = ctx.service;
      payload.redirect_uri = ctx.redirectUri;
    }

    const response = await sso.auth.requestPasswordReset(payload);
    message.value = response?.message || `If ${email.value} exists, a reset link has been sent.`;
  } catch (error) {
    errorMessage.value = error.message || 'Unable to send a reset email.';
  } finally {
    loading.value = false;
  }
}
</script>
