<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Password reset</div>
        <h1 class="title">Reset your password</h1>
        <p class="muted">We’ll send a reset link to your email address.</p>
      </div>

      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>

      <div class="field">
        <label for="email">Email address</label>
        <input id="email" v-model="email" type="email" class="input" placeholder="you@example.com" />
      </div>

      <BaseButton :loading="loading" @click="handleSubmit">Send reset link</BaseButton>

      <p class="muted">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { useRoute } from 'vue-router';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
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

    await sso.auth.requestPasswordReset(payload);
    message.value = `If ${email.value} exists, a reset link has been sent.`;
  } catch (error) {
    errorMessage.value = error.message || 'Unable to send a reset email.';
  } finally {
    loading.value = false;
  }
}
</script>
