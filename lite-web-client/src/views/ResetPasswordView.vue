<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Set a new password</div>
        <h1 class="title">Choose a new password</h1>
        <p class="muted">This link expires after one hour.</p>
      </div>

      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>

      <template v-if="token">
        <div class="field">
          <label for="password">New password</label>
          <input id="password" v-model="password" type="password" class="input" placeholder="Minimum 8 characters" />
        </div>

        <div class="field">
          <label for="confirm-password">Confirm password</label>
          <input id="confirm-password" v-model="confirmPassword" type="password" class="input" placeholder="Repeat your password" />
        </div>

        <BaseButton :loading="loading" @click="handleSubmit">Reset password</BaseButton>
      </template>

      <div v-else class="alert alert-error">This reset link is invalid or missing its token.</div>

      <p class="muted">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';
import { useRoute } from 'vue-router';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
const token = computed(() => Array.isArray(route.query.token) ? route.query.token[0] : route.query.token);
const password = ref('');
const confirmPassword = ref('');
const loading = ref(false);
const message = ref('');
const errorMessage = ref('');

async function handleSubmit() {
  if (!token.value || password.value.length < 8 || password.value !== confirmPassword.value) {
    errorMessage.value = 'Use matching passwords with at least 8 characters.';
    return;
  }

  loading.value = true;
  message.value = '';
  errorMessage.value = '';

  try {
    await sso.auth.resetPassword({
      token: String(token.value),
      new_password: password.value,
    });
    message.value = 'Password updated. You can now sign in.';
  } catch (error) {
    errorMessage.value = error.message || 'Failed to reset password.';
  } finally {
    loading.value = false;
  }
}
</script>
