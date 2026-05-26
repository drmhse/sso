<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Create account</div>
        <h1 class="title">Join AuthOS</h1>
        <p class="muted">Create an account for hosted sign-in and your organization workspace.</p>
      </div>

      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>

      <div class="button-row">
        <BaseButton variant="secondary" @click="handleOAuthRegister('github')">GitHub</BaseButton>
        <BaseButton variant="secondary" @click="handleOAuthRegister('google')">Google</BaseButton>
        <BaseButton variant="secondary" @click="handleOAuthRegister('microsoft')">Microsoft</BaseButton>
      </div>

      <div class="field">
        <label for="email">Email address</label>
        <input id="email" v-model="email" type="email" class="input" placeholder="name@company.com" />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input id="password" v-model="password" type="password" class="input" placeholder="Minimum 8 characters" />
      </div>

      <div class="field">
        <label for="confirm-password">Confirm password</label>
        <input id="confirm-password" v-model="confirmPassword" type="password" class="input" placeholder="Repeat your password" />
      </div>

      <BaseButton :loading="loading" @click="handlePasswordRegister">Create account</BaseButton>

      <p class="muted">
        Already have an account?
        <router-link :to="authRouteWithContext(route, '/')">Sign in</router-link>.
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
const password = ref('');
const confirmPassword = ref('');
const loading = ref(false);
const message = ref('');
const errorMessage = ref('');

function handleOAuthRegister(provider) {
  const ctx = getAuthFlowContext(route);
  const loginUrl = ctx.isServiceFlow
    ? sso.auth.getLoginUrl(provider, {
        org: ctx.org,
        service: ctx.service,
        redirect_uri: ctx.redirectUri,
      })
    : sso.auth.getAdminLoginUrl(provider);

  window.location.href = loginUrl;
}

async function handlePasswordRegister() {
  if (!email.value || password.value.length < 8 || password.value !== confirmPassword.value) {
    errorMessage.value = 'Enter a valid email and matching passwords with at least 8 characters.';
    return;
  }

  loading.value = true;
  message.value = '';
  errorMessage.value = '';

  try {
    const ctx = getAuthFlowContext(route);
    const payload = {
      email: email.value,
      password: password.value,
    };

    if (ctx.isServiceFlow) {
      payload.org_slug = ctx.org;
      payload.service_slug = ctx.service;
      payload.redirect_uri = ctx.redirectUri;
    }

    await sso.auth.register(payload);
    message.value = `Verification email sent to ${email.value}.`;
  } catch (error) {
    errorMessage.value = error.message || 'Registration failed.';
  } finally {
    loading.value = false;
  }
}
</script>
