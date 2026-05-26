<template>
  <div class="page-shell">
    <div class="auth-card">
      <div class="eyebrow">Hosted auth</div>
      <h1 class="title">Sign in to AuthOS</h1>
      <p class="muted">
        The embedded client handles end-user sign-in and the single-organization workspace.
      </p>
      <div style="margin-top: 24px;">
        <LiteLoginForm />
      </div>
      <p class="muted" style="margin: 24px 0 0;">
        Need an account?
        <router-link :to="authRouteWithContext(route, '/register')">Create one here</router-link>.
      </p>
    </div>
  </div>
</template>

<script setup>
import { useRoute } from 'vue-router';
import LiteLoginForm from '@/components/LiteLoginForm.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
</script>
