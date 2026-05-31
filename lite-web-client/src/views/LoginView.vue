<template>
  <AuthShell>
    <div class="stack">
      <div v-if="accountSecurityRedirect" class="alert alert-warning">
        Sign in to manage authenticator apps, backup codes, and passkeys.
      </div>

      <LiteLoginForm />

      <div class="auth-inline-links auth-inline-links--between">
        <router-link class="text-link" :to="authRouteWithContext(route, '/activate')">
          Device Auth
        </router-link>
        <router-link class="text-link" :to="authRouteWithContext(route, '/register')">
          Create account
        </router-link>
      </div>
    </div>
  </AuthShell>
</template>

<script setup>
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import LiteLoginForm from '@/components/LiteLoginForm.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
const accountSecurityRedirect = computed(() => {
  const redirect = Array.isArray(route.query.redirect) ? route.query.redirect[0] : route.query.redirect;
  return typeof redirect === 'string' && (
    redirect.startsWith('/account/security') ||
    redirect.startsWith('/app/account-security')
  );
});
</script>
