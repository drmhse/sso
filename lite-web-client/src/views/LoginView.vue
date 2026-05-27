<template>
  <AuthShell>
    <div class="stack">
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
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import LiteLoginForm from '@/components/LiteLoginForm.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
</script>
