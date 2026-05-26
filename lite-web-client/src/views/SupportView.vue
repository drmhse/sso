<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Support</div>
        <h1 class="title">Need help signing in?</h1>
        <p class="muted">
          Contact your organization owner or support operator to recover access, reset MFA, or verify your account setup.
        </p>
      </div>

      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Common issues</div>
          <div class="meta-value" style="font-size: 1rem;">Lost authenticator, expired invitation, or missing redirect URI.</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Next step</div>
          <div class="meta-value" style="font-size: 1rem;">Return to sign in or ask your operator to review the organization settings.</div>
        </div>
      </div>

      <p class="muted">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { useRoute } from 'vue-router';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
</script>
