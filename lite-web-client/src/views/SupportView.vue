<template>
  <AuthShell
    title="Need help signing in?"
    description="Contact your organization owner or support operator to recover access, reset MFA, or verify your account setup."
  >
    <div class="stack">
      <div class="workspace-action-list">
        <div class="workspace-action-card">
          <div class="workspace-action-card__title">Common issues</div>
          <div class="workspace-action-card__copy">Lost authenticator device, expired invitation, or a missing redirect URL.</div>
        </div>

        <div class="workspace-action-card">
          <div class="workspace-action-card__title">Next step</div>
          <div class="workspace-action-card__copy">Return to sign in or ask an operator to review your organization settings.</div>
        </div>
      </div>

      <p class="muted auth-centered-copy">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </AuthShell>
</template>

<script setup>
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';

const route = useRoute();
</script>
