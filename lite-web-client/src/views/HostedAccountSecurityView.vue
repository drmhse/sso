<template>
  <AuthShell
    title="Account security"
    :description="description"
    panel-width="lg"
    brand-tagline="Secure your sign-in methods"
  >
    <div class="hosted-security-page stack-lg">
      <section class="hosted-security-header">
        <div class="stack-sm">
          <p class="subsection-title">Signed in as</p>
          <h2 class="section-title">{{ authStore.userEmail || 'AuthOS user' }}</h2>
          <p v-if="serviceContext" class="section-copy">{{ serviceContext }}</p>
        </div>

        <div class="button-row hosted-security-header__actions">
          <BaseButton v-if="returnTo" variant="secondary" @click="returnToApplication">
            Return to application
          </BaseButton>
          <BaseButton variant="ghost" @click="signOut">
            Sign out
          </BaseButton>
        </div>
      </section>

      <AccountSecurityControls :refresh-version="refreshVersion" />
    </div>
  </AuthShell>
</template>

<script setup>
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import AccountSecurityControls from '@/features/workspace/components/security/AccountSecurityControls.vue';
import { useAuthStore } from '@/stores/auth';
import { firstQueryValue, getAuthFlowContext } from '@/utils/authFlowContext';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const refreshVersion = ref(0);

const returnTo = computed(() => normalizeHttpReturnTo(firstQueryValue(route.query.return_to)));
const authContext = computed(() => getAuthFlowContext(route));
const serviceContext = computed(() => {
  if (!authContext.value.org && !authContext.value.service) {
    return '';
  }

  return `For ${authContext.value.serviceLabel} in ${authContext.value.orgLabel}.`;
});
const description = computed(() => (
  returnTo.value
    ? 'Manage your AuthOS sign-in factors, then return to the application that sent you here.'
    : 'Manage your AuthOS sign-in factors and trusted devices.'
));

function returnToApplication() {
  if (returnTo.value) {
    window.location.href = returnTo.value;
  }
}

async function signOut() {
  await authStore.logout();
  await router.push('/');
}

function normalizeHttpReturnTo(value) {
  if (!value) return '';

  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.toString() : '';
  } catch {
    return '';
  }
}
</script>
