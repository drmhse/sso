<template>
  <AuthShell
    title="Review your invitation"
    description="Accept or decline this organization invitation using your signed-in account."
  >
    <div class="stack">
      <div v-if="statusMessage" class="alert" :class="statusClass">{{ statusMessage }}</div>

      <template v-if="token">
        <div class="button-row">
          <BaseButton :loading="accepting" block @click="handleAccept">Accept invitation</BaseButton>
          <BaseButton variant="secondary" :loading="declining" block @click="handleDecline">Decline invitation</BaseButton>
        </div>
      </template>
      <div v-else class="alert alert-error">This invitation link is missing its token.</div>

      <p class="muted auth-centered-copy">
        <router-link to="/app/overview">Go to my workspace</router-link>
      </p>
    </div>
  </AuthShell>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';
import { scrubCurrentUrl } from '@/utils/urlSecurity';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const token = ref(Array.isArray(route.query.token) ? route.query.token[0] : route.query.token);
const accepting = ref(false);
const declining = ref(false);
const statusMessage = ref('');
const statusType = ref('success');
const statusClass = computed(() => statusType.value === 'success' ? 'alert-success' : 'alert-error');

onMounted(() => {
  if (!token.value) return;
  scrubCurrentUrl({ queryKeys: ['token'] });
});

async function handleAccept() {
  if (!token.value) return;
  accepting.value = true;
  statusMessage.value = '';

  try {
    await sso.invitations.accept(String(token.value));
    await authStore.refreshUser();
    await workspaceStore.resolveWorkspace();
    statusType.value = 'success';
    statusMessage.value = 'Invitation accepted. Redirecting to your workspace...';
    setTimeout(() => router.push('/app/overview'), 800);
  } catch (error) {
    statusType.value = 'error';
    statusMessage.value = error.message || 'Unable to accept this invitation.';
  } finally {
    accepting.value = false;
  }
}

async function handleDecline() {
  if (!token.value) return;
  declining.value = true;
  statusMessage.value = '';

  try {
    await sso.invitations.decline(String(token.value));
    statusType.value = 'success';
    statusMessage.value = 'Invitation declined.';
  } catch (error) {
    statusType.value = 'error';
    statusMessage.value = error.message || 'Unable to decline this invitation.';
  } finally {
    declining.value = false;
  }
}
</script>
