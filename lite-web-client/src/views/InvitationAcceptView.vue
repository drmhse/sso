<template>
  <div class="page-shell">
    <div class="auth-card stack">
      <div>
        <div class="eyebrow">Invitation</div>
        <h1 class="title">Review your invitation</h1>
        <p class="muted">Accept or decline this organization invitation using your signed-in account.</p>
      </div>

      <div v-if="statusMessage" class="alert" :class="statusClass">{{ statusMessage }}</div>

      <template v-if="token">
        <div class="button-row">
          <BaseButton :loading="accepting" @click="handleAccept">Accept invitation</BaseButton>
          <BaseButton variant="danger" :loading="declining" @click="handleDecline">Decline invitation</BaseButton>
        </div>
      </template>
      <div v-else class="alert alert-error">This invitation link is missing its token.</div>

      <p class="muted">
        <router-link to="/app">Go to my workspace</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';
import BaseButton from '@/components/BaseButton.vue';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const token = computed(() => Array.isArray(route.query.token) ? route.query.token[0] : route.query.token);
const accepting = ref(false);
const declining = ref(false);
const statusMessage = ref('');
const statusType = ref('success');
const statusClass = computed(() => statusType.value === 'success' ? 'alert-success' : 'alert-error');

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
    setTimeout(() => router.push('/app'), 800);
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
