<template>
  <section id="invitations" class="panel stack">
    <div>
      <h2>Invitations</h2>
      <p class="muted">Review organization invitations for this signed-in account.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <div v-if="invitations.length === 0" class="muted">No pending invitations.</div>
    <div v-else class="list">
      <div v-for="invitation in invitations" :key="invitation.id" class="list-item">
        <div>
          <div>{{ invitation.organization_name }}</div>
          <div class="muted">Role: {{ invitation.role }} · Invited by {{ invitation.inviter_email }}</div>
        </div>
        <div class="button-row">
          <BaseButton @click="acceptInvitation(invitation.id)">Accept</BaseButton>
          <BaseButton variant="danger" @click="declineInvitation(invitation.id)">Decline</BaseButton>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, watch } from 'vue';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import { useWorkspaceStore } from '@/stores/workspace';

const props = defineProps({
  refreshKey: { type: Number, default: 0 },
});

const emit = defineEmits(['workspace-changed']);
const workspaceStore = useWorkspaceStore();

const invitations = ref([]);
const message = ref('');
const messageType = ref('success');

watch(
  () => props.refreshKey,
  async () => {
    if (workspaceStore.mode === 'ready') {
      await loadInvitations();
    } else {
      invitations.value = [];
    }
  },
  { immediate: true },
);

async function loadInvitations() {
  invitations.value = await sso.invitations.listForUser();
}

async function acceptInvitation(invitationId) {
  try {
    await sso.invitations.acceptById(invitationId);
    messageType.value = 'success';
    message.value = 'Invitation accepted.';
    emit('workspace-changed');
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to accept the invitation.';
  }
}

async function declineInvitation(invitationId) {
  try {
    await sso.invitations.declineById(invitationId);
    messageType.value = 'success';
    message.value = 'Invitation declined.';
    await loadInvitations();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to decline the invitation.';
  }
}
</script>
