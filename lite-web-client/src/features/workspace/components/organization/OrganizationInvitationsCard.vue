<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Pending Invitations</h2>
        <p class="section-copy">Review invitations attached to the signed-in operator account.</p>
      </div>
    </div>

    <div v-if="invitations.length === 0" class="workspace-empty-state">
      <p class="section-copy">No pending invitations.</p>
    </div>

    <div v-else class="resource-list">
      <article v-for="invitation in invitations" :key="invitation.id" class="resource-row">
        <div>
          <div class="resource-row__title">{{ invitation.organization_name }}</div>
          <div class="resource-row__meta">
            Role: {{ invitation.role }} · Invited by {{ invitation.inviter_email }}
          </div>
        </div>

        <div class="resource-row__actions">
          <span class="status-chip status-chip--warning">Pending</span>
          <button type="button" class="text-link" @click="$emit('accept', invitation.id)">Accept</button>
          <button
            type="button"
            class="icon-button icon-button--danger"
            aria-label="Decline invitation"
            @click="$emit('decline', invitation.id)"
          >
            <Trash2 class="icon-button__icon" />
          </button>
        </div>
      </article>
    </div>
  </section>
</template>

<script setup>
import { Trash2 } from '@lucide/vue';

defineProps({
  invitations: { type: Array, default: () => [] },
});

defineEmits(['accept', 'decline']);
</script>
