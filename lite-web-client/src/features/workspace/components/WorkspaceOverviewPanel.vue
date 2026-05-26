<template>
  <section id="overview" class="panel stack">
    <div>
      <h2>Overview</h2>
      <p class="muted">Current user and organization context.</p>
    </div>

    <LoadingSpinner v-if="mode === 'loading'" text="Loading your workspace..." />
    <div v-else-if="mode === 'error'" class="alert alert-error">{{ error }}</div>
    <div v-else-if="mode === 'handoff'" class="stack">
      <div class="alert alert-warning">
        This account needs the full AuthOS client because it has access to multiple organizations.
      </div>
      <BaseButton v-if="fullClientUrl" @click="$emit('open-full-client')">
        Continue in full client
      </BaseButton>
      <div v-else class="muted">Set `FULL_WEB_CLIENT_BASE_URL` if you want multi-org sessions to hand off automatically.</div>
    </div>
    <div v-else-if="mode === 'no-org'" class="alert alert-warning">
      This account is signed in but is not attached to an organization yet.
    </div>
    <template v-else>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Email</div>
          <div class="meta-value">{{ email }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Organization</div>
          <div class="meta-value">{{ orgName }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Status</div>
          <div class="meta-value">
            <span class="status-pill" :class="orgStatus">{{ orgStatus }}</span>
          </div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Current role</div>
          <div class="meta-value">{{ role || 'member' }}</div>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';

defineProps({
  mode: { type: String, default: 'idle' },
  error: { type: String, default: '' },
  email: { type: String, default: '' },
  orgName: { type: String, default: '' },
  orgStatus: { type: String, default: '' },
  role: { type: String, default: '' },
  fullClientUrl: { type: String, default: '' },
});

defineEmits(['open-full-client']);
</script>
