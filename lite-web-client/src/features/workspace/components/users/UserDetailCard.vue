<template>
  <section class="workspace-card stack">
    <div v-if="!user" class="workspace-empty-state">
      <h2 class="section-title">Select a user</h2>
      <p class="section-copy">Choose a user from the table to inspect their subscriptions and recent login activity.</p>
    </div>

    <template v-else>
      <div class="section-header">
        <div>
          <h2 class="section-title">{{ user.user.email }}</h2>
          <p class="section-copy">Detailed activity and session information for this end-user.</p>
        </div>
      </div>

      <div class="workspace-stat-grid workspace-stat-grid--detail">
        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Sessions</div>
          <div class="workspace-stat-card__value">{{ user.session_count }}</div>
        </article>
        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Providers</div>
          <div class="workspace-stat-card__value">{{ providerNameList(user.identities).join(', ') || 'None' }}</div>
        </article>
        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Created</div>
          <div class="workspace-stat-card__value">{{ formatDateTime(user.user.created_at) }}</div>
        </article>
      </div>

      <BaseButton variant="danger" :loading="revokeLoading" :disabled="user.session_count === 0" @click="$emit('revoke')">
        Revoke all sessions
      </BaseButton>

      <div class="stack">
        <h3 class="subsection-title">Subscriptions</h3>
        <div v-if="user.subscriptions.length === 0" class="muted">No subscriptions recorded.</div>
        <div v-else class="resource-list">
          <article v-for="subscription in user.subscriptions" :key="subscription.plan_id + subscription.service_id" class="resource-row">
            <div>
              <div class="resource-row__title">{{ subscription.service_name }}</div>
              <div class="resource-row__meta">{{ subscription.plan_name }} · {{ subscription.status }}</div>
            </div>
            <div class="resource-row__meta">{{ formatDateTime(subscription.current_period_end) }}</div>
          </article>
        </div>
      </div>

      <div class="stack">
        <h3 class="subsection-title">Recent logins</h3>
        <div v-if="user.recent_logins.length === 0" class="muted">No recent login events recorded.</div>
        <div v-else class="resource-list">
          <article v-for="login in user.recent_logins.slice(0, 6)" :key="login.id" class="resource-row">
            <div>
              <div class="resource-row__title">{{ login.provider }} · {{ login.service_name || 'Unknown service' }}</div>
              <div class="resource-row__meta">{{ login.ip_address || 'No IP address' }}</div>
            </div>
            <div class="resource-row__meta">{{ formatDateTime(login.created_at) }}</div>
          </article>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';
import { formatDateTime, providerNameList } from '@/utils/formatting';

defineProps({
  user: { type: Object, default: null },
  revokeLoading: { type: Boolean, default: false },
});

defineEmits(['revoke']);
</script>
