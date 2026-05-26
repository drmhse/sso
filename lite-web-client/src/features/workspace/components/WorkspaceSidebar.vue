<template>
  <aside class="panel stack">
    <div>
      <div class="eyebrow">Lite workspace</div>
      <h1 class="title workspace-title">{{ userEmail || 'AuthOS account' }}</h1>
      <p class="muted sidebar-copy">
        Hosted sign-in, single-application operations, end-user review, and account security.
      </p>
    </div>

    <nav class="nav-list">
      <a href="#overview" class="nav-link">Overview</a>
      <a v-if="showSetup" href="#setup" class="nav-link">Setup</a>
      <a href="#organization" class="nav-link">Organization</a>
      <a href="#application" class="nav-link">Application</a>
      <a href="#users" class="nav-link">Users</a>
      <a href="#account" class="nav-link">Account</a>
      <a href="#security" class="nav-link">Security</a>
      <a href="#invitations" class="nav-link">Invitations</a>
    </nav>

    <div class="button-row">
      <BaseButton variant="secondary" @click="$emit('refresh')">Refresh</BaseButton>
      <BaseButton variant="secondary" @click="$emit('logout')">Sign out</BaseButton>
    </div>

    <BaseButton v-if="fullClientUrl" variant="secondary" @click="$emit('open-full-client')">
      Open full client
    </BaseButton>
  </aside>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  userEmail: { type: String, default: '' },
  showSetup: { type: Boolean, default: false },
  fullClientUrl: { type: String, default: '' },
});

defineEmits(['refresh', 'logout', 'open-full-client']);
</script>
