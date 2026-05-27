<template>
  <header class="workspace-topbar">
    <div class="workspace-topbar__heading">
      <button
        type="button"
        class="icon-button workspace-topbar__menu-toggle"
        aria-label="Open navigation"
        @click="$emit('toggle-sidebar')"
      >
        <Menu class="icon-button__icon" />
      </button>

      <h1 class="workspace-topbar__title">{{ title }}</h1>
      <span v-if="badgeLabel" class="status-chip" :class="badgeClass">
        {{ badgeLabel }}
      </span>
    </div>

    <div class="workspace-topbar__actions">
      <button type="button" class="icon-button" aria-label="Refresh workspace" @click="$emit('refresh')">
        <RefreshCw class="icon-button__icon" />
      </button>

      <button
        type="button"
        class="workspace-org-chip"
        :class="{ 'workspace-org-chip--interactive': orgInteractive }"
        @click="handleOrgClick"
      >
        <span>{{ orgLabel }}</span>
        <ChevronDown class="workspace-org-chip__icon" />
      </button>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue';
import { ChevronDown, Menu, RefreshCw } from '@lucide/vue';

const props = defineProps({
  title: { type: String, default: 'Overview' },
  badgeLabel: { type: String, default: '' },
  badgeTone: { type: String, default: 'success' },
  orgLabel: { type: String, default: 'AuthOS Lite' },
  orgInteractive: { type: Boolean, default: false },
});

const emit = defineEmits(['refresh', 'open-full-client', 'toggle-sidebar']);

const badgeClass = computed(() => `status-chip--${props.badgeTone}`);

function handleOrgClick() {
  if (props.orgInteractive) {
    emit('open-full-client');
  }
}
</script>
