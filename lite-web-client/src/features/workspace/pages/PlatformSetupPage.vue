<template>
  <div class="workspace-page stack-lg">
    <section v-if="!showSetup" class="workspace-card stack">
      <h2 class="section-title">Managed setup is not available</h2>
      <p class="section-copy">
        This AuthOS Lite session does not have access to the standalone configuration workspace.
      </p>
    </section>

    <ManagedConfigPanel v-else />
  </div>
</template>

<script setup>
import { computed } from 'vue';
import ManagedConfigPanel from '@/components/ManagedConfigPanel.vue';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const showSetup = computed(() => authStore.isPlatformOwner && workspaceStore.managedConfigEnabled);
</script>
