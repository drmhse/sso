<template>
  <div class="workspace-page">
    <AccountSecurityControls :refresh-version="refreshVersion" />
  </div>
</template>

<script setup>
import AccountSecurityControls from '@/features/workspace/components/security/AccountSecurityControls.vue';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';

const { refreshVersion } = useWorkspaceRuntime();
</script>
