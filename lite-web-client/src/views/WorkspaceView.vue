<template>
  <div class="page-shell workspace-page-shell">
    <div class="workspace-shell split">
      <WorkspaceSidebar
        :user-email="authStore.userEmail"
        :show-setup="showSetup"
        :full-client-url="workspaceStore.fullClientUrl"
        @refresh="reload"
        @logout="authStore.logout"
        @open-full-client="openFullClient"
      />

      <main class="section-list">
        <WorkspaceOverviewPanel
          :mode="workspaceStore.mode"
          :error="workspaceStore.error"
          :email="authStore.user?.email"
          :org-name="workspaceStore.currentOrgName"
          :org-status="workspaceStore.currentOrgStatus"
          :role="authStore.activeOrgRole"
          :full-client-url="workspaceStore.fullClientUrl"
          @open-full-client="openFullClient"
        />

        <ManagedConfigPanel v-if="showSetup" id="setup" />

        <WorkspaceOrganizationPanel :refresh-key="refreshKey" />

        <ApplicationsPanel
          id="application"
          v-if="workspaceStore.mode === 'ready'"
          :org-slug="workspaceStore.currentOrgSlug"
          :can-manage="canEditOrg"
          :refresh-key="refreshKey"
          @services-loaded="updateServiceOptions"
        />

        <EndUsersPanel
          id="users"
          v-if="workspaceStore.mode === 'ready'"
          :org-slug="workspaceStore.currentOrgSlug"
          :service-options="serviceOptions"
          :refresh-key="refreshKey"
        />

        <WorkspaceAccountPanel :refresh-key="refreshKey" />
        <WorkspaceSecurityPanel :refresh-key="refreshKey" />
        <WorkspaceInvitationsPanel :refresh-key="refreshKey" @workspace-changed="reload" />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import ApplicationsPanel from '@/components/ApplicationsPanel.vue';
import EndUsersPanel from '@/components/EndUsersPanel.vue';
import ManagedConfigPanel from '@/components/ManagedConfigPanel.vue';
import WorkspaceAccountPanel from '@/features/workspace/components/WorkspaceAccountPanel.vue';
import WorkspaceInvitationsPanel from '@/features/workspace/components/WorkspaceInvitationsPanel.vue';
import WorkspaceOrganizationPanel from '@/features/workspace/components/WorkspaceOrganizationPanel.vue';
import WorkspaceOverviewPanel from '@/features/workspace/components/WorkspaceOverviewPanel.vue';
import WorkspaceSecurityPanel from '@/features/workspace/components/WorkspaceSecurityPanel.vue';
import WorkspaceSidebar from '@/features/workspace/components/WorkspaceSidebar.vue';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const refreshKey = ref(0);
const serviceOptions = ref([]);

const canEditOrg = computed(() => ['owner', 'admin'].includes(authStore.activeOrgRole || ''));
const showSetup = computed(() => authStore.isPlatformOwner && workspaceStore.managedConfigEnabled);

onMounted(reload);

async function reload() {
  await workspaceStore.resolveWorkspace();
  serviceOptions.value = [];
  refreshKey.value += 1;
}

function updateServiceOptions(services) {
  serviceOptions.value = services;
}

function openFullClient() {
  workspaceStore.redirectToFullClient('/home');
}
</script>
