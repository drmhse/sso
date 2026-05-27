<template>
  <div class="workspace-page stack-lg">
    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <section v-if="workspaceStore.mode === 'loading'" class="workspace-card">
      <LoadingSpinner text="Loading organization..." />
    </section>
    <section v-else-if="workspaceStore.mode !== 'ready'" class="workspace-card stack">
      <h2 class="section-title">Organization management is not available</h2>
      <p class="section-copy">
        AuthOS Lite can only manage organization settings after a single active organization has been resolved.
      </p>
    </section>
    <template v-else>
      <OrganizationProfileCard
        :org-name="orgName"
        :org-slug="workspaceStore.currentOrgSlug"
        :membership-count="workspaceStore.currentOrganization?.membership_count || 0"
        :service-count="workspaceStore.currentOrganization?.service_count || 0"
        :can-edit="canEditOrg"
        :saving="saving"
        @update:org-name="orgName = $event"
        @save="saveOrganization"
      />

      <OrganizationInvitationsCard
        :invitations="invitations"
        @accept="acceptInvitation"
        @decline="declineInvitation"
      />
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import OrganizationInvitationsCard from '@/features/workspace/components/organization/OrganizationInvitationsCard.vue';
import OrganizationProfileCard from '@/features/workspace/components/organization/OrganizationProfileCard.vue';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();
const { refreshVersion, reload } = useWorkspaceRuntime();

const orgName = ref('');
const saving = ref(false);
const message = ref('');
const messageType = ref('success');
const invitations = ref([]);
const canEditOrg = computed(() => ['owner', 'admin'].includes(authStore.activeOrgRole || ''));

watch(
  () => [refreshVersion.value, workspaceStore.currentOrganization?.organization?.name],
  async () => {
    orgName.value = workspaceStore.currentOrganization?.organization?.name || '';
    if (workspaceStore.mode === 'ready') {
      invitations.value = await sso.invitations.listForUser();
    } else {
      invitations.value = [];
    }
  },
  { immediate: true },
);

async function saveOrganization() {
  if (!workspaceStore.currentOrganization || !canEditOrg.value) {
    messageType.value = 'error';
    message.value = 'This session cannot update organization settings.';
    return;
  }

  saving.value = true;
  message.value = '';

  try {
    await workspaceStore.updateOrganization({ name: orgName.value });
    messageType.value = 'success';
    message.value = 'Organization updated.';
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to update the organization.';
  } finally {
    saving.value = false;
  }
}

async function declineInvitation(invitationId) {
  try {
    await sso.invitations.declineById(invitationId);
    invitations.value = await sso.invitations.listForUser();
    messageType.value = 'success';
    message.value = 'Invitation declined.';
    await reload();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to decline the invitation.';
  }
}

async function acceptInvitation(invitationId) {
  try {
    await sso.invitations.acceptById(invitationId);
    invitations.value = await sso.invitations.listForUser();
    messageType.value = 'success';
    message.value = 'Invitation accepted.';
    await reload();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to accept the invitation.';
  }
}
</script>
