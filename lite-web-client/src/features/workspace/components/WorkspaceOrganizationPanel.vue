<template>
  <section id="organization" class="panel stack" v-if="workspaceStore.mode === 'ready' || workspaceStore.mode === 'no-org'">
    <div>
      <h2>Organization</h2>
      <p class="muted">Update the single organization exposed by the lite client.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <template v-if="workspaceStore.currentOrganization">
      <div class="field">
        <label for="org-name">Organization name</label>
        <input id="org-name" v-model="orgName" class="input" />
      </div>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Slug</div>
          <div class="meta-value code">{{ workspaceStore.currentOrgSlug }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Members</div>
          <div class="meta-value">{{ workspaceStore.currentOrganization.membership_count }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Services</div>
          <div class="meta-value">{{ workspaceStore.currentOrganization.service_count }}</div>
        </div>
      </div>
      <BaseButton :loading="saving" @click="saveOrganization">Save organization changes</BaseButton>
    </template>
  </section>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const props = defineProps({
  refreshKey: { type: Number, default: 0 },
});

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const orgName = ref('');
const saving = ref(false);
const message = ref('');
const messageType = ref('success');
const canEditOrg = computed(() => ['owner', 'admin'].includes(authStore.activeOrgRole || ''));

watch(
  () => [props.refreshKey, workspaceStore.currentOrganization?.organization?.name],
  () => {
    orgName.value = workspaceStore.currentOrganization?.organization?.name || '';
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
</script>
