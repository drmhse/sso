<template>
  <div class="workspace-page stack-lg">
    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <section v-if="workspaceStore.mode === 'loading'" class="workspace-card">
      <LoadingSpinner text="Loading users..." />
    </section>
    <section v-else-if="workspaceStore.mode !== 'ready'" class="workspace-card stack">
      <h2 class="section-title">User inspection is not available</h2>
      <p class="section-copy">
        AuthOS Lite can only review end-users after a single active organization has been resolved.
      </p>
    </section>
    <template v-else>
      <div v-if="loading" class="workspace-card">
        <LoadingSpinner text="Loading end-users..." />
      </div>
      <div v-else-if="error" class="workspace-card stack">
        <div class="alert alert-error">{{ error }}</div>
        <BaseButton variant="secondary" @click="loadUsers">Try again</BaseButton>
      </div>
      <div v-else-if="users.length === 0" class="workspace-card">
        <div class="alert alert-warning">No end-users have signed in to this application yet.</div>
      </div>
      <div v-else class="workspace-two-column workspace-two-column--users">
        <UsersTable
          :users="filteredUsers"
          :search="search"
          :selected-service-slug="selectedServiceSlug"
          :selected-user-id="selectedUserId"
          :service-options="serviceOptions"
          @update:search="search = $event"
          @update:selected-service-slug="selectedServiceSlug = $event"
          @select="inspectUser"
        />

        <UserDetailCard :user="selectedUser" :revoke-loading="revokeLoading" @revoke="revokeSessions" />
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import UserDetailCard from '@/features/workspace/components/users/UserDetailCard.vue';
import UsersTable from '@/features/workspace/components/users/UsersTable.vue';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';
import { sso } from '@/lib/api';
import { useWorkspaceStore } from '@/stores/workspace';
import { providerNameList } from '@/utils/formatting';

const workspaceStore = useWorkspaceStore();
const { refreshVersion } = useWorkspaceRuntime();

const loading = ref(false);
const detailLoading = ref(false);
const revokeLoading = ref(false);
const error = ref('');
const message = ref('');
const messageType = ref('success');
const users = ref([]);
const selectedUserId = ref('');
const selectedUser = ref(null);
const selectedServiceSlug = ref('');
const search = ref('');
const serviceOptions = ref([]);

const filteredUsers = computed(() => {
  const term = search.value.trim().toLowerCase();
  if (!term) return users.value;

  return users.value.filter((entry) => {
    const haystacks = [
      entry.user.email,
      ...providerNameList(entry.identities),
      ...entry.subscriptions.map((subscription) => subscription.service_name || ''),
    ]
      .filter(Boolean)
      .map((value) => String(value).toLowerCase());

    return haystacks.some((value) => value.includes(term));
  });
});

watch(
  () => [workspaceStore.currentOrgSlug, refreshVersion.value],
  async () => {
    if (workspaceStore.currentOrgSlug && workspaceStore.mode === 'ready') {
      await loadUsers();
    }
  },
  { immediate: true },
);

watch(selectedServiceSlug, async () => {
  if (workspaceStore.mode === 'ready' && workspaceStore.currentOrgSlug) {
    await loadUsers();
  }
});

async function loadUsers() {
  loading.value = true;
  error.value = '';
  selectedUser.value = null;
  selectedUserId.value = '';

  try {
    const servicesResponse = await sso.services.list(workspaceStore.currentOrgSlug);
    serviceOptions.value = (servicesResponse.services || []).map((service) => ({
      slug: service.slug,
      name: service.name,
    }));
    if (serviceOptions.value.length === 1 && !selectedServiceSlug.value) {
      selectedServiceSlug.value = serviceOptions.value[0].slug;
    }

    const response = await sso.organizations.endUsers.list(workspaceStore.currentOrgSlug, {
      limit: 100,
      ...(selectedServiceSlug.value ? { service_slug: selectedServiceSlug.value } : {}),
    });
    users.value = response.users || [];
  } catch (currentError) {
    error.value = currentError.message || 'Failed to load end-users.';
    users.value = [];
  } finally {
    loading.value = false;
  }
}

async function inspectUser(userId) {
  detailLoading.value = true;
  message.value = '';
  selectedUserId.value = userId;

  try {
    selectedUser.value = await sso.organizations.endUsers.get(workspaceStore.currentOrgSlug, userId);
  } catch (currentError) {
    messageType.value = 'error';
    message.value = currentError.message || 'Failed to load end-user details.';
  } finally {
    detailLoading.value = false;
  }
}

async function revokeSessions() {
  if (!selectedUser.value) return;
  revokeLoading.value = true;
  message.value = '';

  try {
    const response = await sso.organizations.endUsers.revokeSessions(
      workspaceStore.currentOrgSlug,
      selectedUser.value.user.id,
    );
    messageType.value = 'success';
    message.value = response.message || `Revoked ${response.revoked_count} sessions.`;
    await inspectUser(selectedUser.value.user.id);
    await loadUsers();
  } catch (currentError) {
    messageType.value = 'error';
    message.value = currentError.message || 'Failed to revoke end-user sessions.';
  } finally {
    revokeLoading.value = false;
  }
}
</script>
