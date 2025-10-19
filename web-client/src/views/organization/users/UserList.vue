<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">End Users</h1>
        <p class="mt-2 text-gray-600">
          Manage your organization's customers and their access.
        </p>
      </div>
    </div>

    <!-- Service Filter -->
    <div class="mb-6">
      <label for="service-filter" class="block text-sm font-medium text-gray-700 mb-2">
        Filter by Service
      </label>
      <select
        id="service-filter"
        v-model="selectedServiceSlug"
        @change="handleServiceFilterChange"
        class="block w-full sm:w-64 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
      >
        <option :value="null">All Services</option>
        <option v-for="service in services" :key="service.id" :value="service.slug">
          {{ service.name }}
        </option>
      </select>
    </div>

    <LoadingSpinner v-if="loading" text="Loading end users..." />

    <div v-else class="space-y-6">
      <!-- Users List -->
      <div class="bg-white shadow overflow-hidden sm:rounded-lg">
        <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
          <div class="flex justify-between items-center">
            <h3 class="text-lg leading-6 font-medium text-gray-900">
              End Users ({{ endUsersStore.total }})
            </h3>
          </div>
        </div>

        <EmptyState
          v-if="users.length === 0"
          icon="users"
          title="No end users yet"
          description="Your organization doesn't have any customers yet."
        />

        <ul v-else class="divide-y divide-gray-200">
          <li v-for="user in users" :key="user.user.id" class="px-6 py-4 hover:bg-gray-50">
            <div class="flex items-center justify-between">
              <div class="flex-1">
                <p class="text-sm font-medium text-gray-900">
                  {{ user.user.email }}
                </p>
                <div class="mt-1 text-sm text-gray-500 space-y-1">
                  <p>Registered: {{ formatDate(user.user.created_at) }}</p>
                  <div class="flex flex-wrap gap-2">
                    <span
                      v-for="sub in user.subscriptions"
                      :key="sub.service_id"
                      class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
                      :class="subscriptionClass(sub.status)"
                    >
                      {{ sub.service_name }} - {{ sub.plan_name }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="flex items-center space-x-4">
                <button
                  @click="viewUserDetails(user.user.id)"
                  class="text-blue-600 hover:text-blue-900 text-sm"
                >
                  View Details
                </button>
              </div>
            </div>
          </li>
        </ul>

        <!-- Load More Button -->
        <div
          v-if="endUsersStore.hasMore"
          class="px-6 py-4 border-t border-gray-200 text-center"
        >
          <BaseButton
            @click="loadMore"
            variant="secondary"
            :disabled="endUsersStore.loading"
          >
            Load More
          </BaseButton>
        </div>
      </div>
    </div>

    <!-- User Details Modal -->
    <BaseModal
      :is-open="detailsModal.isOpen"
      title="User Details"
      confirm-text="Close"
      @close="closeDetailsModal"
      @confirm="closeDetailsModal"
      :show-cancel="false"
    >
      <div v-if="selectedUser" class="space-y-6">
        <!-- User Information -->
        <div>
          <h4 class="text-sm font-medium text-gray-900 mb-2">User Information</h4>
          <dl class="grid grid-cols-1 gap-x-4 gap-y-3">
            <div>
              <dt class="text-sm font-medium text-gray-500">Email</dt>
              <dd class="mt-1 text-sm text-gray-900">{{ selectedUser.user.email }}</dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500">Registered</dt>
              <dd class="mt-1 text-sm text-gray-900">
                {{ formatDate(selectedUser.user.created_at) }}
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500">Active Sessions</dt>
              <dd class="mt-1 text-sm text-gray-900">{{ selectedUser.session_count }}</dd>
            </div>
          </dl>
        </div>

        <!-- Subscriptions -->
        <div>
          <h4 class="text-sm font-medium text-gray-900 mb-2">Subscriptions</h4>
          <ul class="space-y-2">
            <li
              v-for="sub in selectedUser.subscriptions"
              :key="sub.service_id"
              class="flex justify-between items-center p-3 bg-gray-50 rounded-md"
            >
              <div>
                <p class="text-sm font-medium text-gray-900">{{ sub.service_name }}</p>
                <p class="text-xs text-gray-500">Plan: {{ sub.plan_name }}</p>
              </div>
              <span
                class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                :class="subscriptionClass(sub.status)"
              >
                {{ sub.status }}
              </span>
            </li>
          </ul>
        </div>

        <!-- OAuth Identities -->
        <div>
          <h4 class="text-sm font-medium text-gray-900 mb-2">Connected Accounts</h4>
          <ul class="space-y-2">
            <li
              v-for="identity in selectedUser.identities"
              :key="identity.provider"
              class="flex justify-between items-center p-3 bg-gray-50 rounded-md"
            >
              <div>
                <p class="text-sm font-medium text-gray-900 capitalize">{{ identity.provider }}</p>
                <p class="text-xs text-gray-500">ID: {{ identity.provider_user_id }}</p>
              </div>
              <span class="text-xs text-gray-500">
                Connected {{ formatDate(identity.created_at) }}
              </span>
            </li>
          </ul>
        </div>

        <!-- Actions -->
        <div v-if="canManageTeam" class="pt-4 border-t border-gray-200">
          <BaseButton
            @click="handleRevokeAllSessions"
            variant="danger"
            :disabled="selectedUser.session_count === 0"
          >
            Revoke All Sessions
          </BaseButton>
          <p class="mt-2 text-xs text-gray-500">
            This will force the user to log in again.
          </p>
        </div>
      </div>
    </BaseModal>

    <!-- Revoke Sessions Confirmation -->
    <ConfirmDialog
      :open="revokeSessionsDialog.isOpen"
      title="Revoke All Sessions"
      :message="`Are you sure you want to revoke all sessions for ${selectedUser?.user.email}? They will need to log in again.`"
      confirm-text="Revoke All Sessions"
      variant="danger"
      @confirm="confirmRevokeAllSessions"
      @cancel="revokeSessionsDialog.isOpen = false"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useEndUsersStore } from '@/stores/endUsers';
import { useServicesStore } from '@/stores/services';
import { usePermissions } from '@/composables/usePermissions';
import { useNotifications } from '@/composables/useNotifications';
import { formatDate } from '@/utils/formatters';
import BaseModal from '@/components/BaseModal.vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';
import ConfirmDialog from '@/components/ConfirmDialog.vue';

const route = useRoute();
const router = useRouter();
const endUsersStore = useEndUsersStore();
const servicesStore = useServicesStore();
const { canManageTeam } = usePermissions();
const { success, error } = useNotifications();

const loading = ref(false);
const selectedUser = ref(null);
const selectedServiceSlug = ref(null);

const orgSlug = computed(() => route.params.orgSlug);
const users = computed(() => endUsersStore.users);
const services = computed(() => servicesStore.services);

const detailsModal = ref({
  isOpen: false,
});

const revokeSessionsDialog = ref({
  isOpen: false,
});

const subscriptionClass = (status) => {
  const classes = {
    active: 'bg-green-100 text-green-800',
    cancelled: 'bg-yellow-100 text-yellow-800',
    expired: 'bg-red-100 text-red-800',
  };
  return classes[status] || 'bg-gray-100 text-gray-800';
};

const viewUserDetails = async (userId) => {
  try {
    selectedUser.value = await endUsersStore.fetchEndUser(orgSlug.value, userId);
    detailsModal.value.isOpen = true;
  } catch (err) {
    error('Load Error', err.message || 'Failed to load user details');
  }
};

const closeDetailsModal = () => {
  detailsModal.value.isOpen = false;
  selectedUser.value = null;
};

const handleRevokeAllSessions = () => {
  if (!selectedUser.value) return;
  revokeSessionsDialog.value.isOpen = true;
};

const confirmRevokeAllSessions = async () => {
  revokeSessionsDialog.value.isOpen = false;

  if (!selectedUser.value) return;

  try {
    const result = await endUsersStore.revokeUserSessions(
      orgSlug.value,
      selectedUser.value.user.id
    );
    success('Sessions Revoked', `${result.revoked_count} session(s) revoked successfully`);

    // Update selected user session count
    selectedUser.value.session_count = 0;
  } catch (err) {
    error('Revocation Failed', err.message || 'Failed to revoke sessions');
  }
};

const handleServiceFilterChange = async () => {
  await loadData();
};

const loadMore = async () => {
  try {
    await endUsersStore.loadMore(orgSlug.value, selectedServiceSlug.value);
  } catch (err) {
    error('Load Error', err.message || 'Failed to load more users');
  }
};

const loadData = async () => {
  loading.value = true;
  try {
    await endUsersStore.fetchEndUsers(orgSlug.value, 1, 50, selectedServiceSlug.value);
  } catch (err) {
    error('Load Error', 'Failed to load end users');
  } finally {
    loading.value = false;
  }
};

onMounted(async () => {
  // Fetch services for the filter dropdown
  try {
    await servicesStore.fetchServices(orgSlug.value);
  } catch (err) {
    // Services load error is not critical, just log it
    console.error('Failed to load services for filter:', err);
  }
  
  // Load end users
  await loadData();
});
</script>
