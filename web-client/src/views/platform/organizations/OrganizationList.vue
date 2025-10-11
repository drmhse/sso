<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">Organizations</h1>
        <p class="mt-2 text-gray-600">Manage and approve organizations on the platform.</p>
      </div>
    </div>

    <div class="mb-4 flex items-center space-x-4">
      <select
        v-model="statusFilter"
        class="block rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
        @change="handleFilterChange"
      >
        <option :value="null">All Statuses</option>
        <option value="pending">Pending</option>
        <option value="active">Active</option>
        <option value="suspended">Suspended</option>
        <option value="rejected">Rejected</option>
      </select>

      <button
        @click="refreshList"
        class="text-sm text-blue-600 hover:text-blue-800"
      >
        Refresh
      </button>
    </div>

    <LoadingSpinner v-if="platformStore.loading && organizations.length === 0" text="Loading organizations..." />

    <EmptyState
      v-else-if="!platformStore.loading && organizations.length === 0"
      icon="inbox"
      title="No organizations found"
      description="No organizations match the current filter."
    />

    <div v-else class="bg-white shadow overflow-hidden sm:rounded-lg">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Organization
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Slug
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Status
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Tier
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Created
            </th>
            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
          <tr v-for="org in organizations" :key="org.id">
            <td class="px-6 py-4 whitespace-nowrap">
              <div class="text-sm font-medium text-gray-900">{{ org.name }}</div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              {{ org.slug }}
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              <span
                class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                :class="statusClass(org.status)"
              >
                {{ org.status }}
              </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              {{ getTierDisplayName(org.tier_id) }}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              {{ formatDate(org.created_at) }}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
              <button
                v-if="org.status === 'pending'"
                @click="openApprovalModal(org)"
                class="text-green-600 hover:text-green-900"
              >
                Approve
              </button>
              <button
                v-if="org.status === 'pending'"
                @click="openRejectionModal(org)"
                class="text-red-600 hover:text-red-900"
              >
                Reject
              </button>
              <button
                v-if="org.status === 'active'"
                @click="handleSuspend(org)"
                class="text-yellow-600 hover:text-yellow-900"
              >
                Suspend
              </button>
              <button
                v-if="org.status === 'suspended'"
                @click="handleActivate(org)"
                class="text-green-600 hover:text-green-900"
              >
                Activate
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Approval Modal -->
    <BaseModal
      :is-open="approvalModal.isOpen"
      title="Approve Organization"
      confirm-text="Approve"
      confirm-variant="success"
      @close="closeApprovalModal"
      @confirm="handleApprove"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500">
          Approve <strong>{{ approvalModal.organization?.name }}</strong> and assign a tier.
        </p>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Tier <span class="text-red-500">*</span>
          </label>
          <select
            v-model="approvalModal.tierId"
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            required
          >
            <option v-for="tier in tiers" :key="tier.id" :value="tier.id">
              {{ tier.display_name }} - ${{ (tier.price_cents / 100).toFixed(2) }}/{{ tier.currency }}
            </option>
          </select>
          <p class="mt-1 text-sm text-gray-500">Select the tier to assign to this organization</p>
        </div>
      </div>
    </BaseModal>

    <!-- Rejection Modal -->
    <BaseModal
      :is-open="rejectionModal.isOpen"
      title="Reject Organization"
      confirm-text="Reject"
      confirm-variant="danger"
      @close="closeRejectionModal"
      @confirm="handleReject"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500">
          Are you sure you want to reject <strong>{{ rejectionModal.organization?.name }}</strong>?
        </p>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Reason <span class="text-red-500">*</span>
          </label>
          <input
            v-model="rejectionModal.reason"
            type="text"
            placeholder="Provide a reason for rejection"
            required
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          />
          <p class="mt-1 text-sm text-gray-500">This reason will be visible to the organization owner</p>
        </div>
      </div>
    </BaseModal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { usePlatformStore } from '@/stores/platform';
import { useNotifications } from '@/composables/useNotifications';
import { formatDate } from '@/utils/formatters';
import BaseModal from '@/components/BaseModal.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';

const platformStore = usePlatformStore();
const { success, error } = useNotifications();

const statusFilter = ref(null);

const organizations = computed(() => platformStore.organizations);
const tiers = computed(() => platformStore.tiers);

const approvalModal = ref({
  isOpen: false,
  organization: null,
  tierId: 'tier_starter',
});

const rejectionModal = ref({
  isOpen: false,
  organization: null,
  reason: '',
});

const statusClass = (status) => {
  const classes = {
    pending: 'bg-yellow-100 text-yellow-800',
    active: 'bg-green-100 text-green-800',
    suspended: 'bg-red-100 text-red-800',
    rejected: 'bg-gray-100 text-gray-800',
  };
  return classes[status] || 'bg-gray-100 text-gray-800';
};

const getTierDisplayName = (tierId) => {
  if (!tierId) return 'None';
  const tier = tiers.value.find(t => t.id === tierId);
  return tier ? tier.display_name : tierId;
};

const handleFilterChange = async () => {
  try {
    await platformStore.fetchOrganizations({
      status: statusFilter.value,
      page: 1,
    });
  } catch (err) {
    error('Filter Error', 'Failed to apply filter');
  }
};

const refreshList = async () => {
  try {
    await platformStore.fetchOrganizations({ status: statusFilter.value });
    success('Refreshed', 'Organization list updated');
  } catch (err) {
    error('Refresh Error', 'Failed to refresh list');
  }
};

const openApprovalModal = (org) => {
  approvalModal.value = {
    isOpen: true,
    organization: org,
    tierId: 'tier_starter',
  };
};

const closeApprovalModal = () => {
  approvalModal.value = {
    isOpen: false,
    organization: null,
    tierId: 'tier_starter',
  };
};

const handleApprove = async () => {
  try {
    await platformStore.approveOrganization(
      approvalModal.value.organization.id,
      approvalModal.value.tierId
    );
    success('Approved', `Organization ${approvalModal.value.organization.name} has been approved`);
    closeApprovalModal();
  } catch (err) {
    error('Approval Failed', err.message || 'Failed to approve organization');
  }
};

const openRejectionModal = (org) => {
  rejectionModal.value = {
    isOpen: true,
    organization: org,
    reason: '',
  };
};

const closeRejectionModal = () => {
  rejectionModal.value = {
    isOpen: false,
    organization: null,
    reason: '',
  };
};

const handleReject = async () => {
  if (!rejectionModal.value.reason) {
    error('Validation Error', 'Please provide a reason for rejection');
    return;
  }

  try {
    await platformStore.rejectOrganization(
      rejectionModal.value.organization.id,
      rejectionModal.value.reason
    );
    success('Rejected', `Organization ${rejectionModal.value.organization.name} has been rejected`);
    closeRejectionModal();
  } catch (err) {
    error('Rejection Failed', err.message || 'Failed to reject organization');
  }
};

const handleSuspend = async (org) => {
  if (!confirm(`Are you sure you want to suspend ${org.name}?`)) {
    return;
  }

  try {
    await platformStore.suspendOrganization(org.id);
    success('Suspended', `Organization ${org.name} has been suspended`);
  } catch (err) {
    error('Suspension Failed', err.message || 'Failed to suspend organization');
  }
};

const handleActivate = async (org) => {
  try {
    await platformStore.activateOrganization(org.id);
    success('Activated', `Organization ${org.name} has been activated`);
  } catch (err) {
    error('Activation Failed', err.message || 'Failed to activate organization');
  }
};

onMounted(() => {
  platformStore.fetchTiers();
  platformStore.fetchOrganizations();
});
</script>
