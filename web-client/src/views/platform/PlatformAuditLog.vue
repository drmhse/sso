<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Platform Audit Log</h1>
      <p class="mt-2 text-gray-600">View all platform-level administrative actions and changes.</p>
    </div>

    <!-- Filters -->
    <div class="bg-white shadow rounded-lg p-6 mb-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">Filters</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- Action Filter -->
        <div>
          <label for="action-filter" class="block text-sm font-medium text-gray-700 mb-2">
            Action
          </label>
          <select
            id="action-filter"
            v-model="filters.action"
            @change="applyFilters"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="">All Actions</option>
            <option value="approve_organization">Approve Organization</option>
            <option value="reject_organization">Reject Organization</option>
            <option value="suspend_organization">Suspend Organization</option>
            <option value="activate_organization">Activate Organization</option>
            <option value="update_organization_tier">Update Tier</option>
            <option value="promote_platform_owner">Promote Owner</option>
            <option value="demote_platform_owner">Demote Owner</option>
          </select>
        </div>

        <!-- Target Type Filter -->
        <div>
          <label for="target-type-filter" class="block text-sm font-medium text-gray-700 mb-2">
            Target Type
          </label>
          <select
            id="target-type-filter"
            v-model="filters.target_type"
            @change="applyFilters"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="">All Types</option>
            <option value="organization">Organization</option>
            <option value="user">User</option>
          </select>
        </div>

        <!-- Clear Filters -->
        <div class="flex items-end">
          <button
            @click="clearFilters"
            class="px-4 py-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
          >
            Clear Filters
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      <p class="mt-2 text-gray-600">Loading audit log...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="bg-red-50 border-l-4 border-red-400 p-4 rounded">
      <p class="text-sm text-red-700">{{ error }}</p>
    </div>

    <!-- Audit Log Table -->
    <div v-else class="bg-white shadow rounded-lg overflow-hidden">
      <div v-if="logs.length === 0" class="text-center py-12">
        <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p class="mt-2 text-sm text-gray-500">No audit log entries found</p>
        <p class="mt-1 text-xs text-gray-400">Audit entries will appear here as platform actions are performed</p>
      </div>

      <div v-else>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Timestamp
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Action
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Target
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Details
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <tr
                v-for="log in logs"
                :key="log.id"
                class="hover:bg-gray-50 transition-colors"
              >
                <!-- Timestamp -->
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  <div>{{ formatDateTime(log.created_at) }}</div>
                  <div class="text-xs text-gray-500">{{ formatTimeAgo(log.created_at) }}</div>
                </td>

                <!-- Action -->
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                    :class="getActionBadgeClass(log.action)"
                  >
                    {{ formatAction(log.action) }}
                  </span>
                </td>

                <!-- Target -->
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium text-gray-900">
                    {{ formatTargetType(log.target_type) }}
                  </div>
                  <div class="text-xs text-gray-500 font-mono">
                    {{ log.target_id.substring(0, 8) }}...
                  </div>
                </td>

                <!-- Details -->
                <td class="px-6 py-4">
                  <button
                    v-if="log.metadata"
                    @click="showMetadata(log)"
                    class="text-blue-600 hover:text-blue-800 text-sm"
                  >
                    View Details
                  </button>
                  <span v-else class="text-gray-400 text-sm">No details</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div class="bg-gray-50 px-6 py-4 border-t border-gray-200">
          <div class="flex items-center justify-between">
            <div class="text-sm text-gray-700">
              Showing {{ ((currentPage - 1) * pageSize) + 1 }} to {{ Math.min(currentPage * pageSize, totalLogs) }} of {{ totalLogs }} entries
            </div>
            <div class="flex space-x-2">
              <button
                @click="previousPage"
                :disabled="currentPage === 1"
                class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>
              <button
                @click="nextPage"
                :disabled="currentPage * pageSize >= totalLogs"
                class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Metadata Modal -->
    <div v-if="selectedLog" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50 flex items-center justify-center">
      <div class="relative p-8 bg-white w-full max-w-2xl m-4 rounded-lg shadow-xl">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-gray-900">Audit Log Details</h3>
          <button
            @click="selectedLog = null"
            class="text-gray-400 hover:text-gray-600"
          >
            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Action</label>
            <p class="text-sm text-gray-900">{{ formatAction(selectedLog.action) }}</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Target</label>
            <p class="text-sm text-gray-900">
              {{ formatTargetType(selectedLog.target_type) }} ({{ selectedLog.target_id }})
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Timestamp</label>
            <p class="text-sm text-gray-900">{{ formatDateTime(selectedLog.created_at) }}</p>
          </div>

          <div v-if="selectedLog.metadata">
            <label class="block text-sm font-medium text-gray-700 mb-1">Metadata</label>
            <pre class="text-sm text-gray-900 bg-gray-50 rounded p-4 overflow-x-auto">{{ formatMetadata(selectedLog.metadata) }}</pre>
          </div>
        </div>

        <div class="mt-6 flex justify-end">
          <button
            @click="selectedLog = null"
            class="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { sso } from '@/api';

const loading = ref(true);
const error = ref(null);
const logs = ref([]);
const totalLogs = ref(0);
const currentPage = ref(1);
const pageSize = ref(50);
const selectedLog = ref(null);

const filters = ref({
  action: '',
  target_type: ''
});

// Format helpers
const formatDateTime = (dateStr) => {
  const date = new Date(dateStr);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

const formatTimeAgo = (dateStr) => {
  const date = new Date(dateStr);
  const now = new Date();
  const seconds = Math.floor((now - date) / 1000);

  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
};

const formatAction = (action) => {
  return action
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

const formatTargetType = (targetType) => {
  return targetType.charAt(0).toUpperCase() + targetType.slice(1);
};

const formatMetadata = (metadata) => {
  try {
    const parsed = typeof metadata === 'string' ? JSON.parse(metadata) : metadata;
    return JSON.stringify(parsed, null, 2);
  } catch {
    return metadata;
  }
};

const getActionBadgeClass = (action) => {
  if (action.includes('approve') || action.includes('activate')) {
    return 'bg-green-100 text-green-800';
  }
  if (action.includes('reject')) {
    return 'bg-red-100 text-red-800';
  }
  if (action.includes('suspend')) {
    return 'bg-orange-100 text-orange-800';
  }
  if (action.includes('promote')) {
    return 'bg-blue-100 text-blue-800';
  }
  if (action.includes('demote')) {
    return 'bg-gray-100 text-gray-800';
  }
  return 'bg-purple-100 text-purple-800';
};

// Data loading
const loadAuditLogs = async () => {
  try {
    loading.value = true;
    error.value = null;

    const params = {
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value
    };

    if (filters.value.action) {
      params.action = filters.value.action;
    }

    if (filters.value.target_type) {
      params.target_type = filters.value.target_type;
    }

    const response = await sso.platform.getAuditLog(params);
    logs.value = response.logs;
    totalLogs.value = response.total;

  } catch (err) {
    console.error('Failed to load audit logs:', err);
    error.value = 'Failed to load audit logs. Please try refreshing the page.';
  } finally {
    loading.value = false;
  }
};

// Filter actions
const applyFilters = () => {
  currentPage.value = 1;
  loadAuditLogs();
};

const clearFilters = () => {
  filters.value.action = '';
  filters.value.target_type = '';
  currentPage.value = 1;
  loadAuditLogs();
};

// Pagination
const previousPage = () => {
  if (currentPage.value > 1) {
    currentPage.value--;
    loadAuditLogs();
  }
};

const nextPage = () => {
  if (currentPage.value * pageSize.value < totalLogs.value) {
    currentPage.value++;
    loadAuditLogs();
  }
};

// Modal actions
const showMetadata = (log) => {
  selectedLog.value = log;
};

onMounted(async () => {
  await loadAuditLogs();
});
</script>
