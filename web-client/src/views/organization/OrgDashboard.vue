<template>
  <div>
    <h1 class="text-2xl font-bold text-gray-900">Organization Dashboard</h1>
    <p class="mt-2 text-gray-600">Welcome to your organization dashboard.</p>

    <!-- Pending Approval State -->
    <div v-if="!organizationStore.isActive" class="mt-6">
      <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-lg">
        <div class="flex">
          <div class="flex-shrink-0">
            <svg class="h-6 w-6 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div class="ml-3">
            <h3 class="text-lg font-medium text-yellow-800">
              Organization Pending Approval
            </h3>
            <div class="mt-2 text-sm text-yellow-700">
              <p>Your organization <span class="font-semibold">{{ organizationStore.currentOrgName }}</span> is currently awaiting platform owner approval.</p>
              <p class="mt-2">You'll be able to access the following features once approved:</p>
              <ul class="mt-2 ml-5 list-disc space-y-1">
                <li>Create and manage services</li>
                <li>Configure custom OAuth credentials (BYOO)</li>
                <li>View and manage end users</li>
                <li>Full dashboard access</li>
              </ul>
              <p class="mt-3 text-xs">Current status: <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase" :class="{
                'bg-yellow-100 text-yellow-800': organizationStore.currentOrgStatus === 'pending',
                'bg-green-100 text-green-800': organizationStore.currentOrgStatus === 'active',
                'bg-red-100 text-red-800': organizationStore.currentOrgStatus === 'rejected',
                'bg-gray-100 text-gray-800': organizationStore.currentOrgStatus === 'suspended'
              }">{{ organizationStore.currentOrgStatus || 'Loading...' }}</span></p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Active Organization Dashboard -->
    <div v-else class="mt-6 space-y-6">
      <!-- Loading State -->
      <div v-if="loading" class="text-center py-12">
        <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p class="mt-2 text-gray-600">Loading dashboard...</p>
      </div>

      <!-- Error State -->
      <div v-else-if="error" class="bg-red-50 border-l-4 border-red-400 p-4 rounded">
        <p class="text-sm text-red-700">{{ error }}</p>
      </div>

      <!-- Dashboard Content -->
      <div v-else>
        <!-- KPI Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <!-- Total End Users -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0 bg-blue-500 rounded-md p-3">
                <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-gray-500 truncate">Total End Users</dt>
                  <dd class="text-2xl font-semibold text-gray-900">{{ kpis.totalEndUsers }}</dd>
                </dl>
              </div>
            </div>
          </div>

          <!-- Total Services -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0 bg-green-500 rounded-md p-3">
                <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-gray-500 truncate">Total Services</dt>
                  <dd class="text-2xl font-semibold text-gray-900">{{ kpis.totalServices }}</dd>
                </dl>
              </div>
            </div>
          </div>

          <!-- Team Members -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0 bg-purple-500 rounded-md p-3">
                <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-gray-500 truncate">Team Members</dt>
                  <dd class="text-2xl font-semibold text-gray-900">{{ kpis.totalMembers }}</dd>
                </dl>
              </div>
            </div>
          </div>

          <!-- Recent Logins (Last 24h) -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center">
              <div class="flex-shrink-0 bg-yellow-500 rounded-md p-3">
                <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-gray-500 truncate">Logins (24h)</dt>
                  <dd class="text-2xl font-semibold text-gray-900">{{ kpis.recentLogins }}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <!-- Login Trends Chart -->
        <div class="bg-white rounded-lg shadow p-6">
          <h3 class="text-lg font-medium text-gray-900 mb-4">Login Trends (Last 30 Days)</h3>
          <div v-if="loginTrends.length === 0" class="text-center py-8 text-gray-500">
            No login data available
          </div>
          <div v-else class="space-y-2">
            <div v-for="trend in loginTrends" :key="trend.date" class="flex items-center">
              <span class="text-sm text-gray-600 w-24">{{ formatDate(trend.date) }}</span>
              <div class="flex-1 bg-gray-200 rounded-full h-4 ml-4">
                <div
                  class="bg-blue-600 h-4 rounded-full"
                  :style="{ width: getBarWidth(trend.count) }"
                ></div>
              </div>
              <span class="text-sm font-semibold text-gray-900 ml-4 w-12 text-right">{{ trend.count }}</span>
            </div>
          </div>
        </div>

        <!-- Two Column Layout for Service and Provider Stats -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Logins by Service -->
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-medium text-gray-900 mb-4">Logins by Service</h3>
            <div v-if="loginsByService.length === 0" class="text-center py-8 text-gray-500">
              No service data available
            </div>
            <div v-else class="space-y-3">
              <div v-for="service in loginsByService" :key="service.service_id" class="flex items-center justify-between">
                <span class="text-sm font-medium text-gray-700">{{ service.service_name }}</span>
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold bg-blue-100 text-blue-800">
                  {{ service.count }}
                </span>
              </div>
            </div>
          </div>

          <!-- Logins by Provider -->
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-medium text-gray-900 mb-4">Logins by Provider</h3>
            <div v-if="loginsByProvider.length === 0" class="text-center py-8 text-gray-500">
              No provider data available
            </div>
            <div v-else class="space-y-3">
              <div v-for="provider in loginsByProvider" :key="provider.provider" class="flex items-center justify-between">
                <div class="flex items-center">
                  <span class="text-sm font-medium text-gray-700 capitalize">{{ provider.provider }}</span>
                </div>
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold" :class="{
                  'bg-gray-800 text-white': provider.provider === 'github',
                  'bg-red-100 text-red-800': provider.provider === 'google',
                  'bg-blue-100 text-blue-800': provider.provider === 'microsoft'
                }">
                  {{ provider.count }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Login Events -->
        <div class="bg-white rounded-lg shadow p-6">
          <h3 class="text-lg font-medium text-gray-900 mb-4">Recent Login Events</h3>
          <div v-if="recentLogins.length === 0" class="text-center py-8 text-gray-500">
            No recent logins
          </div>
          <div v-else class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead>
                <tr>
                  <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Time
                  </th>
                  <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Provider
                  </th>
                  <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    User ID
                  </th>
                  <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Service ID
                  </th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                <tr v-for="login in recentLogins" :key="login.id">
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {{ formatDateTime(login.created_at) }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize" :class="{
                      'bg-gray-800 text-white': login.provider === 'github',
                      'bg-red-100 text-red-800': login.provider === 'google',
                      'bg-blue-100 text-blue-800': login.provider === 'microsoft'
                    }">
                      {{ login.provider }}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">
                    {{ login.user_id.substring(0, 8) }}...
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">
                    {{ login.service_id.substring(0, 8) }}...
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import { useRoute } from 'vue-router';
import { useOrganizationStore } from '@/stores/organization';
import { sso } from '@/api';

const route = useRoute();
const organizationStore = useOrganizationStore();

const loading = ref(true);
const error = ref(null);

// KPI data
const kpis = ref({
  totalEndUsers: 0,
  totalServices: 0,
  totalMembers: 0,
  recentLogins: 0
});

// Analytics data
const loginTrends = ref([]);
const loginsByService = ref([]);
const loginsByProvider = ref([]);
const recentLogins = ref([]);

// Computed max value for bar chart scaling
const maxLoginCount = computed(() => {
  if (loginTrends.value.length === 0) return 1;
  return Math.max(...loginTrends.value.map(t => t.count), 1);
});

// Helper functions
const getBarWidth = (count) => {
  return `${(count / maxLoginCount.value) * 100}%`;
};

const formatDate = (dateStr) => {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const formatDateTime = (dateStr) => {
  const date = new Date(dateStr);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

// Load dashboard data
const loadDashboardData = async () => {
  try {
    loading.value = true;
    error.value = null;

    const orgSlug = route.params.orgSlug;

    // Calculate date range (last 30 days)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    const formatDateParam = (date) => {
      return date.toISOString().split('T')[0];
    };

    // Fetch all data in parallel
    const [
      endUsersData,
      servicesData,
      membersData,
      trendsData,
      byServiceData,
      byProviderData,
      recentLoginsData
    ] = await Promise.all([
      sso.organizations.endUsers.list(orgSlug).catch(() => ({ total: 0, users: [], page: 1, limit: 10 })),
      sso.services.list(orgSlug).catch(() => ({ services: [], usage: { current_services: 0, max_services: 0, tier: '' } })),
      sso.organizations.members.list(orgSlug).catch(() => ({ members: [], total: 0, limit: { current: 0, max: 0, source: '' } })),
      sso.analytics.getLoginTrends(orgSlug, {
        start_date: formatDateParam(startDate),
        end_date: formatDateParam(endDate)
      }).catch(() => []),
      sso.analytics.getLoginsByService(orgSlug, {
        start_date: formatDateParam(startDate),
        end_date: formatDateParam(endDate)
      }).catch(() => []),
      sso.analytics.getLoginsByProvider(orgSlug, {
        start_date: formatDateParam(startDate),
        end_date: formatDateParam(endDate)
      }).catch(() => []),
      sso.analytics.getRecentLogins(orgSlug, { limit: 10 }).catch(() => [])
    ]);

    // Update KPIs
    kpis.value.totalEndUsers = endUsersData.total || 0;
    kpis.value.totalServices = servicesData.services?.length || 0;
    kpis.value.totalMembers = membersData.members?.length || 0;

    // Calculate recent logins (last 24 hours)
    const oneDayAgo = new Date();
    oneDayAgo.setHours(oneDayAgo.getHours() - 24);
    kpis.value.recentLogins = recentLoginsData.filter(
      login => new Date(login.created_at) > oneDayAgo
    ).length;

    // Update analytics data
    loginTrends.value = trendsData;
    loginsByService.value = byServiceData;
    loginsByProvider.value = byProviderData;
    recentLogins.value = recentLoginsData;

  } catch (err) {
    console.error('Failed to load dashboard data:', err);
    error.value = 'Failed to load dashboard data. Please try refreshing the page.';
  } finally {
    loading.value = false;
  }
};

onMounted(async () => {
  const orgSlug = route.params.orgSlug;
  if (orgSlug && !organizationStore.currentOrganization) {
    try {
      await organizationStore.fetchOrganization(orgSlug);
    } catch (error) {
      console.error('Failed to fetch organization:', error);
    }
  }

  // Load dashboard data if organization is active
  if (organizationStore.isActive) {
    await loadDashboardData();
  }
});
</script>
