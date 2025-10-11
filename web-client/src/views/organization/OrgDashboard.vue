<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Organization Dashboard</h1>
      <p class="mt-2 text-gray-600">Analytics and insights for {{ organizationStore.currentOrgName }}</p>
    </div>

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
    <div v-else class="space-y-6">
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
      <div v-else class="space-y-6">
        <!-- Top KPI Cards -->
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

        <!-- Activity Metrics Row -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <!-- Logins Last 30d -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-500">Logins (30 days)</p>
                <p class="text-3xl font-bold text-gray-900 mt-2">{{ kpis.totalLogins30d }}</p>
              </div>
              <div class="bg-indigo-100 rounded-full p-3">
                <svg class="h-8 w-8 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>

          <!-- Average Daily Logins -->
          <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-500">Average Daily Logins</p>
                <p class="text-3xl font-bold text-gray-900 mt-2">{{ kpis.avgDailyLogins }}</p>
              </div>
              <div class="bg-green-100 rounded-full p-3">
                <svg class="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                </svg>
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
                  class="bg-indigo-600 h-4 rounded-full transition-all duration-300"
                  :style="{ width: getBarWidth(trend.count) }"
                ></div>
              </div>
              <span class="text-sm font-semibold text-gray-900 ml-4 w-16 text-right">{{ trend.count }}</span>
            </div>
          </div>
        </div>

        <!-- Two Column Layout for Service and Provider Stats -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Logins by Service -->
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-medium text-gray-900 mb-4">Most Active Services</h3>
            <div v-if="loginsByService.length === 0" class="text-center py-8 text-gray-500">
              No service data available
            </div>
            <div v-else class="space-y-3">
              <div
                v-for="(service, index) in loginsByService"
                :key="service.service_id"
                class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <div class="flex items-center space-x-3">
                  <span class="flex items-center justify-center w-8 h-8 rounded-full bg-blue-600 text-white text-sm font-bold">
                    {{ index + 1 }}
                  </span>
                  <span class="text-sm font-medium text-gray-900">{{ service.service_name }}</span>
                </div>
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
              <div
                v-for="provider in loginsByProvider"
                :key="provider.provider"
                class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <div class="flex items-center space-x-3">
                  <div class="flex items-center justify-center w-8 h-8 rounded-full" :class="{
                    'bg-gray-800': provider.provider === 'github',
                    'bg-red-500': provider.provider === 'google',
                    'bg-blue-500': provider.provider === 'microsoft'
                  }">
                    <svg class="h-4 w-4 text-white" fill="currentColor" viewBox="0 0 24 24">
                      <path v-if="provider.provider === 'github'" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                      <path v-else-if="provider.provider === 'google'" d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z"/>
                      <circle v-else cx="12" cy="12" r="10"/>
                    </svg>
                  </div>
                  <span class="text-sm font-medium text-gray-900 capitalize">{{ provider.provider }}</span>
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
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-medium text-gray-900">Recent Login Events</h3>
            <span class="text-xs text-gray-500">Last 10 logins</span>
          </div>
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
                    Service
                  </th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                <tr v-for="login in recentLogins" :key="login.id" class="hover:bg-gray-50 transition-colors">
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
                    {{ getServiceName(login.service_id) }}
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
  recentLogins: 0,
  totalLogins30d: 0,
  avgDailyLogins: 0
});

// Analytics data
const loginTrends = ref([]);
const loginsByService = ref([]);
const loginsByProvider = ref([]);
const recentLogins = ref([]);
const services = ref([]);

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

const getServiceName = (serviceId) => {
  const service = services.value.find(s => s.id === serviceId);
  return service ? service.name : serviceId.substring(0, 8) + '...';
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

    // Store services for lookup
    services.value = servicesData.services || [];

    // Update KPIs
    kpis.value.totalEndUsers = endUsersData.total || 0;
    kpis.value.totalServices = servicesData.services?.length || 0;
    kpis.value.totalMembers = membersData.members?.length || 0;

    // Calculate login metrics
    const oneDayAgo = new Date();
    oneDayAgo.setHours(oneDayAgo.getHours() - 24);
    kpis.value.recentLogins = recentLoginsData.filter(
      login => new Date(login.created_at) > oneDayAgo
    ).length;

    // Calculate total logins in 30 days
    kpis.value.totalLogins30d = trendsData.reduce((sum, trend) => sum + trend.count, 0);

    // Calculate average daily logins
    kpis.value.avgDailyLogins = trendsData.length > 0
      ? Math.round(kpis.value.totalLogins30d / trendsData.length)
      : 0;

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
