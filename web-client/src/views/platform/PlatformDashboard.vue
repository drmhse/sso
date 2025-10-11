<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Platform Dashboard</h1>
      <p class="mt-2 text-gray-600">Comprehensive platform analytics and management overview.</p>
    </div>

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
        <!-- Total Organizations -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0 bg-blue-500 rounded-md p-3">
              <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Total Organizations</dt>
                <dd class="text-2xl font-semibold text-gray-900">{{ overview.total_organizations }}</dd>
              </dl>
            </div>
          </div>
        </div>

        <!-- Total Users -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0 bg-green-500 rounded-md p-3">
              <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Platform Users</dt>
                <dd class="text-2xl font-semibold text-gray-900">{{ overview.total_users }}</dd>
              </dl>
            </div>
          </div>
        </div>

        <!-- Total End Users -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0 bg-purple-500 rounded-md p-3">
              <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Total End Users</dt>
                <dd class="text-2xl font-semibold text-gray-900">{{ overview.total_end_users }}</dd>
              </dl>
            </div>
          </div>
        </div>

        <!-- Total Services -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0 bg-yellow-500 rounded-md p-3">
              <svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Total Services</dt>
                <dd class="text-2xl font-semibold text-gray-900">{{ overview.total_services }}</dd>
              </dl>
            </div>
          </div>
        </div>
      </div>

      <!-- Activity Metrics Row -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Logins Last 24h -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm font-medium text-gray-500">Logins (24h)</p>
              <p class="text-3xl font-bold text-gray-900 mt-2">{{ overview.total_logins_24h }}</p>
            </div>
            <div class="bg-indigo-100 rounded-full p-3">
              <svg class="h-8 w-8 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
              </svg>
            </div>
          </div>
        </div>

        <!-- Logins Last 30d -->
        <div class="bg-white rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm font-medium text-gray-500">Logins (30 days)</p>
              <p class="text-3xl font-bold text-gray-900 mt-2">{{ overview.total_logins_30d }}</p>
            </div>
            <div class="bg-green-100 rounded-full p-3">
              <svg class="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Organization Status Breakdown -->
      <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-medium text-gray-900 mb-4">Organization Status</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div class="text-center p-4 bg-yellow-50 rounded-lg">
            <p class="text-3xl font-bold text-yellow-600">{{ statusBreakdown.pending }}</p>
            <p class="text-sm text-gray-600 mt-1">Pending</p>
          </div>
          <div class="text-center p-4 bg-green-50 rounded-lg">
            <p class="text-3xl font-bold text-green-600">{{ statusBreakdown.active }}</p>
            <p class="text-sm text-gray-600 mt-1">Active</p>
          </div>
          <div class="text-center p-4 bg-red-50 rounded-lg">
            <p class="text-3xl font-bold text-red-600">{{ statusBreakdown.suspended }}</p>
            <p class="text-sm text-gray-600 mt-1">Suspended</p>
          </div>
          <div class="text-center p-4 bg-gray-50 rounded-lg">
            <p class="text-3xl font-bold text-gray-600">{{ statusBreakdown.rejected }}</p>
            <p class="text-sm text-gray-600 mt-1">Rejected</p>
          </div>
        </div>
      </div>

      <!-- Platform-wide Login Activity Chart -->
      <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-medium text-gray-900 mb-4">Platform-wide Login Activity (Last 30 Days)</h3>
        <div v-if="loginActivity.length === 0" class="text-center py-8 text-gray-500">
          No login activity data available
        </div>
        <div v-else class="space-y-2">
          <div v-for="activity in loginActivity" :key="activity.date" class="flex items-center">
            <span class="text-sm text-gray-600 w-24">{{ formatDate(activity.date) }}</span>
            <div class="flex-1 bg-gray-200 rounded-full h-4 ml-4">
              <div
                class="bg-indigo-600 h-4 rounded-full"
                :style="{ width: getBarWidth(activity.count, maxLoginActivity) }"
              ></div>
            </div>
            <span class="text-sm font-semibold text-gray-900 ml-4 w-16 text-right">{{ activity.count }}</span>
          </div>
        </div>
      </div>

      <!-- Growth Trends -->
      <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-medium text-gray-900 mb-4">Platform Growth Trends (Last 30 Days)</h3>
        <div v-if="growthTrends.length === 0" class="text-center py-8 text-gray-500">
          No growth data available
        </div>
        <div v-else class="space-y-4">
          <!-- Organizations Growth -->
          <div>
            <p class="text-sm font-medium text-gray-700 mb-2">New Organizations</p>
            <div class="space-y-2">
              <div v-for="trend in growthTrends" :key="'org-' + trend.date" class="flex items-center">
                <span class="text-xs text-gray-600 w-20">{{ formatDate(trend.date) }}</span>
                <div class="flex-1 bg-gray-200 rounded-full h-3 ml-3">
                  <div
                    class="bg-blue-500 h-3 rounded-full"
                    :style="{ width: getBarWidth(trend.new_organizations, maxNewOrgs) }"
                  ></div>
                </div>
                <span class="text-xs font-semibold text-gray-900 ml-3 w-12 text-right">{{ trend.new_organizations }}</span>
              </div>
            </div>
          </div>

          <!-- Users Growth -->
          <div class="mt-6">
            <p class="text-sm font-medium text-gray-700 mb-2">New End Users</p>
            <div class="space-y-2">
              <div v-for="trend in growthTrends" :key="'user-' + trend.date" class="flex items-center">
                <span class="text-xs text-gray-600 w-20">{{ formatDate(trend.date) }}</span>
                <div class="flex-1 bg-gray-200 rounded-full h-3 ml-3">
                  <div
                    class="bg-green-500 h-3 rounded-full"
                    :style="{ width: getBarWidth(trend.new_users, maxNewUsers) }"
                  ></div>
                </div>
                <span class="text-xs font-semibold text-gray-900 ml-3 w-12 text-right">{{ trend.new_users }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Two Column Layout: Top Organizations and Recent Organizations -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Top Organizations -->
        <div class="bg-white rounded-lg shadow p-6">
          <h3 class="text-lg font-medium text-gray-900 mb-4">Most Active Organizations</h3>
          <div v-if="topOrganizations.length === 0" class="text-center py-8 text-gray-500">
            No organization data available
          </div>
          <div v-else class="space-y-3">
            <div
              v-for="(org, index) in topOrganizations"
              :key="org.id"
              class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <div class="flex items-center space-x-3">
                <span class="flex items-center justify-center w-8 h-8 rounded-full bg-blue-600 text-white text-sm font-bold">
                  {{ index + 1 }}
                </span>
                <div>
                  <p class="text-sm font-medium text-gray-900">{{ org.name }}</p>
                  <p class="text-xs text-gray-500">{{ org.slug }}</p>
                </div>
              </div>
              <div class="text-right">
                <p class="text-sm font-semibold text-gray-900">{{ org.login_count_30d }} logins</p>
                <p class="text-xs text-gray-500">{{ org.user_count }} users, {{ org.service_count }} services</p>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Organizations -->
        <div class="bg-white rounded-lg shadow p-6">
          <h3 class="text-lg font-medium text-gray-900 mb-4">Recent Organizations</h3>
          <div v-if="recentOrganizations.length === 0" class="text-center py-8 text-gray-500">
            No recent organizations
          </div>
          <div v-else class="space-y-3">
            <div
              v-for="org in recentOrganizations"
              :key="org.id"
              class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <div>
                <p class="text-sm font-medium text-gray-900">{{ org.name }}</p>
                <p class="text-xs text-gray-500">{{ org.slug }}</p>
              </div>
              <div class="text-right">
                <span
                  class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase"
                  :class="getStatusClass(org.status)"
                >
                  {{ org.status }}
                </span>
                <p class="text-xs text-gray-500 mt-1">{{ formatDateTime(org.created_at) }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import { sso } from '@/api';

const loading = ref(true);
const error = ref(null);

// Dashboard data
const overview = ref({
  total_organizations: 0,
  total_users: 0,
  total_end_users: 0,
  total_services: 0,
  total_logins_24h: 0,
  total_logins_30d: 0
});

const statusBreakdown = ref({
  pending: 0,
  active: 0,
  suspended: 0,
  rejected: 0
});

const loginActivity = ref([]);
const growthTrends = ref([]);
const topOrganizations = ref([]);
const recentOrganizations = ref([]);

// Computed values for chart scaling
const maxLoginActivity = computed(() => {
  if (loginActivity.value.length === 0) return 1;
  return Math.max(...loginActivity.value.map(a => a.count), 1);
});

const maxNewOrgs = computed(() => {
  if (growthTrends.value.length === 0) return 1;
  return Math.max(...growthTrends.value.map(t => t.new_organizations), 1);
});

const maxNewUsers = computed(() => {
  if (growthTrends.value.length === 0) return 1;
  return Math.max(...growthTrends.value.map(t => t.new_users), 1);
});

// Helper functions
const getBarWidth = (value, max) => {
  return `${(value / max) * 100}%`;
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

const getStatusClass = (status) => {
  const classes = {
    pending: 'bg-yellow-100 text-yellow-800',
    active: 'bg-green-100 text-green-800',
    suspended: 'bg-red-100 text-red-800',
    rejected: 'bg-gray-100 text-gray-800'
  };
  return classes[status] || 'bg-gray-100 text-gray-800';
};

// Load dashboard data
const loadDashboardData = async () => {
  try {
    loading.value = true;
    error.value = null;

    // Calculate date range (last 30 days)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    const formatDateParam = (date) => {
      return date.toISOString().split('T')[0];
    };

    // Fetch all data in parallel
    const [
      overviewData,
      statusData,
      loginActivityData,
      growthData,
      topOrgsData,
      recentOrgsData
    ] = await Promise.all([
      sso.platform.analytics.getOverview().catch(() => ({
        total_organizations: 0,
        total_users: 0,
        total_end_users: 0,
        total_services: 0,
        total_logins_24h: 0,
        total_logins_30d: 0
      })),
      sso.platform.analytics.getOrganizationStatus().catch(() => ({
        pending: 0,
        active: 0,
        suspended: 0,
        rejected: 0
      })),
      sso.platform.analytics.getLoginActivity({
        start_date: formatDateParam(startDate),
        end_date: formatDateParam(endDate)
      }).catch(() => []),
      sso.platform.analytics.getGrowthTrends({
        start_date: formatDateParam(startDate),
        end_date: formatDateParam(endDate)
      }).catch(() => []),
      sso.platform.analytics.getTopOrganizations().catch(() => []),
      sso.platform.analytics.getRecentOrganizations({ limit: 10 }).catch(() => [])
    ]);

    // Update state
    overview.value = overviewData;
    statusBreakdown.value = statusData;
    loginActivity.value = loginActivityData;
    growthTrends.value = growthData;
    topOrganizations.value = topOrgsData;
    recentOrganizations.value = recentOrgsData;

  } catch (err) {
    console.error('Failed to load dashboard data:', err);
    error.value = 'Failed to load dashboard data. Please try refreshing the page.';
  } finally {
    loading.value = false;
  }
};

onMounted(async () => {
  await loadDashboardData();
});
</script>
