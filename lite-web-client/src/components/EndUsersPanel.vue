<template>
  <section class="panel stack">
    <div>
      <h2>Users</h2>
      <p class="muted">Review the end-users signing in to your AuthOS-backed application.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <div class="field" v-if="serviceOptions.length > 1">
      <label for="end-user-service-filter">Application filter</label>
      <select id="end-user-service-filter" v-model="selectedServiceSlug" class="input">
        <option value="">All applications</option>
        <option v-for="service in serviceOptions" :key="service.slug" :value="service.slug">
          {{ service.name }}
        </option>
      </select>
    </div>

    <LoadingSpinner v-if="loading" text="Loading end-users..." />
    <div v-else-if="error" class="alert alert-error">{{ error }}</div>
    <div v-else-if="users.length === 0" class="alert alert-warning">
      No end-users have signed in to this application yet.
    </div>
    <template v-else>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Visible users</div>
          <div class="meta-value">{{ users.length }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Total</div>
          <div class="meta-value">{{ total }}</div>
        </div>
      </div>

      <div class="list">
        <div v-for="entry in users" :key="entry.user.id" class="list-item">
          <div style="min-width: 0;">
            <div>{{ entry.user.email }}</div>
            <div class="muted">
              Providers: {{ providerList(entry) }} · Subscriptions: {{ entry.subscriptions.length }}
            </div>
          </div>
          <BaseButton variant="secondary" :loading="detailLoading && selectedUserId === entry.user.id" @click="inspectUser(entry.user.id)">
            Inspect
          </BaseButton>
        </div>
      </div>

      <div v-if="selectedUser" class="panel stack" style="padding: 16px;">
        <div>
          <h3 style="margin-bottom: 4px;">{{ selectedUser.user.email }}</h3>
          <p class="muted" style="margin: 0;">Detailed activity and session information.</p>
        </div>

        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">Sessions</div>
            <div class="meta-value">{{ selectedUser.session_count }}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Providers</div>
            <div class="meta-value">{{ providerList(selectedUser) }}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Created</div>
            <div class="meta-value">{{ formatDate(selectedUser.user.created_at) }}</div>
          </div>
        </div>

        <div class="button-row">
          <BaseButton
            variant="danger"
            :loading="revokeLoading"
            :disabled="selectedUser.session_count === 0"
            @click="revokeSessions"
          >
            Revoke all sessions
          </BaseButton>
        </div>

        <div class="stack">
          <h3>Subscriptions</h3>
          <div v-if="selectedUser.subscriptions.length === 0" class="muted">No subscriptions recorded.</div>
          <div v-else class="list">
            <div v-for="subscription in selectedUser.subscriptions" :key="subscription.plan_id + subscription.service_id" class="list-item">
              <div>
                <div>{{ subscription.service_name }}</div>
                <div class="muted">{{ subscription.plan_name }} · {{ subscription.status }}</div>
              </div>
              <div class="muted">{{ formatDate(subscription.current_period_end) }}</div>
            </div>
          </div>
        </div>

        <div class="stack">
          <h3>Recent logins</h3>
          <div v-if="selectedUser.recent_logins.length === 0" class="muted">No recent login events recorded.</div>
          <div v-else class="list">
            <div v-for="login in selectedUser.recent_logins.slice(0, 5)" :key="login.id" class="list-item">
              <div>
                <div>{{ login.provider }} · {{ login.service_name || 'Unknown service' }}</div>
                <div class="muted">{{ login.ip_address || 'No IP address' }}</div>
              </div>
              <div class="muted">{{ formatDate(login.created_at) }}</div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup>
import { ref, watch } from 'vue';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';

const props = defineProps({
  orgSlug: { type: String, default: '' },
  serviceOptions: {
    type: Array,
    default: () => [],
  },
  refreshKey: { type: Number, default: 0 },
});

const loading = ref(false);
const detailLoading = ref(false);
const revokeLoading = ref(false);
const error = ref('');
const message = ref('');
const messageType = ref('success');
const users = ref([]);
const total = ref(0);
const selectedServiceSlug = ref('');
const selectedUserId = ref('');
const selectedUser = ref(null);

watch(
  () => props.serviceOptions,
  (serviceOptions) => {
    if (serviceOptions.length === 1 && !selectedServiceSlug.value) {
      selectedServiceSlug.value = serviceOptions[0].slug;
    }
  },
  { immediate: true },
);

watch(
  () => props.orgSlug,
  async (orgSlug) => {
    if (!orgSlug) return;
    await loadUsers();
  },
  { immediate: true },
);

watch(selectedServiceSlug, async () => {
  if (!props.orgSlug) return;
  await loadUsers();
});

watch(
  () => props.refreshKey,
  async () => {
    if (props.orgSlug) {
      await loadUsers();
    }
  },
);

async function loadUsers() {
  loading.value = true;
  error.value = '';
  selectedUser.value = null;
  selectedUserId.value = '';

  try {
    const response = await sso.organizations.endUsers.list(props.orgSlug, {
      limit: 50,
      ...(selectedServiceSlug.value ? { service_slug: selectedServiceSlug.value } : {}),
    });
    users.value = response.users || [];
    total.value = response.total || 0;
  } catch (currentError) {
    error.value = currentError.message || 'Failed to load end-users.';
    users.value = [];
    total.value = 0;
  } finally {
    loading.value = false;
  }
}

async function inspectUser(userId) {
  detailLoading.value = true;
  message.value = '';
  selectedUserId.value = userId;

  try {
    selectedUser.value = await sso.organizations.endUsers.get(props.orgSlug, userId);
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
      props.orgSlug,
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

function providerList(entry) {
  if (!entry.identities?.length) return 'none';
  return entry.identities.map((item) => item.provider).join(', ');
}

function formatDate(value) {
  if (!value) return 'unknown';
  return new Date(value).toLocaleString();
}
</script>
