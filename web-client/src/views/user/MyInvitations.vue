<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">My Invitations</h1>
      <p class="mt-2 text-gray-600">View and manage your organization invitations.</p>
    </div>

    <LoadingSpinner v-if="loading" text="Loading invitations..." />

    <EmptyState
      v-else-if="invitations.length === 0"
      icon="inbox"
      title="No invitations"
      description="You don't have any pending organization invitations at the moment."
    />

    <div v-else class="space-y-4">
      <div
        v-for="invitation in invitations"
        :key="invitation.id"
        class="bg-white shadow overflow-hidden sm:rounded-lg"
      >
        <div class="px-4 py-5 sm:p-6">
          <div class="flex items-center justify-between">
            <div class="flex-1">
              <h3 class="text-lg font-medium text-gray-900">
                {{ invitation.organization_name }}
              </h3>
              <p class="mt-1 text-sm text-gray-500">
                You've been invited to join as {{ formatRole(invitation.role) }}
              </p>
              <p class="mt-1 text-sm text-gray-400">
                Invited {{ formatDate(invitation.created_at) }}
                <span v-if="invitation.inviter_email"> by {{ invitation.inviter_email }}</span>
              </p>
            </div>

            <div class="flex space-x-3">
              <BaseButton
                @click="handleAccept(invitation)"
                variant="success"
                :loading="accepting === invitation.id"
              >
                Accept
              </BaseButton>
              <BaseButton
                @click="handleDecline(invitation)"
                variant="danger"
                :loading="declining === invitation.id"
              >
                Decline
              </BaseButton>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { sso } from '@/api';
import { useNotifications } from '@/composables/useNotifications';
import { formatDate, formatRole } from '@/utils/formatters';
import { useAuthStore } from '@/stores/auth';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';

const router = useRouter();
const authStore = useAuthStore();
const { success, error } = useNotifications();

const loading = ref(false);
const invitations = ref([]);
const accepting = ref(null);
const declining = ref(null);

const fetchInvitations = async () => {
  loading.value = true;
  try {
    invitations.value = await sso.invitations.listForUser();
  } catch (err) {
    console.error('Failed to fetch invitations:', err);
    error('Load Error', 'Failed to load invitations');
  } finally {
    loading.value = false;
  }
};

const handleAccept = async (invitation) => {
  accepting.value = invitation.id;

  try {
    await sso.invitations.accept(invitation.token);

    success(
      'Invitation Accepted',
      `You've joined ${invitation.organization_name}. Refreshing your session...`
    );

    // Remove from local list
    invitations.value = invitations.value.filter(inv => inv.id !== invitation.id);

    // Refresh auth state to get updated claims
    await authStore.refreshUser();

    // Redirect to the organization dashboard after a short delay
    setTimeout(() => {
      router.push(`/orgs/${invitation.organization_slug}/dashboard`);
    }, 1500);
  } catch (err) {
    console.error('Failed to accept invitation:', err);
    error('Accept Failed', err.message || 'Failed to accept invitation');
  } finally {
    accepting.value = null;
  }
};

const handleDecline = async (invitation) => {
  if (!confirm(`Are you sure you want to decline the invitation from ${invitation.organization_name}?`)) {
    return;
  }

  declining.value = invitation.id;

  try {
    await sso.invitations.decline(invitation.token);

    success(
      'Invitation Declined',
      `You've declined the invitation from ${invitation.organization_name}`
    );

    // Remove from local list
    invitations.value = invitations.value.filter(inv => inv.id !== invitation.id);
  } catch (err) {
    console.error('Failed to decline invitation:', err);
    error('Decline Failed', err.message || 'Failed to decline invitation');
  } finally {
    declining.value = null;
  }
};

onMounted(() => {
  fetchInvitations();
});
</script>
