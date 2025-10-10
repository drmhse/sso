<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">Team Members</h1>
        <p class="mt-2 text-gray-600">Manage your team members and invitations.</p>
      </div>

      <BaseButton
        v-if="canManageTeam"
        @click="openInviteModal"
        variant="primary"
      >
        Invite Member
      </BaseButton>
    </div>

    <LoadingSpinner v-if="loading" text="Loading team members..." />

    <div v-else class="space-y-6">
      <!-- Members List -->
      <div class="bg-white shadow overflow-hidden sm:rounded-lg">
        <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
          <h3 class="text-lg leading-6 font-medium text-gray-900">
            Active Members ({{ members.length }})
          </h3>
        </div>

        <EmptyState
          v-if="members.length === 0"
          icon="users"
          title="No members yet"
          description="Invite members to collaborate on this organization."
        >
          <template #action>
            <BaseButton v-if="canManageTeam" @click="openInviteModal" variant="primary">
              Invite Your First Member
            </BaseButton>
          </template>
        </EmptyState>

        <ul v-else class="divide-y divide-gray-200">
          <li v-for="member in members" :key="member.user_id" class="px-6 py-4">
            <div class="flex items-center justify-between">
              <div class="flex-1">
                <div class="flex items-center">
                  <div>
                    <p class="text-sm font-medium text-gray-900">
                      {{ member.email }}
                    </p>
                    <p class="text-sm text-gray-500">
                      Joined {{ formatDate(member.joined_at) }}
                    </p>
                  </div>
                </div>
              </div>

              <div class="flex items-center space-x-4">
                <span
                  class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                  :class="roleClass(member.role)"
                >
                  {{ formatRole(member.role) }}
                </span>

                <div v-if="canManageTeam && member.role !== 'owner'" class="flex space-x-2">
                  <button
                    @click="openRoleModal(member)"
                    class="text-blue-600 hover:text-blue-900 text-sm"
                  >
                    Change Role
                  </button>
                  <button
                    @click="handleRemoveMember(member)"
                    class="text-red-600 hover:text-red-900 text-sm"
                  >
                    Remove
                  </button>
                </div>
              </div>
            </div>
          </li>
        </ul>
      </div>

      <!-- Pending Invitations -->
      <div v-if="canManageTeam && invitations.length > 0" class="bg-white shadow overflow-hidden sm:rounded-lg">
        <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
          <h3 class="text-lg leading-6 font-medium text-gray-900">
            Pending Invitations ({{ pendingInvitations.length }})
          </h3>
        </div>

        <ul class="divide-y divide-gray-200">
          <li v-for="invitation in pendingInvitations" :key="invitation.id" class="px-6 py-4">
            <div class="flex items-center justify-between">
              <div class="flex-1">
                <div class="flex items-center">
                  <div>
                    <p class="text-sm font-medium text-gray-900">
                      {{ invitation.invitee_email }}
                    </p>
                    <p class="text-sm text-gray-500">
                      Invited {{ formatDate(invitation.created_at) }}
                    </p>
                  </div>
                </div>
              </div>

              <div class="flex items-center space-x-4">
                <span
                  class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800"
                >
                  {{ formatRole(invitation.role) }}
                </span>

                <button
                  @click="handleCancelInvitation(invitation)"
                  class="text-red-600 hover:text-red-900 text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </li>
        </ul>
      </div>
    </div>

    <!-- Invite Modal -->
    <BaseModal
      :is-open="inviteModal.isOpen"
      title="Invite Team Member"
      confirm-text="Send Invitation"
      @close="closeInviteModal"
      @confirm="handleInvite"
    >
      <div class="space-y-4">
        <BaseInput
          v-model="inviteModal.email"
          label="Email Address"
          type="email"
          placeholder="member@example.com"
          required
        />

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Role <span class="text-red-500">*</span>
          </label>
          <select
            v-model="inviteModal.role"
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
          <p class="mt-1 text-sm text-gray-500">
            Admins can manage team members and services.
          </p>
        </div>
      </div>
    </BaseModal>

    <!-- Change Role Modal -->
    <BaseModal
      :is-open="roleModal.isOpen"
      title="Change Member Role"
      confirm-text="Update Role"
      @close="closeRoleModal"
      @confirm="handleUpdateRole"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500">
          Change role for <strong>{{ roleModal.member?.email }}</strong>
        </p>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            New Role <span class="text-red-500">*</span>
          </label>
          <select
            v-model="roleModal.role"
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </div>
    </BaseModal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useMembersStore } from '@/stores/members';
import { usePermissions } from '@/composables/usePermissions';
import { useNotifications } from '@/composables/useNotifications';
import { formatDate, formatRole } from '@/utils/formatters';
import BaseModal from '@/components/BaseModal.vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';

const route = useRoute();
const membersStore = useMembersStore();
const { canManageTeam } = usePermissions();
const { success, error } = useNotifications();

const loading = ref(false);

const orgSlug = computed(() => route.params.orgSlug);
const members = computed(() => membersStore.members);
const invitations = computed(() => membersStore.invitations);
const pendingInvitations = computed(() => membersStore.pendingInvitations);

const inviteModal = ref({
  isOpen: false,
  email: '',
  role: 'member',
});

const roleModal = ref({
  isOpen: false,
  member: null,
  role: 'member',
});

const roleClass = (role) => {
  const classes = {
    owner: 'bg-purple-100 text-purple-800',
    admin: 'bg-blue-100 text-blue-800',
    member: 'bg-gray-100 text-gray-800',
  };
  return classes[role] || 'bg-gray-100 text-gray-800';
};

const openInviteModal = () => {
  inviteModal.value = {
    isOpen: true,
    email: '',
    role: 'member',
  };
};

const closeInviteModal = () => {
  inviteModal.value = {
    isOpen: false,
    email: '',
    role: 'member',
  };
};

const handleInvite = async () => {
  if (!inviteModal.value.email) {
    error('Validation Error', 'Please enter an email address');
    return;
  }

  try {
    await membersStore.createInvitation(orgSlug.value, {
      invitee_email: inviteModal.value.email,
      role: inviteModal.value.role,
    });

    success('Invitation Sent', `Invitation sent to ${inviteModal.value.email}`);
    closeInviteModal();
  } catch (err) {
    error('Invitation Failed', err.message || 'Failed to send invitation');
  }
};

const openRoleModal = (member) => {
  roleModal.value = {
    isOpen: true,
    member,
    role: member.role,
  };
};

const closeRoleModal = () => {
  roleModal.value = {
    isOpen: false,
    member: null,
    role: 'member',
  };
};

const handleUpdateRole = async () => {
  try {
    await membersStore.updateMemberRole(
      orgSlug.value,
      roleModal.value.member.user_id,
      roleModal.value.role
    );

    success('Role Updated', `Role updated for ${roleModal.value.member.email}`);
    closeRoleModal();
  } catch (err) {
    error('Update Failed', err.message || 'Failed to update role');
  }
};

const handleRemoveMember = async (member) => {
  if (!confirm(`Are you sure you want to remove ${member.email} from this organization?`)) {
    return;
  }

  try {
    await membersStore.removeMember(orgSlug.value, member.user_id);
    success('Member Removed', `${member.email} has been removed from the organization`);
  } catch (err) {
    error('Removal Failed', err.message || 'Failed to remove member');
  }
};

const handleCancelInvitation = async (invitation) => {
  if (!confirm(`Are you sure you want to cancel the invitation to ${invitation.invitee_email}?`)) {
    return;
  }

  try {
    await membersStore.cancelInvitation(orgSlug.value, invitation.id);
    success('Invitation Cancelled', `Invitation to ${invitation.invitee_email} has been cancelled`);
  } catch (err) {
    error('Cancellation Failed', err.message || 'Failed to cancel invitation');
  }
};

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      membersStore.fetchMembers(orgSlug.value),
      membersStore.fetchInvitations(orgSlug.value),
    ]);
  } catch (err) {
    error('Load Error', 'Failed to load team data');
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadData();
});
</script>
