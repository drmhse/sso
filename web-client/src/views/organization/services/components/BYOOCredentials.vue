<template>
  <div class="space-y-6">
    <!-- Organization Not Active Warning -->
    <div v-if="!isOrgActive" class="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded-lg">
      <div class="flex">
        <div class="flex-shrink-0">
          <svg class="h-5 w-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
          </svg>
        </div>
        <div class="ml-3">
          <h3 class="text-sm font-medium text-yellow-800">Organization Pending Approval</h3>
          <div class="mt-2 text-sm text-yellow-700">
            <p>OAuth credential management is only available for active organizations. Your organization is awaiting platform owner approval.</p>
          </div>
        </div>
      </div>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
      <div class="flex">
        <div class="flex-shrink-0">
          <svg class="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
          </svg>
        </div>
        <div class="ml-3">
          <h3 class="text-sm font-medium text-blue-800">Bring Your Own OAuth (BYOO)</h3>
          <div class="mt-2 text-sm text-blue-700">
            <p>Configure custom OAuth credentials to white-label the authentication experience with your own OAuth applications.</p>
          </div>
        </div>
      </div>
    </div>

    <div
      v-for="provider in providers"
      :key="provider.id"
      class="bg-white shadow rounded-lg"
    >
      <div class="px-6 py-4 border-b border-gray-200">
        <div class="flex items-center justify-between">
          <div class="flex items-center">
            <div
              class="flex items-center justify-center w-10 h-10 rounded-lg"
              :class="provider.bgColor"
            >
              <svg class="w-6 h-6" :class="provider.iconColor" fill="currentColor" viewBox="0 0 24 24">
                <path v-if="provider.id === 'github'" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                <path v-else-if="provider.id === 'google'" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                <path v-else d="M11.4 24H7.6C6.1 24 5 22.9 5 21.4V7.6C5 6.1 6.1 5 7.6 5h11.8C20.9 5 22 6.1 22 7.6v11.8c0 1.5-1.1 2.6-2.6 2.6h-3.8v-9.4h3.3l.5-3.9h-3.8v-2.4c0-1.1.3-1.9 1.9-1.9h2.1V5.1c-.4-.1-1.5-.1-2.8-.1-2.8 0-4.7 1.7-4.7 4.8v2.7H9.4v3.9h3.6V24z"/>
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-lg font-medium text-gray-900">{{ provider.name }}</h3>
              <p class="text-sm text-gray-500">{{ provider.description }}</p>
            </div>
          </div>
          <span
            v-if="credentials[provider.id]"
            class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800"
          >
            Configured
          </span>
        </div>
      </div>

      <div class="px-6 py-6">
        <form @submit.prevent="handleSubmit(provider.id)" class="space-y-4">
          <div v-if="credentials[provider.id]" class="mb-4 p-4 bg-gray-50 rounded-md">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-700">Current Client ID:</p>
                <p class="mt-1 text-sm font-mono text-gray-900">{{ credentials[provider.id].client_id }}</p>
              </div>
              <button
                type="button"
                @click="copyToClipboard(credentials[provider.id].client_id)"
                class="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
          </div>

          <BaseInput
            v-model="forms[provider.id].client_id"
            label="Client ID"
            :placeholder="`${provider.name} OAuth App Client ID`"
            :disabled="!isOrgActive"
            required
          />

          <BaseInput
            v-model="forms[provider.id].client_secret"
            label="Client Secret"
            type="password"
            :placeholder="`${provider.name} OAuth App Client Secret`"
            :disabled="!isOrgActive"
            required
            :hint="credentials[provider.id] ? 'Enter a new secret to update, or leave blank to keep existing' : ''"
          />

          <div class="p-4 bg-gray-50 rounded-md">
            <h4 class="text-sm font-medium text-gray-900 mb-2">Callback URL Configuration</h4>
            <p class="text-xs text-gray-600 mb-2">
              Use this URL when configuring your {{ provider.name }} OAuth application:
            </p>
            <div class="flex items-center justify-between bg-white border border-gray-300 rounded px-3 py-2">
              <code class="text-sm font-mono text-gray-900">{{ getCallbackUrl(provider.id) }}</code>
              <button
                type="button"
                @click="copyToClipboard(getCallbackUrl(provider.id))"
                class="ml-2 text-gray-500 hover:text-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
            <details class="mt-2">
              <summary class="text-xs text-blue-600 cursor-pointer hover:text-blue-700">
                Setup Instructions
              </summary>
              <div class="mt-2 text-xs text-gray-600 space-y-1">
                <p v-for="(instruction, idx) in provider.instructions" :key="idx">
                  {{ idx + 1 }}. {{ instruction }}
                </p>
              </div>
            </details>
          </div>

          <div class="flex justify-end pt-4 border-t">
            <BaseButton
              type="submit"
              variant="primary"
              :loading="saving[provider.id]"
              :disabled="!isOrgActive"
            >
              {{ credentials[provider.id] ? 'Update' : 'Save' }} Credentials
            </BaseButton>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useServicesStore } from '@/stores/services';
import { useOrganizationStore } from '@/stores/organization';
import { useNotifications } from '@/composables/useNotifications';
import BaseInput from '@/components/BaseInput.vue';
import BaseButton from '@/components/BaseButton.vue';

const servicesStore = useServicesStore();
const organizationStore = useOrganizationStore();
const { showSuccess, showError } = useNotifications();

const credentials = computed(() => servicesStore.oauthCredentials);
const isOrgActive = computed(() => organizationStore.isActive);

const providers = [
  {
    id: 'github',
    name: 'GitHub',
    description: 'Use your own GitHub OAuth App',
    bgColor: 'bg-gray-900',
    iconColor: 'text-white',
    instructions: [
      'Go to GitHub Settings > Developer settings > OAuth Apps',
      'Click "New OAuth App"',
      'Enter your application details and the callback URL above',
      'Copy the Client ID and generate a new Client Secret',
      'Paste them into the form above and save',
    ],
  },
  {
    id: 'google',
    name: 'Google',
    description: 'Use your own Google OAuth 2.0 Client',
    bgColor: 'bg-white border border-gray-200',
    iconColor: 'text-gray-700',
    instructions: [
      'Go to Google Cloud Console > APIs & Services > Credentials',
      'Click "Create Credentials" > "OAuth client ID"',
      'Select "Web application" as the application type',
      'Add the callback URL above to "Authorized redirect URIs"',
      'Copy the Client ID and Client Secret',
      'Paste them into the form above and save',
    ],
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    description: 'Use your own Microsoft Azure AD App',
    bgColor: 'bg-blue-600',
    iconColor: 'text-white',
    instructions: [
      'Go to Azure Portal > Azure Active Directory > App registrations',
      'Click "New registration"',
      'Enter your application details',
      'Under "Redirect URIs", add the callback URL above',
      'Go to "Certificates & secrets" and create a new client secret',
      'Copy the Application (client) ID and the client secret value',
      'Paste them into the form above and save',
    ],
  },
];

const forms = ref({
  github: { client_id: '', client_secret: '' },
  google: { client_id: '', client_secret: '' },
  microsoft: { client_id: '', client_secret: '' },
});

const saving = ref({
  github: false,
  google: false,
  microsoft: false,
});

const getCallbackUrl = (provider) => {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000';
  return `${baseUrl}/auth/${provider}/callback`;
};

const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    showSuccess('Copied to clipboard');
  } catch (error) {
    showError('Failed to copy to clipboard');
  }
};

const handleSubmit = async (provider) => {
  const form = forms.value[provider];

  if (!form.client_id.trim()) {
    showError('Client ID is required');
    return;
  }

  if (!credentials.value[provider] && !form.client_secret.trim()) {
    showError('Client Secret is required for new credentials');
    return;
  }

  saving.value[provider] = true;

  try {
    const payload = {
      client_id: form.client_id.trim(),
    };

    if (form.client_secret.trim()) {
      payload.client_secret = form.client_secret.trim();
    }

    await servicesStore.setOAuthCredentials(
      organizationStore.currentOrgSlug,
      provider,
      payload
    );

    showSuccess(`${providers.find(p => p.id === provider).name} credentials saved successfully`);

    forms.value[provider].client_secret = '';
  } catch (error) {
    console.error(`Failed to save ${provider} credentials:`, error);
    if (error.response?.data?.error) {
      showError(error.response.data.error);
    } else {
      showError(`Failed to save ${provider} credentials. Please try again.`);
    }
  } finally {
    saving.value[provider] = false;
  }
};
</script>
