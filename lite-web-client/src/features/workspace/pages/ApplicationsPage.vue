<template>
  <div class="workspace-page stack-lg">
    <section v-if="workspaceStore.mode === 'loading'" class="workspace-card">
      <LoadingSpinner text="Loading application settings..." />
    </section>

    <section v-else-if="workspaceStore.mode !== 'ready'" class="workspace-card stack">
      <h2 class="section-title">Application management is not available</h2>
      <p class="section-copy">
        AuthOS Lite can only edit application settings after a single active organization has been resolved.
      </p>
    </section>

    <template v-else>
      <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
        {{ message }}
      </div>

      <div v-if="loading" class="workspace-card">
        <LoadingSpinner text="Loading application settings..." />
      </div>
      <div v-else-if="error" class="workspace-card stack">
        <div class="alert alert-error">{{ error }}</div>
        <BaseButton variant="secondary" @click="loadServices">Try again</BaseButton>
      </div>
      <div v-else-if="services.length === 0" class="workspace-card">
        <div class="alert alert-warning">No AuthOS applications are attached to this organization yet.</div>
      </div>
      <div v-else class="workspace-two-column workspace-two-column--applications">
        <ApplicationConfigCard
          :services="services"
          :selected-service-slug="selectedServiceSlug"
          :service-name="serviceName"
          :redirect-uris-text="redirectUrisText"
          :device-activation-uri="deviceActivationUri"
          :saving="saving"
          :can-manage="canManage"
          @update:selected-service-slug="selectedServiceSlug = $event"
          @update:service-name="serviceName = $event"
          @update:redirect-uris-text="redirectUrisText = $event"
          @update:device-activation-uri="deviceActivationUri = $event"
          @save="saveService"
        />

        <div class="stack">
          <ApplicationDetailsCard :service="selectedService" />
          <ApplicationUsageCard :usage="usage" :service="selectedService" />
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import ApplicationConfigCard from '@/features/workspace/components/applications/ApplicationConfigCard.vue';
import ApplicationDetailsCard from '@/features/workspace/components/applications/ApplicationDetailsCard.vue';
import ApplicationUsageCard from '@/features/workspace/components/applications/ApplicationUsageCard.vue';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();
const { refreshVersion } = useWorkspaceRuntime();

const loading = ref(false);
const saving = ref(false);
const error = ref('');
const message = ref('');
const messageType = ref('success');
const services = ref([]);
const usage = ref({
  current_services: 0,
  max_services: 0,
  tier: '',
});
const selectedServiceSlug = ref('');
const serviceName = ref('');
const redirectUrisText = ref('');
const deviceActivationUri = ref('');

const canManage = computed(() => ['owner', 'admin'].includes(authStore.activeOrgRole || ''));
const selectedService = computed(() =>
  services.value.find((service) => service.slug === selectedServiceSlug.value) || null,
);

watch(
  () => [workspaceStore.currentOrgSlug, refreshVersion.value],
  async () => {
    if (workspaceStore.currentOrgSlug && workspaceStore.mode === 'ready') {
      await loadServices();
    }
  },
  { immediate: true },
);

watch(selectedService, syncSelectedServiceForm);

async function loadServices() {
  loading.value = true;
  error.value = '';

  try {
    const response = await sso.services.list(workspaceStore.currentOrgSlug);
    services.value = response.services || [];
    usage.value = response.usage || usage.value;

    if (!services.value.some((service) => service.slug === selectedServiceSlug.value)) {
      selectedServiceSlug.value = services.value[0]?.slug || '';
    } else {
      syncSelectedServiceForm(selectedService.value);
    }
  } catch (currentError) {
    error.value = currentError.message || 'Failed to load application settings.';
    services.value = [];
  } finally {
    loading.value = false;
  }
}

function syncSelectedServiceForm(service) {
  if (!service) {
    serviceName.value = '';
    redirectUrisText.value = '';
    deviceActivationUri.value = '';
    return;
  }

  serviceName.value = service.name;
  redirectUrisText.value = (service.redirect_uris || []).join('\n');
  deviceActivationUri.value = service.device_activation_uri || '';
}

async function saveService() {
  if (!selectedService.value || !canManage.value) return;

  const redirectUris = redirectUrisText.value
    .split('\n')
    .map((value) => value.trim())
    .filter(Boolean);

  if (redirectUris.length === 0) {
    messageType.value = 'error';
    message.value = 'At least one redirect URL is required.';
    return;
  }

  saving.value = true;
  message.value = '';

  try {
    await sso.services.update(workspaceStore.currentOrgSlug, selectedService.value.slug, {
      name: serviceName.value,
      redirect_uris: redirectUris,
      ...(deviceActivationUri.value.trim()
        ? { device_activation_uri: deviceActivationUri.value.trim() }
        : {}),
    });
    await loadServices();
    messageType.value = 'success';
    message.value = 'Application settings updated.';
  } catch (currentError) {
    messageType.value = 'error';
    message.value = currentError.message || 'Failed to update the application.';
  } finally {
    saving.value = false;
  }
}
</script>
