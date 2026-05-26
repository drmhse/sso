<template>
  <section class="panel stack">
    <div>
      <h2>Application</h2>
      <p class="muted">Review and update the AuthOS application attached to this organization.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <LoadingSpinner v-if="loading" text="Loading application settings..." />
    <div v-else-if="error" class="alert alert-error">{{ error }}</div>
    <div v-else-if="services.length === 0" class="alert alert-warning">
      No AuthOS applications are attached to this organization yet.
    </div>
    <template v-else>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Services</div>
          <div class="meta-value">{{ usage.current_services }} / {{ usage.max_services }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Tier</div>
          <div class="meta-value">{{ usage.tier || 'Unknown' }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Subscriptions</div>
          <div class="meta-value">{{ selectedService?.subscription_count || 0 }}</div>
        </div>
      </div>

      <div class="field" v-if="services.length > 1">
        <label for="service-slug">Application</label>
        <select id="service-slug" v-model="selectedServiceSlug" class="input">
          <option v-for="item in services" :key="item.slug" :value="item.slug">
            {{ item.name }} ({{ item.slug }})
          </option>
        </select>
      </div>

      <template v-if="selectedService">
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">Client ID</div>
            <div class="meta-value code">{{ selectedService.client_id }}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Type</div>
            <div class="meta-value">{{ selectedService.service_type }}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Plans</div>
            <div class="meta-value">{{ selectedService.plan_count }}</div>
          </div>
        </div>

        <div class="field">
          <label for="service-name">Application name</label>
          <input id="service-name" v-model="serviceName" class="input" :disabled="!canManage" />
        </div>

        <div class="field">
          <label for="service-redirects">Redirect URIs</label>
          <textarea
            id="service-redirects"
            v-model="redirectUrisText"
            class="textarea code"
            :disabled="!canManage"
          />
        </div>

        <div class="field">
          <label for="device-activation-uri">Device activation URL</label>
          <input
            id="device-activation-uri"
            v-model="deviceActivationUri"
            class="input code"
            :disabled="!canManage"
            placeholder="https://example.com/activate"
          />
        </div>

        <BaseButton :loading="saving" :disabled="!canManage" @click="saveService">
          Save application settings
        </BaseButton>
        <div v-if="!canManage" class="muted">This session can view application settings but cannot change them.</div>
      </template>
    </template>
  </section>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';

const props = defineProps({
  orgSlug: { type: String, default: '' },
  canManage: { type: Boolean, default: false },
  refreshKey: { type: Number, default: 0 },
});

const emit = defineEmits(['services-loaded']);

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

const selectedService = computed(() =>
  services.value.find((item) => item.slug === selectedServiceSlug.value) || null,
);

watch(
  () => props.orgSlug,
  async (orgSlug) => {
    if (!orgSlug) {
      services.value = [];
      emit('services-loaded', []);
      return;
    }
    await loadServices(orgSlug);
  },
  { immediate: true },
);

watch(
  () => props.refreshKey,
  async () => {
    if (props.orgSlug) {
      await loadServices(props.orgSlug);
    }
  },
);

watch(selectedService, syncSelectedServiceForm, { immediate: false });

async function loadServices(orgSlug = props.orgSlug) {
  loading.value = true;
  error.value = '';

  try {
    const response = await sso.services.list(orgSlug);
    services.value = response.services || [];
    usage.value = response.usage || usage.value;
    emit(
      'services-loaded',
      services.value.map((item) => ({
        slug: item.slug,
        name: item.name,
      })),
    );

    if (!services.value.some((item) => item.slug === selectedServiceSlug.value)) {
      selectedServiceSlug.value = services.value[0]?.slug || '';
    } else {
      syncSelectedServiceForm(selectedService.value);
    }
  } catch (currentError) {
    error.value = currentError.message || 'Failed to load application settings.';
    services.value = [];
    emit('services-loaded', []);
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
  if (!selectedService.value || !props.canManage) return;

  const redirectUris = redirectUrisText.value
    .split('\n')
    .map((item) => item.trim())
    .filter(Boolean);

  if (redirectUris.length === 0) {
    messageType.value = 'error';
    message.value = 'At least one redirect URI is required.';
    return;
  }

  saving.value = true;
  message.value = '';

  try {
    await sso.services.update(props.orgSlug, selectedService.value.slug, {
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
