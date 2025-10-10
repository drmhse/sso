<template>
  <div>
    <div class="bg-white shadow rounded-lg">
      <div class="px-6 py-4 border-b border-gray-200">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-lg font-medium text-gray-900">Subscription Plans</h2>
            <p class="mt-1 text-sm text-gray-600">
              Manage pricing tiers and features for your service
            </p>
          </div>
          <BaseButton variant="primary" @click="openCreateModal">
            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Create Plan
          </BaseButton>
        </div>
      </div>

      <div v-if="loading" class="px-6 py-12 text-center">
        <LoadingSpinner />
      </div>

      <div v-else-if="plans.length === 0" class="px-6 py-12">
        <EmptyState
          icon="document"
          title="No plans yet"
          description="Create subscription plans to monetize your service."
        >
          <template #action>
            <BaseButton variant="primary" @click="openCreateModal">
              Create Your First Plan
            </BaseButton>
          </template>
        </EmptyState>
      </div>

      <div v-else class="px-6 py-6">
        <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <div
            v-for="plan in plans"
            :key="plan.id"
            class="border rounded-lg p-6"
            :class="plan.is_default ? 'border-blue-500 bg-blue-50' : 'border-gray-200'"
          >
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-semibold text-gray-900 capitalize">
                {{ plan.name }}
              </h3>
              <span
                v-if="plan.is_default"
                class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
              >
                Default
              </span>
            </div>

            <div class="mb-4">
              <span class="text-3xl font-bold text-gray-900">
                {{ formatPrice(plan.price_monthly) }}
              </span>
              <span class="text-gray-600">/month</span>
            </div>

            <p v-if="plan.description" class="text-sm text-gray-600 mb-4">
              {{ plan.description }}
            </p>

            <div v-if="plan.features && plan.features.length > 0" class="space-y-2">
              <p class="text-xs font-medium text-gray-700 uppercase">Features:</p>
              <ul class="space-y-1">
                <li
                  v-for="(feature, idx) in plan.features"
                  :key="idx"
                  class="flex items-start text-sm text-gray-600"
                >
                  <svg class="w-5 h-5 mr-2 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  {{ feature }}
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    <BaseModal
      :is-open="isCreateModalOpen"
      title="Create Subscription Plan"
      size="lg"
      :show-actions="false"
      @close="closeCreateModal"
    >
      <form @submit.prevent="handleCreatePlan" class="space-y-4">
        <BaseInput
          v-model="form.name"
          label="Plan Name"
          placeholder="pro"
          hint="Lowercase identifier (e.g., free, pro, enterprise)"
          required
          :error="errors.name"
        />

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Description
          </label>
          <textarea
            v-model="form.description"
            rows="3"
            placeholder="Describe what's included in this plan..."
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          ></textarea>
        </div>

        <BaseInput
          v-model.number="form.price_monthly"
          type="number"
          step="0.01"
          min="0"
          label="Monthly Price"
          placeholder="29.99"
          hint="Leave as 0 for a free plan"
        />

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Features
          </label>
          <div class="space-y-2">
            <div
              v-for="(feature, index) in form.features"
              :key="index"
              class="flex gap-2"
            >
              <input
                v-model="form.features[index]"
                type="text"
                placeholder="Feature description"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              />
              <button
                v-if="form.features.length > 1"
                type="button"
                @click="removeFeature(index)"
                class="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
          <button
            type="button"
            @click="addFeature"
            class="mt-2 inline-flex items-center text-sm text-blue-600 hover:text-blue-700"
          >
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Add Feature
          </button>
        </div>

        <div class="flex items-center">
          <input
            id="is_default"
            v-model="form.is_default"
            type="checkbox"
            class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
          <label for="is_default" class="ml-2 block text-sm text-gray-900">
            Set as default plan
          </label>
        </div>

        <div class="mt-6 flex justify-end space-x-3 pt-4 border-t">
          <BaseButton
            type="button"
            variant="ghost"
            @click="closeCreateModal"
          >
            Cancel
          </BaseButton>
          <BaseButton
            type="submit"
            variant="primary"
            :loading="creating"
          >
            Create Plan
          </BaseButton>
        </div>
      </form>
    </BaseModal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useServicesStore } from '@/stores/services';
import { useOrganizationStore } from '@/stores/organization';
import { useNotifications } from '@/composables/useNotifications';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseModal from '@/components/BaseModal.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';

const route = useRoute();
const servicesStore = useServicesStore();
const organizationStore = useOrganizationStore();
const { showSuccess, showError } = useNotifications();

const loading = ref(false);
const plans = computed(() => servicesStore.currentServicePlans);
const currentService = computed(() => servicesStore.currentService);

const isCreateModalOpen = ref(false);
const creating = ref(false);

const form = ref({
  name: '',
  description: '',
  price_monthly: 0,
  features: [''],
  is_default: false,
});

const errors = ref({
  name: '',
});

const openCreateModal = () => {
  isCreateModalOpen.value = true;
  resetForm();
};

const closeCreateModal = () => {
  isCreateModalOpen.value = false;
  resetForm();
};

const resetForm = () => {
  form.value = {
    name: '',
    description: '',
    price_monthly: 0,
    features: [''],
    is_default: false,
  };
  errors.value = { name: '' };
};

const addFeature = () => {
  form.value.features.push('');
};

const removeFeature = (index) => {
  form.value.features.splice(index, 1);
};

const formatPrice = (price) => {
  if (price === null || price === undefined || price === 0) {
    return 'Free';
  }
  return `$${price.toFixed(2)}`;
};

const handleCreatePlan = async () => {
  errors.value = { name: '' };

  const validFeatures = form.value.features.filter(f => f.trim().length > 0);

  const payload = {
    name: form.value.name.toLowerCase().trim(),
    description: form.value.description.trim() || undefined,
    price_monthly: form.value.price_monthly || undefined,
    features: validFeatures,
    is_default: form.value.is_default,
  };

  creating.value = true;

  try {
    if (!currentService.value?.service?.slug) {
      throw new Error('Service information is not available');
    }

    await servicesStore.createPlan(
      organizationStore.currentOrgSlug,
      currentService.value.service.slug,
      payload
    );

    showSuccess('Plan created successfully');
    closeCreateModal();
  } catch (error) {
    console.error('Failed to create plan:', error);
    if (error.response?.data?.error) {
      const errorMsg = error.response.data.error;
      if (errorMsg.toLowerCase().includes('name')) {
        errors.value.name = errorMsg;
      } else {
        showError(errorMsg);
      }
    } else {
      showError(error.message || 'Failed to create plan. Please try again.');
    }
  } finally {
    creating.value = false;
  }
};

onMounted(async () => {
  if (currentService.value?.service?.slug) {
    loading.value = true;
    try {
      await servicesStore.fetchPlans(
        organizationStore.currentOrgSlug,
        currentService.value.service.slug
      );
    } catch (error) {
      console.error('Failed to load plans:', error);
    } finally {
      loading.value = false;
    }
  }
});
</script>
